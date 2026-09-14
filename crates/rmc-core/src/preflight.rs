//! 开启远程维护前的四步检查，见方案 3.4。
//!
//! 前一步失败时后续依赖它的步骤标为 [`StepOutcome::Skipped`]，而不是伪造
//! 一个失败——工程师在界面上看到的应该是"一体机连不上，所以没测 host
//! key"，不是一条无中生有的"host key 校验失败"。
//!
//! # R4（本任务开工前预扫描已发现）：`run` 必须能被换成假实现
//!
//! Task 10 的 `Command::Start` 在真正建隧道（`attempt`）之前会先跑一遍
//! 预检，且预检失败直接让状态机进 `Failed`。如果这一步只能调本模块的
//! 自由函数 `run`（真的会 `TcpStream::connect`、真的会 `lookup_host`），
//! Task 10 那份状态机测试——脚本化假隧道、`#[tokio::test(start_paused =
//! true)]`——会在 `Command::Start` 这一步整个失灵：
//!
//! - 测试用的地址（`192.168.100.10:22`、`gateway.company.com:443`）在
//!   CI/开发机上必然不可达，预检真的跑一遍网络之后返回失败，状态机
//!   直接进 `Failed`，`Scripted` 假隧道工厂的 `establish` 一次都不会被
//!   调用——`TunnelFactory` 这道注入接缝形同虚设，测试名字声称在验证
//!   状态机的重连/退避/会话可见性等行为，实际上验证的是"预检对一个不
//!   存在的地址会失败"，牛头不对马嘴。
//! - 另一个独立的理由跟"地址通不通"无关，纯粹是 `start_paused = true`
//!   的机制问题——**一次真实 I/O 的 `.await` 会让虚拟时钟一步跳掉几
//!   百秒**，把测试自己的超时预算烧光。
//!
//!   R77（第四轮评审）订正：这里原来写的是"测试会卡在等待真实网络
//!   返回上、`cargo test` 直接挂起"。结论（必须注入假 `Preflight`）
//!   没变，但成因写得不对，照着这条去排查同类症状会走错方向。
//!
//!   真相是：`start_paused` 的自动前进发生在运行时 park 且没有可跑
//!   任务的时候，前进量取自 `wheel.next_expiration_time()`——而这个值
//!   是**时间轮层级槽的边界**，不是某个定时器的真实到期时刻（tokio
//!   `time/wheel/level.rs`：`slot_range(level) = 64^level` 毫秒，
//!   level 3 = 262144 ms）。真实 I/O 的 `.await` 恰好是"让运行时 park
//!   而时间轮里没有近处定时器"最常见的方式，于是虚拟钟一步跳到下一个
//!   槽边界。本地对 tokio 1.53.1 实测：测试里只挂着一个 300 秒的死锁
//!   保护定时器时，一次真实 `TcpStream::connect().await` 就让虚拟时钟
//!   前进 262.144 秒（真实时间只花了 139µs），300 秒预算只剩 38 秒；
//!   同一次 I/O，如果测试里另外挂着一个 1 秒心跳（时间轮里始终有近处
//!   定时器），虚拟时钟只前进 1 秒。
//!
//!   所以症状是"整个测试二进制在零点几秒真实时间内就以超时失败告终"，
//!   不是挂起。真要在 `start_paused` 的测试里做一次真实网络动作，用
//!   阻塞的 `std::net::TcpStream::connect_timeout` 这类完全不经过
//!   tokio I/O driver 的调用就不会触发这件事（`supervisor.rs` 里
//!   `degraded_stays_degraded_while_the_appliance_is_still_down` 的
//!   死地址自检就是这么做的）——但预检要的是整套 DNS + TCP + TLS，
//!   没有这样的替代品，只能注入假实现。
//!
//! 解决办法：把 `run` 包成一个可以被替换的接口——[`Preflight`] trait，
//! 真实实现是 [`TransportPreflight`]（内部就是调用本模块的 `run`）。
//!
//! **Task 10 的接线方式**：
//! - `supervisor::Deps` 在 `factory: Arc<dyn TunnelFactory>` 旁边加一个
//!   同构的字段 `pub preflight: Arc<dyn Preflight>`。
//! - 生产环境构造 `Deps` 时传 `Arc::new(TransportPreflight::new(transport
//!   .clone()))`。
//! - `run_preflight(ctx)` 里原来直接调用自由函数的那一行
//!   `preflight::run(ctx.deps.transport.as_ref(), &c.gateway, &c.appliance)`
//!   改成 `ctx.deps.preflight.run(&c.gateway, &c.appliance).await`——
//!   这一行是唯一要改的生产代码。
//! - 测试注入一个自己的假 `Preflight`（`run` 立即返回一份脚本化的
//!   `PreflightReport`，例如四步全部 `Pass`，不等待、不碰网络），
//!   `Scripted`/`FakeHandle` 那一整套假隧道基础设施才有机会被真正跑到。
//!
//! trait 方法与本模块的自由函数同名（都叫 `run`），这不构成歧义：前者
//! 只能通过 `instance.run(...)`/`Preflight::run(&instance, ...)` 这种
//! 方法调用语法触达，后者是 `preflight::run(...)` 这种函数调用语法，
//! Rust 按调用形式消歧，两者可以在同一个模块里共存。

use crate::addr::HostPort;
use crate::error::{Error, ErrorClass};
use crate::knownhosts::fingerprint_of;
use crate::platform::Conn;
use crate::transport::Transport;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub const STEP_APPLIANCE_TCP: &str = "一体机 TCP";
pub const STEP_APPLIANCE_HOSTKEY: &str = "一体机 host key 指纹";
pub const STEP_GATEWAY_DNS: &str = "Gateway 域名解析";
pub const STEP_GATEWAY_TLS: &str = "Gateway TLS";

/// 单个网络操作的超时预算。预检存在的意义就是把"连不上"这件事在工程师
/// 现场几秒内说清楚，而不是让界面无限期转圈——见下面 `bounded` 上的说明：
/// 这个预算不只用在两个一体机步骤上（brief 原始草稿只给这两步套了
/// 超时），Gateway 的 DNS 解析与 TLS 连接同样套着，理由见 `bounded`。
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    Pass { detail: String },
    Fail { detail: String, class: ErrorClass },
    Skipped { detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightStep {
    pub name: &'static str,
    pub outcome: StepOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightReport {
    pub steps: Vec<PreflightStep>,
}

impl PreflightReport {
    pub fn passed(&self) -> bool {
        self.steps
            .iter()
            .all(|s| matches!(s.outcome, StepOutcome::Pass { .. }))
    }

    /// 第一条真正 `Fail` 的步骤——`Skipped` 不算失败，只是"因为前一步
    /// 没过，这一步没跑"，不能被这里当成需要报告给工程师的根因。
    pub fn first_failure(&self) -> Option<&PreflightStep> {
        self.steps
            .iter()
            .find(|s| matches!(s.outcome, StepOutcome::Fail { .. }))
    }
}

fn fail(e: &Error) -> StepOutcome {
    StepOutcome::Fail {
        detail: e.to_string(),
        class: e.class(),
    }
}

/// 给一个网络操作套上 [`PROBE_TIMEOUT`]，超时时用 `on_timeout()` 现造一个
/// 错误——错误闭包而不是现成的 `Error` 值，是为了避免
/// `clippy::or_fun_call` 那类"默认值本身有构造开销，应该惰性求值"的
/// 提醒：`format!` 分配的字符串只在真的超时这一条分支上才会被造出来。
///
/// 这不是 brief 原始草稿的写法——草稿只给两个一体机步骤（`appliance_banner`/
/// `appliance_host_key`）套了 `tokio::time::timeout`，Gateway 的 DNS 解析
/// 与 `Transport::connect`（TCP 拨号 + 可选 HTTP CONNECT + TLS 握手）完全
/// 裸跑，没有任何超时保护。`Transport::connect` 内部的 `TcpStream::connect`
/// 本身没有超时，`tls::wrap_tls` 也没有——对着一个只完成三次握手、之后
/// 再也不发一个字节的对端（防火墙静默丢包、慢速代理），`preflight::run`
/// 会挂在这一步上不返回，跟 R4 说的"预检不该让状态机挂住"是同一类问题，
/// 只是触发条件从"注入不了假实现"换成了"真实网络里一个不说话的对端"。
/// 一体机的两步已经套了超时，Gateway 的两步没有理由被漏掉。
async fn bounded<T>(
    fut: impl Future<Output = Result<T, Error>>,
    on_timeout: impl FnOnce() -> Error,
) -> Result<T, Error> {
    tokio::time::timeout(PROBE_TIMEOUT, fut)
        .await
        .unwrap_or_else(|_| Err(on_timeout()))
}

/// 读取一体机的 SSH banner，确认端口后面真的是个 SSH 服务，不只是"端口
/// 开着"——一个开着的端口后面跑着别的协议（或者压根什么都不说）对工程师
/// 而言跟"根本连不上"一样没用。只做版本行这一步，不做 KEX，等价于
/// `nc` 探测。
async fn appliance_banner(appliance: &HostPort) -> Result<String, Error> {
    let mut s = tokio::time::timeout(
        PROBE_TIMEOUT,
        TcpStream::connect((appliance.host(), appliance.port())),
    )
    .await
    .map_err(|_| Error::ApplianceUnreachable(format!("连接 {appliance} 超时")))?
    .map_err(|e| Error::ApplianceUnreachable(format!("连接 {appliance} 失败：{e}")))?;

    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(PROBE_TIMEOUT, s.read(&mut buf))
        .await
        .map_err(|_| Error::ApplianceUnreachable("读取 SSH banner 超时".into()))?
        .map_err(|e| Error::ApplianceUnreachable(format!("读取 SSH banner 失败：{e}")))?;
    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    if !banner.starts_with("SSH-2.0-") {
        return Err(Error::ApplianceUnreachable(format!(
            "{appliance} 未返回 SSH banner：{banner}"
        )));
    }
    Ok(banner)
}

/// 真正拨号一体机，随即把连接交给 [`probe_host_key_over`] 做 KEX。
///
/// 拆成"拨号"（这里，需要真实 TCP）与"KEX 取指纹"（`probe_host_key_over`，
/// 只需要一条 `AsyncRead + AsyncWrite` 流）两段，用的是
/// `crate::ssh::mod` 里 `establish`/`establish_over` 同一个拆分手法——
/// 目的也一样：让 `crate::ssh::test_support` 的进程内假 SSH 服务端能把
/// 后一段（`check_server_key` 回调、指纹计算）钉在每一次 `cargo test`
/// 里，不需要真的起 TCP 连接、不需要 docker。
async fn appliance_host_key(appliance: &HostPort) -> Result<String, Error> {
    let stream = tokio::time::timeout(
        PROBE_TIMEOUT,
        TcpStream::connect((appliance.host(), appliance.port())),
    )
    .await
    .map_err(|_| Error::ApplianceUnreachable(format!("连接 {appliance} 超时")))?
    .map_err(|e| Error::ApplianceUnreachable(format!("连接 {appliance} 失败：{e}")))?;

    tokio::time::timeout(PROBE_TIMEOUT, probe_host_key_over(Box::new(stream)))
        .await
        .unwrap_or_else(|_| Err(Error::ApplianceUnreachable("SSH 握手超时".into())))
}

/// 与对端做一次 KEX 取 host key 指纹，随即断开——不认证，等价于
/// `ssh-keyscan`。真正的 host key 比对（首次记录/变更拒绝）在认证之前
/// 必经的 `ssh::handler::ClientHandler::check_server_key` 里，这里只是
/// 让工程师提前看到指纹，不做任何 known_hosts 读写。
///
/// ## F2（本任务开工前预扫描已发现）：按 russh 0.63 的真实签名写
///
/// `check_server_key` 收的是 `&PublicKeyOrCertificate`，不是
/// `&PublicKey`——必须先 `.public_key()` 转一次，`PublicKeyOrCertificate`
/// 自己没有 `public_key_bytes()`。`impl russh::client::Handler` 不能加
/// `#[async_trait::async_trait]`：这个 trait 自 0.5x 起用原生 `async fn`
/// （`-> impl Future`），`async-trait` 是 russh 的非默认 feature，
/// `Cargo.toml` 没打开，硬加这个属性宏会直接编译不过。`type Error` 用
/// `crate::error::Error`——`error.rs` 已经给它写好了
/// `impl From<russh::Error> for Error`，满足 `Handler` trait 要求的
/// `Self::Error: From<russh::Error>`。Task 7 的 `ssh::handler::
/// ClientHandler` 已经把这些都趟平了，这里照抄它的写法，不重新发明。
async fn probe_host_key_over(conn: Conn) -> Result<String, Error> {
    struct Probe {
        fp: Arc<Mutex<Option<String>>>,
    }

    impl russh::client::Handler for Probe {
        type Error = Error;

        async fn check_server_key(
            &mut self,
            server_public_key: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            use russh::keys::PublicKeyBase64;
            let key = server_public_key.public_key();
            let blob = key.public_key_bytes();
            // 与 handler.rs 里同一处检查同样的理由：`public_key_bytes()`
            // 编码失败时悄悄退化成空 `Vec`，空 blob 的指纹是一个固定值，
            // 会匹配任何同样触发了编码失败的服务端。
            if blob.is_empty() {
                return Err(Error::SshTransport(
                    "服务端公钥编码为空，无法计算指纹".into(),
                ));
            }
            // 用 `knownhosts::fingerprint_of` 直接拿类型化的 Fingerprint，
            // 不走 `Fingerprint::new(&fingerprint_sha256(...)).expect(...)`
            // 这种"round-trip 永远不会失败"却仍然在安全关键路径上留一个
            // `expect` 的写法——`fingerprint_of` 本身就在指纹自己的模块
            // 内构造，跳过了这道本可避免的 panic 风险，见 knownhosts.rs
            // 上 `fingerprint_of` 的文档。
            let fp = fingerprint_of(&blob);
            // 只是探测指纹给工程师看，接受任意 key——真正拒绝变更过的
            // host key 是认证前必经的 `ClientHandler::check_server_key`
            // 的职责（Task 7），这里 `Ok(true)` 只是让握手走到能读出
            // 指纹的这一步，不代表这把 key 通过了任何校验。
            *self.fp.lock().unwrap() = Some(fp.as_str().to_string());
            Ok(true)
        }
    }

    let fp: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let handler = Probe { fp: fp.clone() };
    let session =
        russh::client::connect_stream(Arc::new(russh::client::Config::default()), conn, handler)
            .await
            .map_err(|e| Error::ApplianceUnreachable(format!("SSH 握手失败：{e}")))?;
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await;

    // F16（本任务开工前预扫描已发现）：不能把 `fp.lock().unwrap().clone()
    // .ok_or_else(...)` 直接当函数的尾表达式返回——按 Rust 的丢弃顺序
    // 规则，块尾表达式里产生的临时量（这里是 `fp.lock()` 返回的
    // `MutexGuard`）在块自身的局部变量（这里是 `fp`）之后才丢弃，而
    // `MutexGuard` 借用着 `fp`，编译不过：
    // `error[E0597]: fp does not live long enough`（本地用 rustc 复现过，
    // 报错原文与这里的写法逐字一致）。先 `let` 绑定成一个新变量，
    // `MutexGuard` 在这条语句结束时就丢弃，不再需要借用到函数末尾——
    // `ssh::mod::establish_over` 里结构相同的一段（读 `verdict` 那段）
    // 正是这么写的，这里照抄同一个形状。
    let fp = fp.lock().unwrap().clone();
    fp.ok_or_else(|| Error::ApplianceUnreachable("握手未返回 host key".into()))
}

pub async fn run(
    transport: &Transport,
    gateway: &HostPort,
    appliance: &HostPort,
) -> PreflightReport {
    let mut steps = Vec::with_capacity(4);

    // 1. 一体机 TCP 与 banner。
    let appliance_ok = match appliance_banner(appliance).await {
        Ok(banner) => {
            steps.push(PreflightStep {
                name: STEP_APPLIANCE_TCP,
                outcome: StepOutcome::Pass {
                    detail: format!("{appliance} 可达 · {banner}"),
                },
            });
            true
        }
        Err(e) => {
            steps.push(PreflightStep {
                name: STEP_APPLIANCE_TCP,
                outcome: fail(&e),
            });
            false
        }
    };

    // 2. 一体机 host key 指纹——依赖第 1 步，第 1 步没过就不用再拨一次号。
    if appliance_ok {
        let outcome = match appliance_host_key(appliance).await {
            Ok(fp) => StepOutcome::Pass { detail: fp },
            Err(e) => fail(&e),
        };
        steps.push(PreflightStep {
            name: STEP_APPLIANCE_HOSTKEY,
            outcome,
        });
    } else {
        steps.push(PreflightStep {
            name: STEP_APPLIANCE_HOSTKEY,
            outcome: StepOutcome::Skipped {
                detail: "一体机不可达，未执行".into(),
            },
        });
    }

    // 3. Gateway 域名解析。
    let dns_result = bounded(transport.resolve_dns(gateway.host()), || {
        Error::Dns(format!("解析 {} 超时", gateway.host()))
    })
    .await;
    let dns_ok = match dns_result {
        Ok(addrs) => {
            let list = addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            steps.push(PreflightStep {
                name: STEP_GATEWAY_DNS,
                outcome: StepOutcome::Pass {
                    detail: format!("{} → {list}", gateway.host()),
                },
            });
            true
        }
        Err(e) => {
            steps.push(PreflightStep {
                name: STEP_GATEWAY_DNS,
                outcome: fail(&e),
            });
            false
        }
    };

    // 4. Gateway TLS，经代理时含 CONNECT——依赖第 3 步，域名都解不出来就
    // 没有地址可拨。
    if dns_ok {
        let proxy = transport.effective_proxy(gateway).await;
        let connect_result = bounded(transport.connect(gateway), || {
            Error::TlsHandshake(format!("连接 {gateway} 超时（含 TCP 拨号与代理 CONNECT）"))
        })
        .await;
        let outcome = match connect_result {
            Ok(conn) => {
                drop(conn);
                let via = match proxy {
                    Some(p) => format!("经代理 {p}"),
                    None => "直连".to_string(),
                };
                StepOutcome::Pass {
                    detail: format!("握手成功 · {via}"),
                }
            }
            Err(e) => fail(&e),
        };
        steps.push(PreflightStep {
            name: STEP_GATEWAY_TLS,
            outcome,
        });
    } else {
        steps.push(PreflightStep {
            name: STEP_GATEWAY_TLS,
            outcome: StepOutcome::Skipped {
                detail: "域名解析失败，未执行".into(),
            },
        });
    }

    PreflightReport { steps }
}

/// 让 [`run`] 可以被替换成假实现的接缝——见模块顶部 R4 的说明。
#[async_trait::async_trait]
pub trait Preflight: Send + Sync {
    async fn run(&self, gateway: &HostPort, appliance: &HostPort) -> PreflightReport;
}

/// 生产用的 [`Preflight`] 实现，底层就是本模块的自由函数 [`run`]。
pub struct TransportPreflight {
    transport: Arc<Transport>,
}

impl TransportPreflight {
    pub fn new(transport: Arc<Transport>) -> Self {
        Self { transport }
    }
}

#[async_trait::async_trait]
impl Preflight for TransportPreflight {
    async fn run(&self, gateway: &HostPort, appliance: &HostPort) -> PreflightReport {
        run(&self.transport, gateway, appliance).await
    }
}

#[cfg(test)]
mod tests {
    //! `passed`/`first_failure` 是纯逻辑，直接拿字面量构造 `PreflightReport`
    //! 验证，不需要网络；`probe_host_key_over` 跑在
    //! `crate::ssh::test_support` 的进程内假 SSH 服务端上——不需要
    //! docker、DNS、真实 TCP，`cargo test -p rmc-core` 任何一次都会跑到。
    //! 需要真实网络/docker 的四步整体行为在 `tests/preflight.rs` 里。

    use super::*;

    fn step(name: &'static str, outcome: StepOutcome) -> PreflightStep {
        PreflightStep { name, outcome }
    }

    fn pass() -> StepOutcome {
        StepOutcome::Pass {
            detail: "ok".into(),
        }
    }

    fn skipped() -> StepOutcome {
        StepOutcome::Skipped {
            detail: "skipped".into(),
        }
    }

    fn failed(class: ErrorClass) -> StepOutcome {
        StepOutcome::Fail {
            detail: "boom".into(),
            class,
        }
    }

    // 会让这条测试变红的实现改法：把 `passed()` 里的 `all` 换成
    // `any`，或者把 `matches!` 里的 `Pass` 换成 `!Fail`（后者会把
    // `Skipped` 也算作"通过"）。
    #[test]
    fn passed_is_true_only_when_every_step_is_pass() {
        let all_pass = PreflightReport {
            steps: vec![step("a", pass()), step("b", pass())],
        };
        assert!(all_pass.passed());

        let one_skipped = PreflightReport {
            steps: vec![step("a", pass()), step("b", skipped())],
        };
        assert!(
            !one_skipped.passed(),
            "Skipped 不是 Pass，不能被算成整体通过"
        );

        let one_failed = PreflightReport {
            steps: vec![step("a", pass()), step("b", failed(ErrorClass::Network))],
        };
        assert!(!one_failed.passed());
    }

    // 会让这条测试变红的实现改法：把 `first_failure` 里的 `matches!(...,
    // StepOutcome::Fail { .. })` 放宽成"不是 Pass 就算"——那样第一个
    // `Skipped` 就会被误当成"失败的根因"报给工程师，而它只是"没跑"，
    // 不是"跑了但失败"。
    #[test]
    fn first_failure_skips_over_skipped_steps() {
        let report = PreflightReport {
            steps: vec![
                step("a", pass()),
                step("b", skipped()),
                step("c", failed(ErrorClass::Fatal)),
                step("d", skipped()),
            ],
        };
        let first = report.first_failure().expect("应该找到一条 Fail");
        assert_eq!(first.name, "c");
    }

    #[test]
    fn first_failure_is_none_when_nothing_failed() {
        let report = PreflightReport {
            steps: vec![step("a", pass()), step("b", skipped())],
        };
        assert!(report.first_failure().is_none());
    }

    // --- 下面这条跑在 Task 7 的进程内假 SSH 服务端上，把 `probe_host_key_
    // over`（`appliance_host_key` 依赖真实 TCP 才能测的那一半之外的核心
    // 逻辑）钉住：真的做一次 KEX，指纹必须等于独立算出来的期望值，而不是
    // 随便返回点什么就能让测试通过。会让这条测试变红的实现改法：
    // `check_server_key` 里改成对 `fp` 塞一个固定字符串（不经过
    // `fingerprint_of`），或者压根不读 `server_public_key`。---

    #[tokio::test]
    async fn probe_host_key_over_reports_the_real_servers_fingerprint() {
        use crate::ssh::test_support::{
            expected_fingerprint, spawn_gateway, with_timeout, GatewayConfig,
        };

        let (_reads, _pending, conn) = spawn_gateway(GatewayConfig::default());
        let fp = with_timeout("probe_host_key_over", probe_host_key_over(conn))
            .await
            .expect("对着假 Gateway 探测 host key 不应该失败");
        assert_eq!(fp, expected_fingerprint().as_str());
    }

    // R56（第二轮评审，LOW）：`tests/preflight.rs` 原来有一条 `#[ignore]`
    // 的 `appliance_hostkey_step_reports_a_sha256_fingerprint`，需要
    // `gateway/test-env` 的 `appliance` 服务在运行——但它测的是
    // `appliance_host_key`（真实 TCP 拨号 + KEX），而 `appliance_host_key`
    // 需要的只是"TCP 那一头真的是个会做 SSH 握手的服务端"，不需要真的是
    // OpenSSH，也不需要 docker：`russh::server::run_stream` 泛型于任意
    // `AsyncRead + AsyncWrite`，直接喂一个真实的 `tokio::net::TcpStream`
    // 就能在进程内把"服务端"这一半也用 russh 实现，不用 `ssh::
    // test_support::spawn_gateway` 的内存双工管道。这条测试因此把
    // 那条 ignored 用例的断言原样搬到默认会跑的 `cargo test` 里：真的
    // `TcpStream::connect` 一个本机端口，真的做一次 KEX，一体机 TCP／
    // host key 两步都必须是 `Pass`，指纹必须等于独立算出来的期望值。
    // 覆盖范围比原来那条 ignored 用例更宽（原来的只验证
    // `STEP_APPLIANCE_HOSTKEY`，这条连 `STEP_APPLIANCE_TCP` 的 banner
    // 检查也一并覆盖了——`russh::server::run_stream` 发送的版本行天然
    // 以 "SSH-2.0-" 开头），原来那条 ignored 用例因此删掉，不再需要
    // docker、也不再计入本 crate 的 ignored 总数。
    //
    // 会让这条测试变红的实现改法：跟
    // `probe_host_key_over_reports_the_real_servers_fingerprint` 一样，
    // 把 `check_server_key` 改成塞固定字符串；或者把 `appliance_banner`
    // 的 `Ok`/`Err` 分支写反。
    #[tokio::test]
    async fn appliance_tcp_and_hostkey_steps_pass_over_a_real_tcp_socket() {
        use crate::ssh::test_support::{expected_fingerprint, test_host_key};

        struct MinimalServer;
        impl russh::server::Handler for MinimalServer {
            type Error = russh::Error;
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_config = Arc::new(russh::server::Config {
            keys: vec![test_host_key()],
            ..Default::default()
        });
        // `run()` 对一体机做两次独立的 TCP 拨号（`appliance_banner`、
        // `appliance_host_key` 各一次），服务端必须能接住不止一条连接，
        // 否则第二次拨号会因为监听端已经在第一次 `accept` 之后被丢弃而
        // 被拒绝/重置——不是每个连接各起一个监听端口，而是循环 accept，
        // 每条连接各自 spawn 一个 `run_stream`。
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let cfg = server_config.clone();
                tokio::spawn(run_stream_ignoring_errors(cfg, stream));
            }
        });

        async fn run_stream_ignoring_errors(
            cfg: Arc<russh::server::Config>,
            stream: tokio::net::TcpStream,
        ) {
            let _ = russh::server::run_stream(cfg, stream, MinimalServer).await;
        }

        let appliance = HostPort::new("127.0.0.1", port).unwrap();
        // 这条只关心一体机的两步，Gateway 用一个保证解析失败的名字，
        // 避免这条不需要网络的测试意外摸到真实 DNS。
        let gateway: HostPort = format!("{}.invalid:443", "a".repeat(64)).parse().unwrap();

        let r = run(
            &Transport::new(
                Arc::new(crate::platform::NoProxy),
                Arc::new(crate::platform::NoProxyAuth),
                crate::transport::tls::TlsRoots::webpki(),
            ),
            &gateway,
            &appliance,
        )
        .await;

        let tcp = r
            .steps
            .iter()
            .find(|s| s.name == STEP_APPLIANCE_TCP)
            .unwrap();
        assert!(
            matches!(tcp.outcome, StepOutcome::Pass { .. }),
            "{:?}",
            tcp.outcome
        );

        let hostkey = r
            .steps
            .iter()
            .find(|s| s.name == STEP_APPLIANCE_HOSTKEY)
            .unwrap();
        match &hostkey.outcome {
            StepOutcome::Pass { detail } => {
                assert!(detail.contains("SHA256:"), "{detail}");
                assert_eq!(detail, expected_fingerprint().as_str());
            }
            other => panic!("{other:?}"),
        }
    }

    // --- R54（第二轮评审，HIGH）：四步里 Pass 方向完全没有测试守着——
    // `tests/preflight.rs` 已有的用例只覆盖 Fail/Skipped，Gateway TLS
    // 步骤的成功分支唯一的把关者是 `#[ignore]` 的
    // `all_four_steps_pass_against_the_harness`，本仓没有任何 CI 会跑
    // 它。评审把 `run()` 里 TLS 步骤的成功分支改成恒定 `Fail`，146 条
    // 依旧全绿。这里在进程内起一个真正的 rustls TLS 服务端（自签证书，
    // 固定下来而不是每次现生成——跟 `ssh::test_support` 里固定 Ed25519
    // host key 是同一个理由：两次连接不需要额外传证书对象），通过
    // `TlsRoots::with_extra_pem` 把它加成信任根（Task 6 已经趟平的
    // 用法，跟 `tests/transport.rs` 信任 harness 自签证书是同一个模式），
    // 证明 DNS 成功、证书受信时 TLS 步骤真的是 `Pass`。
    //
    // 会让这条测试变红的实现改法：把 `run()` 里 TLS 步骤 `Ok(conn) =>
    // {...}` 分支的结果强制改成 `fail(&e)`（不管 `transport.connect`
    // 是否真的成功）——本地验证过：改完这条测试会在 `match` 的 `other`
    // 分支上 panic。

    /// 固定的测试专用 EC (P-256) 自签证书 + 私钥，本地用
    /// `openssl req -x509 -newkey ec ...` 生成一次，CN/SAN 都是
    /// `localhost`，只用来跑进程内假 Gateway 的 TLS 服务端，不是任何
    /// 真实环境的凭据，有效期 100 年（避免这条测试因为证书过期而莫名
    /// 变红）。
    const TEST_TLS_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBODCB36ADAgECAgkAr2yXAE+wDB8wCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJ\n\
bG9jYWxob3N0MCAXDTI2MDkxNDAzNDE1M1oYDzIxMjYwODIxMDM0MTUzWjAUMRIw\n\
EAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ50frL\n\
mLEPSa7z0sqCmmRXJQQxgTfzxlcoJ4CKlST85mlZ9Fl2Un3fPCYFwtRi0eEJ4jAh\n\
5cf6WHGmEM9gZlsVoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0E\n\
AwIDSAAwRQIgAQ1gD0AFOxtEdH0SRv1x7wvGDHHzEXsEqehSXayGKjcCIQCXRetW\n\
I3vKyk+IVraIkoFtpwtyhck6zxYrkM07snH3iw==\n\
-----END CERTIFICATE-----\n";

    const TEST_TLS_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqqQ6iAlPo7gj+MbM\n\
Z5JHB/f/r1o7nt406+2/PKx/N1yhRANCAAQ50frLmLEPSa7z0sqCmmRXJQQxgTfz\n\
xlcoJ4CKlST85mlZ9Fl2Un3fPCYFwtRi0eEJ4jAh5cf6WHGmEM9gZlsV\n\
-----END PRIVATE KEY-----\n";

    #[tokio::test]
    async fn gateway_tls_step_passes_when_the_certificate_is_trusted() {
        use crate::platform::{NoProxy, NoProxyAuth};
        use crate::transport::tls::TlsRoots;

        let certs: Vec<_> = rustls_pemfile::certs(&mut TEST_TLS_CERT_PEM.as_bytes())
            .collect::<std::result::Result<_, _>>()
            .expect("测试证书应该能被解析");
        let key = rustls_pemfile::private_key(&mut TEST_TLS_KEY_PEM.as_bytes())
            .expect("测试私钥应该能被解析")
            .expect("测试私钥不应该缺失");
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("测试证书与私钥应该匹配");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                // 预检的 TLS 步骤只关心握手成不成功，完成一次握手就够了。
                let _ = acceptor.accept(sock).await;
            }
        });

        let mut roots = TlsRoots::webpki();
        roots.with_extra_pem(TEST_TLS_CERT_PEM.as_bytes()).unwrap();
        let transport = Transport::new(Arc::new(NoProxy), Arc::new(NoProxyAuth), roots);

        let gateway: HostPort = format!("localhost:{port}").parse().unwrap();
        // 一体机步骤跟这条测试无关，绑一个立刻释放的端口，保证空置、
        // 快速失败，不拖慢这条只关心 TLS 步骤的测试。
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let appliance = HostPort::new("127.0.0.1", dead.local_addr().unwrap().port()).unwrap();
        drop(dead);

        let r = run(&transport, &gateway, &appliance).await;
        let tls = r.steps.iter().find(|s| s.name == STEP_GATEWAY_TLS).unwrap();
        match &tls.outcome {
            StepOutcome::Pass { .. } => {}
            other => panic!("证书受信、握手应该成功，实际却是 {other:?}"),
        }
    }

    // --- R55（第二轮评审，MED）：`bounded()` 的超时分支之前没有任何
    // 测试命中过。用 `#[tokio::test(start_paused = true)]` 配
    // `std::future::pending`（一个定义上永远不会自己完成、也不注册任何
    // 定时器的占位 future）：`tokio::time::timeout` 内部会为它挂一个
    // `PROBE_TIMEOUT` 之后到期的定时器，虚拟时钟在"没有别的活干、只剩
    // 这一个定时器"时会自动跳到它的到期时刻——不需要真的等 8 秒挂钟
    // 时间，也不需要改一行生产代码：`bounded` 本来就泛型于任意
    // `Future`，这条本来就是免费的。
    //
    // 会让这条测试变红的实现改法：把 `unwrap_or_else(|_| Err(on_timeout()))`
    // 换成别的错误分支（本地验证过：改成 `Err(Error::AuthRejected)`，
    // 这条测试立刻在 `match` 上失败）。把 `bounded` 里的
    // `tokio::time::timeout(PROBE_TIMEOUT, fut)` 直接换成裸 `fut`（去掉
    // 超时保护）则会让这条测试真的挂住——`std::future::pending()` 定义
    // 上就是永远不完成、也不注册任何定时器，虚拟时钟的自动前进机制救
    // 不了一个压根没有定时器可跳的死等，这正是这条测试想防住的后果，
    // 不需要在提交里真的复现一次死锁来证明它。
    #[tokio::test(start_paused = true)]
    async fn bounded_times_out_without_waiting_for_the_probe_budget_in_real_time() {
        let result: Result<(), Error> =
            bounded(std::future::pending(), || Error::Dns("探测超时占位".into())).await;
        match result {
            Err(Error::Dns(msg)) => assert_eq!(msg, "探测超时占位"),
            other => panic!("超过 PROBE_TIMEOUT 应该报超时错误，实际却是 {other:?}"),
        }
    }
}
