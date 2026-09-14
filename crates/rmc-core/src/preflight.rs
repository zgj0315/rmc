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
//! - 更糟的是这不是一次快速失败，是**挂住**：`start_paused = true` 下
//!   虚拟时钟只在"没有别的活干"时才会被 `tokio::time::sleep` 一类调用
//!   推进；一旦真的发起了 `TcpStream::connect`/`lookup_host` 这类不受
//!   虚拟时钟控制的真实系统调用，测试会卡在等待真实网络返回上，
//!   `start_paused` 帮不上忙，等待状态变化的断言永远等不到超时，
//!   `cargo test` 直接挂起。
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
}
