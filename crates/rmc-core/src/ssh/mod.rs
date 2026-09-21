//! russh 实现的隧道：握手、host key 校验、口令认证、反向端口注册。

pub mod handler;
pub mod pump;

#[cfg(test)]
pub(crate) mod test_support;

use crate::error::{Error, Result};
use crate::platform::Conn;
use crate::transport::Transport;
use crate::tunnel::{TunnelFactory, TunnelHandle, TunnelMsg, TunnelParams, UnknownSessionId};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex as AsyncMutex};

/// R96（最终复审）：这里**没有** `gateway` 字段，是故意的。
///
/// 原来有——`new()` 收一个 `gateway: HostPort` 存起来，`establish()`
/// 就拨那一个、host key 也对那一个比。于是「界面上显示、预检探测、
/// 审计日志记录的那台 Gateway」与「隧道实际连上、host key 实际比对的
/// 那台 Gateway」变成两个可以各自漂移的真相来源，而工厂是
/// `Supervisor::spawn` 时一次性传进 `Deps` 的，此后无法更换——方案
/// §3.8 要求的「Gateway 地址与端口可现场修改」在那套 API 下做不到，
/// 而且失配时没有任何东西会报错，只会安静地连错机器。完整的因果与
/// 实测见 `tunnel::TunnelParams` 上的文档。
///
/// 现在 Gateway 地址随每一次 `establish` 从 [`TunnelParams`] 进来，
/// 工厂只留跟具体目标无关的一样东西：拨号用的 `Transport`。
///
/// Task 10：`known_hosts` 字段删掉了——SSH host key 校验换成核对连接码
/// 里的指纹（`params.fingerprint`），没有本地状态需要工厂替它保管。
pub struct SshTunnelFactory {
    transport: Arc<Transport>,
}

impl SshTunnelFactory {
    pub fn new(transport: Arc<Transport>) -> Self {
        Self { transport }
    }
}

/// Task 10 新增：`session` 从直接持有改成 `Arc<AsyncMutex<..>>`，理由见
/// [`spawn_disconnect_watcher`]——一个独立的后台任务需要能在
/// `SshTunnel`（负责 `close_remote_session`/`shutdown`）之外，同时对同一个
/// `Handle` 做一次轻量的 `is_closed()` 检查，`Handle` 本身不是 `Clone`，
/// 共享所有权是唯一的办法。锁只在检查/断开这类不跨越应用层等待的短操作
/// 上持有，不构成争用热点。
pub struct SshTunnel {
    session: Arc<AsyncMutex<russh::client::Handle<handler::ClientHandler>>>,
    channels: pump::SharedChannels,
    /// R76：`shutdown()` 是否已经真的把 disconnect 发出去了。只由
    /// [`Drop`] 读取，用来判断还需不需要补一次——见 `impl Drop for
    /// SshTunnel` 上的说明。
    disconnected: AtomicBool,
}

/// 把"给 Gateway 发一条 disconnect"这一步单列出来，`shutdown()`（正常
/// 路径）和 [`Drop`]（兜底路径）共用同一份实现，不会长歪。
///
/// 失败一律忽略：会话可能早就死了（对端先断、keepalive 超时），这时
/// 发不出去是正常的，也没有任何补救动作可做。
async fn disconnect_session(session: &AsyncMutex<russh::client::Handle<handler::ClientHandler>>) {
    let _ = session
        .lock()
        .await
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await;
}

/// R76（第四轮评审，纵深防御）：**句柄被丢弃而没有 `shutdown()`，必须
/// 不再等于 Gateway 侧的真实泄漏。**
///
/// 到第四轮为止，同一个根源已经三次造成真实泄漏（`Start` 紧接 `Cancel`、
/// `Start` 紧接第二条 `Start`、`Backoff` 中连发两条系统事件），三次都是
/// `supervisor.rs` 主循环里某一处把 `Box<dyn TunnelHandle>` 丢掉而没有
/// `shutdown()`。之所以每一次都会升级成"Gateway 上留下一条活着的会话和
/// 一个已注册的反向端口"，是因为：
///
/// 1. `SshTunnel` 原来没有 `Drop`，丢弃它不会发出任何 disconnect；
/// 2. [`spawn_disconnect_watcher`] 起的那个后台任务还攥着
///    `Arc<AsyncMutex<Handle>>`，所以 `SshTunnel` 被丢弃时 `Handle`
///    本身**不会**被析构，russh 的会话任务继续活着，TCP 连接也继续
///    活着——连"靠析构顺带断开"这条退路都被堵死了。
///
/// 逐个堵调用点是治标（而且第三次证明了它堵不干净）；给类型加 `Drop`
/// 是对**整类**缺陷的防御，也更耐后人改动：以后任何人在主循环里新写
/// 一条路径、忘了 `shutdown()`，代价从"必须重启进程才能解除的生产
/// 故障"降级成"晚了最多一个调度周期的断开"。
///
/// 实现上的两处约束：
///
/// - `Drop::drop` 不能 `async`，disconnect 必须走一个 detached 任务；
/// - `tokio::spawn` 在没有运行时上下文时会 panic——在 `Drop` 里 panic
///   尤其危险（可能发生在栈展开过程中，导致 abort）。用
///   [`tokio::runtime::Handle::try_current`] 判断，拿不到就安静放弃：
///   这种情况意味着运行时已经关掉、或者根本不在运行时线程上，几乎必然
///   是进程正在退出，操作系统会关掉这条 TCP 连接，Gateway 侧的 sshd
///   随之收掉会话与反向端口——真正需要这条兜底的场景（进程继续跑、
///   运行时还活着，只是主循环把句柄弄丢了）恰好就是 `try_current()`
///   一定成功的那个场景。
///
/// 正常走过 `shutdown()` 的句柄不会在这里重复发一次 disconnect：
/// `disconnected` 标志由 `shutdown()` 在 disconnect **真的完成之后**
/// 才置位，所以"`shutdown()` 的 future 跑到一半被取消"这种情况仍然会
/// 落到这条兜底路径上，正是想要的行为。
///
/// R81（Task 11 复审顺手做）：兜底真的触发时补一条 `tracing::warn!`。
/// 上一轮实现者拒绝在这里打日志，理由是 `ssh/pump.rs` 里 R59 那条哨兵
/// 测试对全 crate 的 `warn!` 分布有依赖——那条测试现在已经改成对捕获
/// 内容做匹配（含端口号 "22002"、不含转发内容的特征字节，见该文件
/// R74 的说明），不再要求"全 crate 只有一处 `warn!` callsite"，这个
/// 顾虑不成立了。
///
/// 信号故意放在 `tracing`，不放进 `crate::audit` 那本审计日志：兜底
/// 生效意味着代码本身有 bug（主循环某处又漏了 `shutdown()`，跟
/// R71/R72/R75 是同一个根源），这是给开发者/维护者看的**实现缺陷**
/// 信号，不是给现场工程师或事后追责审计看的**运维事件**——审计日志的
/// 受众关心"谁连到了哪台一体机、干了多久"，混进一条"某个内部句柄被
/// 兜底回收"只会让真正的账目更难读，且暴露的是代码问题而不是会话
/// 本身的任何事实。少这条 tracing 信号的代价是：`Drop` 把泄漏兜住的
/// 同时，也把"有人新写了一条忘记 `shutdown` 的路径"这件事从生产环境
/// 里完全藏起来——见本函数文档最上面那段："晚了最多一个调度周期的
/// 断开"不该是一个没人会注意到的降级。
impl Drop for SshTunnel {
    fn drop(&mut self) {
        if self.disconnected.load(Ordering::SeqCst) {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            // 拿不到运行时通常意味着进程正在退出，操作系统会收掉 TCP
            // 连接——不在这里打日志：那是"正常关闭"，不是需要有人去看
            // 的实现缺陷，见本函数文档上面那段说明。
            return;
        };
        // 兜底真的要发一次 disconnect 了——这本身就是一个信号："有一条
        // 路径持有了 `SshTunnel` 却没调用 `shutdown()`"，且运行时还
        // 活着（不是进程退出的正常路径）。不含地址、会话 id、字节数：
        // 这条日志的受众是读代码的人，不是审计。
        tracing::warn!(
            "SshTunnel 被丢弃时尚未 shutdown()，Drop 兜底补发了一次 \
             disconnect——这意味着某处调用点忘了 shutdown()，是需要修的 \
             实现缺陷，不是运维事件"
        );
        let session = self.session.clone();
        rt.spawn(async move {
            disconnect_session(&session).await;
        });
    }
}

/// `Handle::is_closed()` 的轮询间隔。见 [`spawn_disconnect_watcher`]。
///
/// 200ms 是权衡过的：轮询本身不消耗虚拟时钟之外的真实等待（`#[tokio::
/// test(start_paused = true)]` 下的 `tokio::time::sleep` 在没有别的活干时
/// 会被虚拟时钟直接跳过），但它给测量 keepalive 断线判定耗时的测试
/// （`supervisor.rs`）引入了至多 200ms 的滞后——相对于方案设计.md §3.4
/// 实测的约 40 秒量级，这个滞后可以忽略；数值定得比这更大会让"最坏情况
/// 滞后"开始逼近需要在报告里额外说明的量级，比这更小则会让非
/// `start_paused` 的普通测试（`ssh::mod::tests`）里轮询本身的调度开销
/// 变得不必要地密集，两者之间取了个整数。
const DISCONNECT_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// R——本任务（Task 10）开工前发现的缺口：`establish_over` 建好隧道之后，
/// 如果底层 SSH 会话中途死掉（对端主动断开、或者 keepalive 连续
/// `keepalive_max` 次无应答被 russh 自己判定为 `KeepaliveTimeout`），
/// 在这一行代码存在之前**没有任何人会注意到**——`TunnelHandle` 只有
/// `close_remote_session`/`shutdown` 两个方法，都是调用方主动发起的操作，
/// 没有任何一处会主动去问"这条隧道是不是已经死了"。`tunnel::TunnelMsg`
/// 里其实早就定义了 `Disconnected { reason }` 这个变体（Task 7 就有），
/// 但在这个函数存在之前，从来没有任何生产代码路径会真的送出它。
///
/// `Handle<H>` 没有暴露"等待关闭"的方法，唯一能问的是同步的
/// `is_closed()`——它背后是 `mpsc::Sender::is_closed()`：当 `Handle`
/// 内部对应的接收端被丢弃（也就是 `session.run(...)` 那个后台任务返回、
/// 它拥有的 `Session` 被整体析构）时变为 `true`。没有事件可等，只能轮询，
/// 于是有了 [`DISCONNECT_POLL_INTERVAL`]。
///
/// 这个任务在 `Supervisor`（Task 10 的另一半）能观察到之前，不需要、也
/// 不应该做任何分类判断——它只负责如实转告"会话没了"，`reason` 里不放
/// 任何猜测出来的原因（尤其不能把 `KeepaliveTimeout` 这个词或数字写进
/// 面向用户的文案，见 `error.rs` 上 `Error::KeepaliveTimeout` 的说明），
/// 分类交给 `Supervisor` 按 `Error::SshTransport(reason).class()`
/// （`Network`）统一处理。
fn spawn_disconnect_watcher(
    session: Arc<AsyncMutex<russh::client::Handle<handler::ClientHandler>>>,
    tx: mpsc::Sender<TunnelMsg>,
) {
    tokio::spawn(async move {
        loop {
            if session.lock().await.is_closed() {
                break;
            }
            tokio::time::sleep(DISCONNECT_POLL_INTERVAL).await;
        }
        let _ = tx
            .send(TunnelMsg::Disconnected {
                reason: "SSH 会话已断开".into(),
            })
            .await;
    });
}

/// 生产用的 russh 客户端 `Config`。单列成函数有两个理由：
///
/// 1. R43（第二轮评审发现）：`keepalive_interval`/`keepalive_max` 这两个
///    数字（10 秒、3 次）此前只以内联字面量的形式活在 `establish()` 里，
///    没有任何测试碰过它们——评审把 `Duration::from_secs(10)` 改成
///    `Duration::from_secs(1000)`、把 `keepalive_max: 3` 改成
///    `keepalive_max: 300`，`cargo test -p rmc-core` 122 个用例照样全绿。
///    单列成函数之后，`test_support` 里的快速单测能直接断言这个函数的
///    返回值，不需要重新构造一遍、也不需要真的建连接等 10 秒。
/// 2. `establish()`（生产路径）和 `establish_over()`（测试路径，见下）
///    共用同一份构造逻辑，不会出现"测试用的 Config 跟生产用的 Config
///    悄悄长歪"这种情况。
pub(crate) fn client_config() -> Arc<russh::client::Config> {
    Arc::new(russh::client::Config {
        keepalive_interval: Some(Duration::from_secs(10)),
        keepalive_max: 3,
        inactivity_timeout: None,
        ..Default::default()
    })
}

#[async_trait::async_trait]
impl TunnelFactory for SshTunnelFactory {
    async fn establish(
        &self,
        params: TunnelParams,
        tx: mpsc::Sender<TunnelMsg>,
    ) -> Result<Box<dyn TunnelHandle>> {
        // 拨号与 host key 比对读的是同一个 `params.gateway`——这一句
        // 里不存在第二个 Gateway 地址来源，也就没有「预检探的那台」与
        // 「实际连的那台」分叉的余地，见类型上的 R96 说明。Task 9：TLS
        // 核对的指纹同样从 `params.fingerprint` 来，不是另一份拷贝。
        let conn = self
            .transport
            .connect(&params.gateway, &params.fingerprint)
            .await?;
        establish_over(conn, params, tx).await
    }
}

/// 握手、host key 校验、认证、反向端口注册的核心逻辑，不关心 `conn`
/// 从哪来。
///
/// R40（第二轮评审发现）：这个 crate 唯一会跑 Rust 代码的 CI 工作流
/// （`.github/workflows/gateway.yml`）按 `paths: ["gateway/**", ...]`
/// 过滤，`crates/**` 下的改动根本不会触发它；这个仓库目前没有任何工作流
/// 会跑 `cargo test`。`tests/ssh_tunnel.rs` 那十条 `#[ignore]` 用例因此
/// 事实上从未被任何自动化跑过——评审把 `check_server_key` 里的错误
/// 传播路径改写成"吞掉 Err、诚实地返回 `Ok(false)`"这种编译器完全不会
/// 拦的写法之后，`cargo test -p rmc-core` 仍然 122/122 全绿，因为真正
/// 会撞上这条路径的测试全都在那十条从不运行的 `#[ignore]` 里。
///
/// 把 `establish()` 拆成"拨号"（`Transport::connect`，需要真实网络）和
/// `establish_over()`（握手往后的一切，只需要一条 `AsyncRead +
/// AsyncWrite` 的字节流）两段，就是为了让 `test_support` 能把
/// `tokio::io::duplex` 内存管道的一端喂给这里——`russh::server` 不是
/// 任何非默认 feature 挡着的模块，`tokio::io::duplex` 也不需要真实
/// socket、DNS、docker，于是能在进程内跑一个完整的假 Gateway，把这里
/// 会用到的每一段逻辑（包括 `handler.rs` 里 `check_server_key`/
/// `server_channel_open_forwarded_tcpip` 那两段安全关键代码）钉在
/// **任何一次** `cargo test -p rmc-core` 里，不需要等 docker、DNS、
/// `/etc/hosts` 都凑齐才能验证。docker 版的 `tests/ssh_tunnel.rs`
/// （连同 `tests/forwarding.rs`、`tests/common/`）在 Task 10 删掉了：
/// Task 9 把客户端 TLS 改成指纹钉扣之后，它描述的已经是旧的 CA/
/// known_hosts 世界，真跑起来会在握手那一步失败，留着只是"能编译但
/// 语义过期"，见 task-10-report.md。
///
/// R96：原来这里还单独收一个 `gateway: &HostPort` 参数，跟
/// `params.appliance` 并列着往 `ClientHandler`
/// 里塞。`TunnelParams` 现在自己带着 gateway（见
/// `tunnel::TunnelParams` 上的 R96 说明），那个参数就删掉了——留着它
/// 等于在函数签名上重新开一个"host key 对着哪台机器比"的独立入口，
/// 调用方可以传一个跟 `params.gateway` 不一样的值，而编译器不会说
/// 什么。整条链路（预检 → 拨号 → host key 比对）现在自始至终只读
/// 一个 `params.gateway`。
pub(crate) async fn establish_over(
    conn: Conn,
    params: TunnelParams,
    tx: mpsc::Sender<TunnelMsg>,
) -> Result<Box<dyn TunnelHandle>> {
    let config = client_config();

    let channels = pump::new_shared_channels();
    // Task 10：服务端回填的反向端口，握手/认证阶段恒为 0——
    // `ClientHandler::server_channel_open_forwarded_tcpip` 据此拒绝这
    // 个阶段送进来的任何 forwarded-tcpip 通道，见该方法上的说明。
    let registered_port = Arc::new(AtomicU16::new(0));
    let handler = handler::ClientHandler {
        fingerprint: params.fingerprint,
        appliance: params.appliance.clone(),
        registered_port: registered_port.clone(),
        tx: tx.clone(),
        next_session_id: Arc::new(AtomicU64::new(1)),
        channels: channels.clone(),
    };

    // R3（预扫描已发现）：不在这里 `.map_err(...)` 包一层。
    // `connect_stream` 返回 `Result<Handle<H>, H::Error>`，而
    // `H::Error = Error`（见 handler.rs 里 `type Error = Error`），
    // 这已经是我们自己的错误类型，不需要再映射一次。更重要的是：
    // 如果这里再包一层 map_err，`check_server_key` 返回的
    // `Error::HostKeyMismatch`（Fatal，不能自动重试）会被顺手裹成
    // `Error::SshTransport`（Network，无限退避重连）——把"连到一个
    // 冒充的 Gateway 应该立刻、永久地失败"变成"跟冒充者失联重试
    // 到天荒地老"。`tests::a_wrong_fingerprint_is_fatal_before_any_
    // password_is_sent`（本文件）钉住的就是这一条：谁把这行改回
    // `.map_err(...)`，那条测试的 `assert_eq!(err.class(), ErrorClass::
    // Fatal)` 立刻变红。
    let mut session = russh::client::connect_stream(config, conn, handler).await?;

    // R41（第二轮评审发现，纠正上一轮写错的说法）：口令交给
    // `authenticate_password(&String, &str)` 之后，russh 0.63.3 并不是
    // 撒手不管——`auth::Method::Password` 实现了 `Drop`，被丢弃时会对
    // `password` 调用 `zeroize()`（src/auth.rs），`Debug` 也把它印成
    // `<redacted>`；口令上线之后走的字节编码落在 `CryptoVec` 里，这个
    // 类型自己的 `Drop` 也会清零底层内存（russh-cryptovec）。上一轮说
    // "russh 不会做 zeroize"是我（Claude）凭印象写错的，没有真的去读
    // 0.63.3 的源码核实。
    //
    // 但这仍然是对**这一个版本**观察到的事实，不是 `authenticate_password`
    // 签名承诺的契约——上面这几处 `Drop`/`Debug` 实现完全可能在未来某个
    // russh 版本里说改就改，函数签名 `P: Into<String>` 不会变。真正不变
    // 的结构性事实只有一条：口令一旦交给 `P: Into<String>`，所有权就
    // 移交给了 russh 内部，我们这一侧的 `Zeroizing<String>` 从这一刻起
    // 保证不了对方怎么处理它——升级 russh 版本时，这一段需要重新对着
    // 新版本的源码核实一遍，不能想当然地继续引用 0.63.3 的这几行。
    let ok = session
        .authenticate_password(&params.username, params.password.as_str())
        .await?;
    if !ok.success() {
        return Err(Error::AuthRejected);
    }

    // 握手阶段 `check_server_key` 已经核对过指纹（不一致会让上面那个
    // `?` 直接短路返回 `Error::HostKeyMismatch`，走不到这一行）——这里
    // 发出的就是那个已经验证过的指纹，不是另一份拷贝。
    let _ = tx
        .send(TunnelMsg::Authenticated {
            fingerprint: params.fingerprint,
        })
        .await;

    // Task 10：申请端口 0，端口由运维服务器按账号分配，客户端不知道也
    // 不需要知道。`tcpip_forward` 返回值就是服务端回填的那个端口。
    let port = session
        .tcpip_forward("", 0)
        .await
        .map_err(map_tcpip_forward_error)?;
    let port = u16::try_from(port)
        .map_err(|_| Error::SshTransport(format!("运维服务器回填的端口不合法：{port}")))?;
    if port == 0 {
        return Err(Error::SshTransport("运维服务器没有回填反向端口".into()));
    }
    registered_port.store(port, Ordering::SeqCst);
    let _ = tx.send(TunnelMsg::ForwardRegistered { port }).await;

    let session = Arc::new(AsyncMutex::new(session));
    spawn_disconnect_watcher(session.clone(), tx);

    Ok(Box::new(SshTunnel {
        session,
        channels,
        disconnected: AtomicBool::new(false),
    }))
}

#[async_trait::async_trait]
impl TunnelHandle for SshTunnel {
    async fn close_remote_session(&self, id: u64) -> std::result::Result<(), UnknownSessionId> {
        // 锁是 std::sync::Mutex：这里只做一次哈希表移除，不跨越任何
        // `.await`，没有理由为了这一步引入 tokio::sync::Mutex 的异步开销
        // ——见 pump::SharedChannels 上关于插入/移除时机的说明。
        match self.channels.lock().unwrap().remove(&id) {
            Some(closer) => {
                closer.close();
                Ok(())
            }
            None => Err(UnknownSessionId(id)),
        }
    }

    async fn shutdown(self: Box<Self>) {
        disconnect_session(&self.session).await;
        // R76：disconnect 真的发完之后才置位，`Drop` 据此跳过兜底的
        // 那次 disconnect——见 `impl Drop for SshTunnel`。放在这一步
        // 之后（而不是函数开头）是故意的：`shutdown()` 的 future 如果
        // 跑到一半被取消，标志仍然是 false，`Drop` 会补上。
        self.disconnected.store(true, Ordering::SeqCst);
        // 主动断开之后 [`spawn_disconnect_watcher`] 会在下一次轮询里发现
        // `is_closed()` 已经为真、送出一条 `TunnelMsg::Disconnected`——这是
        // 无害的：`Supervisor` 收到这条命令触发的 `shutdown` 时早已经把
        // `ctx.handle` 置空、多数路径下 `ctx.creds` 也已经清空，迟到的
        // `Disconnected` 会在 `handle_msg` 里被 `ctx.creds.is_some()` 挡掉，
        // 不会触发一次多余的重连。
    }
}

/// R9：`tcpip_forward` 的失败必须按*原因*分类，不能把 russh 返回的一切
/// 错误都笼统地当成"端口占用"。
///
/// russh 的 `tcpip_forward` 只有两种失败形状（见其源码）：
/// - `Error::RequestDenied`：服务端明确回了 SSH_MSG_REQUEST_FAILURE——
///   这条全局请求真的被拒了，比如同账号已经有一条隧道在线（Task 10：
///   端口本身已经不是客户端能指定的了，"端口没在 PermitListen 里"这类
///   旧世界的成因跟着申请端口 0 一起消失，但"账号上一条隧道的监听尚未
///   回收"这条依然会让服务端拒绝这次注册）——这种情况退避重连没有
///   意义，等一小段固定时间再试才对，落 `ForwardPortBusy`（`PortBusy`
///   类，Task 10 起不再带端口号——客户端申请的是 0，从不知道具体端口）。
/// - 其他任何变体（`SendError`——请求都没发出去，会话早已经死了；
///   `Disconnect`——等回复的过程中连接断了）：这是链路层面的问题，跟
///   "端口是不是被占用"毫无关系，必须走退避重连（`Network` 类），不能
///   套用端口占用那套"固定 5 秒、最长 120 秒"的重试节奏——一次网络
///   抖动被误判成端口占用，最坏情况是重试 120 秒后放弃，比正常的
///   无限退避重连更差。
fn map_tcpip_forward_error(e: russh::Error) -> Error {
    match e {
        russh::Error::RequestDenied => Error::ForwardPortBusy,
        other => Error::SshTransport(format!("注册反向端口失败：{other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::ServerFingerprint;
    use crate::error::ErrorClass;

    // 这条不需要 docker 环境，任何 `cargo test -p rmc-core` 都会跑到——
    // 它直接摆事实：给这个函数喂 `SendError`/`Disconnect`，断言它们
    // 绝不会被判成 PortBusy。
    //
    // 会让这条测试变红的改法：把 `other => Error::SshTransport(...)`
    // 这个分支删掉，换成跟 `RequestDenied` 一样的 `ForwardPortBusy`
    // （也就是 brief 原文那种"一切失败都算端口占用"的写法）。
    #[test]
    fn request_denied_is_port_busy_but_disconnect_and_send_error_are_network() {
        let denied = map_tcpip_forward_error(russh::Error::RequestDenied);
        assert_eq!(denied.class(), ErrorClass::PortBusy);
        assert!(matches!(denied, Error::ForwardPortBusy));

        for e in [russh::Error::Disconnect, russh::Error::SendError] {
            let mapped = map_tcpip_forward_error(e);
            assert_eq!(
                mapped.class(),
                ErrorClass::Network,
                "会话中途断线不该被当成端口占用去做固定 5 秒/最长 120 秒重试"
            );
        }
    }

    // R43：快速、不碰网络的那一半证据——直接断言生产用的 `Config`
    // 字面量里的两个数字，不用真的等 10 秒。协议级别"这两个数字真的
    // 在起作用"的证据见 test_support 里
    // `keepalive_interval_matches_the_configured_ten_seconds`。
    #[test]
    fn client_config_keepalive_matches_the_operator_runbook_numbers() {
        let cfg = client_config();
        assert_eq!(cfg.keepalive_interval, Some(Duration::from_secs(10)));
        assert_eq!(cfg.keepalive_max, 3);
    }

    // --- Task 10：spawn_disconnect_watcher 的快速证据（不依赖 keepalive
    // 计时）——只证明"会话结束后，无论什么原因，watcher 最终都会送出一条
    // Disconnected 消息"这条接线本身是通的；keepalive 超时具体耗时多久的
    // 端到端测量在 supervisor.rs（需要真实经过状态机）。
    //
    // 会让这条测试变红的实现改法：删掉 `establish_over` 末尾对
    // `spawn_disconnect_watcher` 的调用（或者让它监视一个错误的
    // session）——`shutdown()` 之后再也不会有任何人往 `tx` 送
    // `TunnelMsg::Disconnected`，`next_msg` 会在 `with_timeout` 的 5 秒
    // 预算耗尽后 panic。

    use crate::ssh::test_support::{
        drain_authenticated_and_forward_registered, expect_err, expected_fingerprint, next_msg,
        spawn_gateway, test_params, test_params_with_fingerprint, with_timeout, GatewayConfig,
    };

    #[tokio::test]
    async fn session_close_is_reported_as_a_disconnected_message() {
        let (_reads, pending, conn, ..) = spawn_gateway(GatewayConfig::default());
        let (tx, mut rx) = mpsc::channel(32);
        let handle = with_timeout("establish_over", establish_over(conn, test_params(), tx))
            .await
            .unwrap();
        drain_authenticated_and_forward_registered(&mut rx).await;

        handle.shutdown().await;

        match with_timeout("等待 Disconnected 消息", next_msg(&mut rx)).await {
            TunnelMsg::Disconnected { .. } => {}
            other => panic!("会话结束后应该收到 Disconnected，实际 {other:?}"),
        }
        drop(pending);
    }

    // --- Task 10：host key 比对连接码指纹、申请端口 0 由服务端回填 ---

    /// 指纹对：认证通过、Authenticated 带指纹、ForwardRegistered 带的是
    /// 服务端回填的端口。
    ///
    /// 改红：`establish_over` 里把 `tcpip_forward("", 0)` 的返回值丢掉、
    /// `ForwardRegistered` 填 0——第三格红。
    ///
    /// R10-3（修复轮 1）：`auth_attempts == 1` 是这条测试正面的那一半
    /// ——跟 `a_wrong_fingerprint_is_fatal_before_any_password_is_sent`
    /// 里的 `== 0` 成对：只断言其中一边，一个恒定返回同一个数的计数器
    /// 也能让断言过关。
    #[tokio::test]
    async fn pinned_fingerprint_matches_and_the_port_comes_back_from_the_server() {
        let (_reads, _pending, conn, auth_attempts) = spawn_gateway(GatewayConfig {
            permitted_port: 22007,
            ..Default::default()
        });
        let (tx, mut rx) = mpsc::channel(32);
        let handle = with_timeout("establish_over", establish_over(conn, test_params(), tx))
            .await
            .unwrap();
        match next_msg(&mut rx).await {
            TunnelMsg::Authenticated { fingerprint } => {
                assert_eq!(fingerprint, expected_fingerprint())
            }
            other => panic!("{other:?}"),
        }
        match next_msg(&mut rx).await {
            TunnelMsg::ForwardRegistered { port } => assert_eq!(port, 22007),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            auth_attempts.load(Ordering::SeqCst),
            1,
            "指纹对的时候应该发生过一次口令认证"
        );
        handle.shutdown().await;
    }

    /// 指纹错：握手阶段就拒绝，Fatal，**不发 Authenticated**，口令根本
    /// 没送出去。
    ///
    /// 改红：`check_server_key` 里把 `!=` 改成 `==`——第一格红（而且上一
    /// 条也红）。
    ///
    /// R10-3（修复轮 1）：原来这里靠 `Sniff` 的读时间戳去侧面论证"服务端
    /// 没读到过 USERAUTH"，复审指出那条推理证明不了这件事本身（`Sniff`
    /// 只数字节到达的时间戳，KEX 本身就是多轮读取，没法从"读过字节"反推
    /// "读到的不是 USERAUTH"）。改成直接的证据：`GatewayHandler::auth_
    /// password` 每被调用一次自增一次的计数器，跟上一条测试的 `== 1`
    /// 成对，正反两面都要断言——否则一个恒为 0 的计数器也能让这条单独
    /// 的断言过关。
    #[tokio::test]
    async fn a_wrong_fingerprint_is_fatal_before_any_password_is_sent() {
        let (reads, _pending, conn, auth_attempts) = spawn_gateway(GatewayConfig::default());
        let (tx, mut rx) = mpsc::channel(32);
        let wrong = ServerFingerprint::of_ed25519_public(&[3u8; 32]);
        let err = expect_err(
            with_timeout(
                "establish_over",
                establish_over(conn, test_params_with_fingerprint(wrong), tx),
            )
            .await,
        );
        assert!(matches!(err, Error::HostKeyMismatch { .. }), "{err:?}");
        assert_eq!(err.class(), ErrorClass::Fatal);
        assert!(err.to_string().contains("连接码"), "{err}");
        assert!(rx.try_recv().is_err(), "不该有任何隧道消息");
        assert_eq!(
            auth_attempts.load(Ordering::SeqCst),
            0,
            "指纹不符时不该发生过任何一次口令认证尝试"
        );
        // `Sniff` 的读时间戳证明不了"服务端没读到过 USERAUTH"这件事
        // 本身（见上面的说明），留着只是记录服务端确实读到过 KEX 那几拍
        // 的字节，不是这条测试的核心证据。
        let _ = reads;
    }

    /// R10-1（修复轮 1，must-fix）：服务端把 tcpip-forward 回成"成功但
    /// 端口是 0"——russh `client/encrypted.rs:938-940` 会把"服务端回
    /// REQUEST_SUCCESS 但 payload 为空"解成 `Ok(0)`，这是协议上真会
    /// 出现的形状，不是臆造的边界。`registered_port` 停在 0 的后果是
    /// `server_channel_open_forwarded_tcpip` 会拒掉**每一条**通道——
    /// 界面显示"已连接"，实际一个字节都转不了，而且没有任何错误。
    ///
    /// 改红：把 `establish_over` 里 `if port == 0 { return Err(...) }`
    /// 整块删掉——**已实测**：`err` 不再是 `SshTransport`，`establish_
    /// over` 会返回 `Ok`，`with_timeout(...).await.unwrap()` 那一行由
    /// panic 变成正常返回，`expect_err` 反而会在 `Ok(_) => panic!(...)`
    /// 那一支炸掉（"期望建立隧道失败，实际却成功了"）。实测记录见
    /// task-10-fix-1-report.md。
    #[tokio::test]
    async fn a_server_that_fills_back_port_zero_is_a_transport_error() {
        let (_r, _p, conn, ..) = spawn_gateway(GatewayConfig {
            permitted_port: 0,
            ..Default::default()
        });
        let (tx, _rx) = mpsc::channel(32);
        let err = expect_err(
            with_timeout("establish_over", establish_over(conn, test_params(), tx)).await,
        );
        assert!(matches!(err, Error::SshTransport(_)), "{err:?}");
        assert!(err.to_string().contains("没有回填"), "{err}");
    }

    /// R10-1（修复轮 1，must-fix）：服务端回填的端口超出 `u16` 范围
    /// ——SSH 协议里 tcpip-forward 的端口字段是 wire 上的 `uint32`
    /// （russh 的 `Handle::tcpip_forward` 签名 `port: u32`、返回值也是
    /// `u32`），`GatewayConfig::permitted_port` 同样是 `u32`，能喂出一个
    /// 合法编码、但转不进 `u16` 的值，不用凑什么触发不了的场景。
    ///
    /// 改红：把 `establish_over` 里 `u16::try_from(port).map_err(...)?`
    /// 换成 `port as u16`（截断而不是拒绝）——**已实测**：`err` 变量
    /// 根本走不到 `Err` 分支（70000 截成 u16 是 4464，不是 0，也过不了
    /// 下面 `if port == 0` 那道守卫），`establish_over` 成功返回，跟上一
    /// 条测试同样的失败形状（`expect_err` 在 `Ok(_)` 那一支炸掉）。
    #[tokio::test]
    async fn a_server_that_fills_back_a_port_above_u16_range_is_a_transport_error() {
        let (_r, _p, conn, ..) = spawn_gateway(GatewayConfig {
            permitted_port: 70_000,
            ..Default::default()
        });
        let (tx, _rx) = mpsc::channel(32);
        let err = expect_err(
            with_timeout("establish_over", establish_over(conn, test_params(), tx)).await,
        );
        assert!(matches!(err, Error::SshTransport(_)), "{err:?}");
        assert!(err.to_string().contains("70000"), "{err}");
        assert!(err.to_string().contains("不合法"), "{err}");
    }

    /// 服务端拒绝转发（比如同账号已在线）→ PortBusy，不带端口号也说
    /// 得清。
    ///
    /// brief 没有给这条的「改红」，这里自己补：把
    /// `map_tcpip_forward_error` 里 `russh::Error::RequestDenied =>
    /// Error::ForwardPortBusy` 换成 `Error::SshTransport(...)`——**已实测**，
    /// `assert!(matches!(err, Error::ForwardPortBusy), ...)` 当场红
    /// （实际输出：`SshTransport("MUTATED")`）。
    #[tokio::test]
    async fn a_denied_forward_is_port_busy_class() {
        let (_r, _p, conn, ..) = spawn_gateway(GatewayConfig {
            accept_forward: false,
            ..Default::default()
        });
        let (tx, _rx) = mpsc::channel(32);
        let err = expect_err(
            with_timeout("establish_over", establish_over(conn, test_params(), tx)).await,
        );
        assert!(matches!(err, Error::ForwardPortBusy), "{err:?}");
        assert_eq!(err.class(), ErrorClass::PortBusy);
    }

    // R76（第四轮评审，纵深防御）：句柄被**直接丢弃**、完全没有调用
    // `shutdown()` 时，Gateway 侧的会话也必须被断开。
    //
    // 这是 `supervisor.rs` 里三次隧道泄漏（R71/R72/R75）共同的最后一
    // 环：主循环某一处把 `Box<dyn TunnelHandle>` 丢了，而 `SshTunnel`
    // 原来没有 `Drop`、`spawn_disconnect_watcher` 又攥着
    // `Arc<AsyncMutex<Handle>>` 让 `Handle` 连析构都不会发生，于是
    // 那条 SSH 会话和反向端口就在 Gateway 上一直活着。这条测试直接
    // 钉住"丢弃 == 断开"这条不变量，不经过状态机——状态机侧那些调用
    // 点该堵的照样堵（见 supervisor.rs），这里是最后一道网。
    //
    // 会让这条测试变红的实现改法：删掉 `impl Drop for SshTunnel`
    // ——`drop(handle)` 之后再也没有人会发出 disconnect，watcher 的
    // `is_closed()` 永远是 false，`next_msg` 会在 `with_timeout` 的
    // 5 秒预算耗尽后 panic（本地实测：删掉之后这条测试必定失败，
    // 其余测试无一变红）。
    #[tokio::test]
    async fn dropping_the_handle_without_shutdown_still_disconnects_the_session() {
        let (_reads, pending, conn, ..) = spawn_gateway(GatewayConfig::default());
        let (tx, mut rx) = mpsc::channel(32);
        let handle = with_timeout("establish_over", establish_over(conn, test_params(), tx))
            .await
            .unwrap();
        drain_authenticated_and_forward_registered(&mut rx).await;

        // 注意：不是 `handle.shutdown().await`，就是直接丢掉。
        drop(handle);

        match with_timeout("等待 Disconnected 消息", next_msg(&mut rx)).await {
            TunnelMsg::Disconnected { .. } => {}
            other => panic!("句柄被丢弃后也应该收到 Disconnected，实际 {other:?}"),
        }
        drop(pending);
    }
}
