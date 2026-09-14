//! russh 实现的隧道：握手、host key 校验、口令认证、反向端口注册。

pub mod handler;
pub mod pump;

#[cfg(test)]
pub(crate) mod test_support;

use crate::addr::HostPort;
use crate::error::{Error, Result};
use crate::knownhosts::KnownHosts;
use crate::platform::Conn;
use crate::transport::Transport;
use crate::tunnel::{TunnelFactory, TunnelHandle, TunnelMsg, TunnelParams, UnknownSessionId};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex as AsyncMutex};

pub struct SshTunnelFactory {
    transport: Arc<Transport>,
    known_hosts: Arc<KnownHosts>,
    gateway: HostPort,
}

impl SshTunnelFactory {
    pub fn new(transport: Arc<Transport>, known_hosts: Arc<KnownHosts>, gateway: HostPort) -> Self {
        Self {
            transport,
            known_hosts,
            gateway,
        }
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
        let conn = self.transport.connect(&self.gateway).await?;
        establish_over(conn, &self.gateway, &self.known_hosts, params, tx).await
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
/// `/etc/hosts` 都凑齐才能验证。docker 版的 `tests/ssh_tunnel.rs` 仍然
/// 保留——它验证的是"真实 Gateway/sshd 是否也这样表现"，跟这里验证的
/// "我们自己的代码是否这样表现"是两件事，互补不冲突。
pub(crate) async fn establish_over(
    conn: Conn,
    gateway: &HostPort,
    known_hosts: &Arc<KnownHosts>,
    params: TunnelParams,
    tx: mpsc::Sender<TunnelMsg>,
) -> Result<Box<dyn TunnelHandle>> {
    let config = client_config();

    let verdict = Arc::new(std::sync::Mutex::new(None));
    let channels = pump::new_shared_channels();
    let handler = handler::ClientHandler {
        gateway: gateway.clone(),
        known_hosts: known_hosts.clone(),
        appliance: params.appliance.clone(),
        reverse_port: params.reverse_port,
        tx: tx.clone(),
        next_session_id: Arc::new(AtomicU64::new(1)),
        verdict: verdict.clone(),
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
    // 到天荒地老"。`recorded_but_changed_host_key_is_fatal`
    // （tests/ssh_tunnel.rs，以及 test_support 里跑在进程内假 Gateway
    // 上的等价用例）钉住的就是这一条：谁把这行改回 `.map_err(...)`，
    // 这条测试的 `assert_eq!(err.class(), ErrorClass::Fatal)` 立刻变红。
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

    let (fp, first_seen) = verdict
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| Error::SshTransport("握手未产生 host key 校验结果".into()))?;
    let _ = tx
        .send(TunnelMsg::Authenticated {
            host_key_fp: fp,
            first_seen,
        })
        .await;

    session
        .tcpip_forward("127.0.0.1", params.reverse_port as u32)
        .await
        .map_err(|e| map_tcpip_forward_error(e, params.reverse_port))?;
    let _ = tx
        .send(TunnelMsg::ForwardRegistered {
            port: params.reverse_port,
        })
        .await;

    let session = Arc::new(AsyncMutex::new(session));
    spawn_disconnect_watcher(session.clone(), tx);

    Ok(Box::new(SshTunnel { session, channels }))
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
        let _ = self
            .session
            .lock()
            .await
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await;
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
///   这条全局请求真的被拒了，可能是端口没在这个账号的 `PermitListen`
///   里，也可能是端口已经被同账号另一条会话占着（sshd 试图 bind 撞上
///   EADDRINUSE，两种服务端拒绝在协议层是同一个消息，客户端天然
///   分辨不出"为什么"被拒，见 tests/ssh_tunnel.rs 里两条
///   `#[ignore]` 用例上的说明）——这种情况退避重连没有意义，等一小段
///   固定时间再试才对，落 `ForwardPortBusy`（`PortBusy` 类）。
/// - 其他任何变体（`SendError`——请求都没发出去，会话早已经死了；
///   `Disconnect`——等回复的过程中连接断了）：这是链路层面的问题，跟
///   "端口是不是被占用"毫无关系，必须走退避重连（`Network` 类），不能
///   套用端口占用那套"固定 5 秒、最长 120 秒"的重试节奏——一次网络
///   抖动被误判成端口占用，最坏情况是重试 120 秒后放弃，比正常的
///   无限退避重连更差。
fn map_tcpip_forward_error(e: russh::Error, port: u16) -> Error {
    match e {
        russh::Error::RequestDenied => Error::ForwardPortBusy(port),
        other => Error::SshTransport(format!("反向端口 {port} 注册失败：{other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorClass;

    // 这条不需要 docker 环境，任何 `cargo test -p rmc-core` 都会跑到——
    // 它是 R9 真正的证据来源：tests/ssh_tunnel.rs 里
    // `port_outside_permitlisten_is_port_busy_class` 和
    // `second_tunnel_on_the_same_port_is_port_busy` 两条都只能观察到
    // 服务端真的把请求拒了（两种成因在协议层不可分辨，见上面的文档
    // 注释），没法在集成测试里证明"网络抖动不会被误判成端口占用"这条
    // 反向命题；这里直接摆事实：给这个函数喂 `SendError`/`Disconnect`，
    // 断言它们绝不会被判成 PortBusy。
    //
    // 会让这条测试变红的改法：把 `other => Error::SshTransport(...)`
    // 这个分支删掉，换成跟 `RequestDenied` 一样的 `ForwardPortBusy`
    // （也就是 brief 原文那种"一切失败都算端口占用"的写法）。
    #[test]
    fn request_denied_is_port_busy_but_disconnect_and_send_error_are_network() {
        let denied = map_tcpip_forward_error(russh::Error::RequestDenied, 22001);
        assert_eq!(denied.class(), ErrorClass::PortBusy);
        assert!(matches!(denied, Error::ForwardPortBusy(22001)));

        for e in [russh::Error::Disconnect, russh::Error::SendError] {
            let mapped = map_tcpip_forward_error(e, 22001);
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
        drain_authenticated_and_forward_registered, next_msg, spawn_gateway, test_gateway_hostport,
        test_params, tmp_known_hosts, with_timeout, GatewayConfig,
    };

    #[tokio::test]
    async fn session_close_is_reported_as_a_disconnected_message() {
        let (_reads, pending, conn) = spawn_gateway(GatewayConfig::default());
        let known_hosts = Arc::new(tmp_known_hosts());
        let (tx, mut rx) = mpsc::channel(32);
        let handle = with_timeout(
            "establish_over",
            establish_over(
                conn,
                &test_gateway_hostport(),
                &known_hosts,
                test_params(22001),
                tx,
            ),
        )
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
}
