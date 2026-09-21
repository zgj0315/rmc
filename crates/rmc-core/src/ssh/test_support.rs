//! 进程内的最小 SSH 服务端，只给本 crate 自己的测试用（`#[cfg(test)]`，
//! 不进生产构建）。
//!
//! R40（第二轮评审发现）：`.github/workflows/gateway.yml` 按
//! `paths: ["gateway/**", ...]` 过滤，`crates/**` 下的改动不会触发任何
//! 工作流；这个仓库目前没有任何 CI 会跑 `cargo build`/`cargo test`。
//! `tests/ssh_tunnel.rs` 那十条 `#[ignore]` 用例因此从未被自动化跑过，
//! 评审用一处编译器完全不会拦的改动（把 `check_server_key` 里的
//! `self.known_hosts.check(...)?` 改成 `Err(_) => Ok(false)`）证明了这
//! 件事的代价：`cargo test -p rmc-core` 122/122 照样绿，而这个改动会让
//! 一次 host key 不匹配从"立刻永久失败"变成"当成网络抖动无限重连"。
//!
//! `russh::server` 不在任何非默认 feature 后面（见 lib_inner.rs
//! `#[cfg(not(target_arch = "wasm32"))] pub mod server;`），
//! `tokio::io::duplex` 是标准库之外零依赖的内存双工管道——两者拼起来，
//! 不需要 docker、DNS、`/etc/hosts`、真实 TCP，就能在一次
//! `#[tokio::test]` 里跑一个完整的假 Gateway，把 `handler.rs`/`mod.rs`
//! 里真正的生产代码路径（`crate::ssh::establish_over`，`establish()`
//! 拨号之后的那一半）钉在每一次 `cargo test` 里。
//!
//! # 第一版死锁及其修复（教训记在这里，别再踩一遍）
//!
//! 第一版 `spawn_gateway` 在把 `client_side` 交还给调用方之前，自己先
//! `.await` 了 `russh::server::run_stream(...)`。`run_stream` 内部要先
//! 读到客户端发来的 SSH 版本行才会返回——但客户端要等 `spawn_gateway`
//! 把 `client_side` 交回去、调用方拿它去驱动 `establish_over(...)`
//! 之后，才有机会发出第一个字节。两边互相等对方先动手：`spawn_gateway`
//! 卡在"读客户端的第一个字节"，调用方卡在"等 `spawn_gateway` 返回"，
//! 9 个测试全部挂起，`cargo test` 跑了三分四十秒都没有任何一条完成
//! （正常应该是毫秒级）。
//!
//! 修复方式：`run_stream(...).await` 整个丢进独立的 `tokio::spawn`
//! 任务里，`spawn_gateway` 自己不等它——立刻带着 `client_side` 和一个
//! "服务端 handle 还没准备好，但可以晚点再等"的 `PendingHandle` 返回。
//! 调用方必须先用 `client_side` 驱动过 `establish_over(...)`（这才是
//! 真正促使服务端读到字节、`run_stream` 得以返回的动作），再调用
//! `PendingHandle::get()`——这时候服务端那边早就该已经跑过握手了。
//!
//! 另外两处配合的修复：
//! - `keepalive_interval_matches_the_configured_ten_seconds`
//!   原来直接 `tokio::time::sleep(Duration::from_secs(12))` 等真实
//!   时钟，实测会把测试拖到 12 秒往上，跟"这个 harness 应该是毫秒级"
//!   的预期矛盾。改用 `#[tokio::test(start_paused = true)]` +
//!   照常调用 `tokio::time::sleep`——时钟暂停之后，`sleep` 会在"没有
//!   别的活干"时自动把虚拟时钟推进到下一个定时器（这里就是 russh 内部
//!   的 keepalive 定时器），协议往返仍然按真实的 poll 顺序发生，只是
//!   不需要真的等 10 秒挂钟时间。`Sniff`/`ReadTimestamps` 因此改用
//!   `tokio::time::Instant`（会跟着虚拟时钟走）而不是
//!   `std::time::Instant`（只认真实挂钟时间，暂停时钟对它没有意义）。
//! - 每个测试用例的关键 `.await` 都套一层 [`with_timeout`]，预算控制在
//!   个位数秒——这个项目已经被"失败路径报不出错、只会一直挂着"坑过不止
//!   一次（最近一次是一条测试卡在读一个没人写的管道上），这里不能重蹈
//!   覆辙：往后这个 harness 自己的实现再引入类似的死锁，得到的应该是
//!   一条秒级失败、说清楚在等什么的用例，不是又一次挂起。

use crate::addr::HostPort;
use crate::code::ServerFingerprint;
use crate::error::Error;
use crate::knownhosts::{fingerprint_of, Fingerprint};
use crate::platform::Io;
use crate::ssh::{client_config, establish_over};
use crate::tunnel::{TunnelHandle, TunnelMsg, TunnelParams};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use zeroize::Zeroizing;

pub(crate) const TEST_USER: &str = "tunnel-zhang";
pub(crate) const TEST_PASSWORD: &str = "tunnel-init-pw";

/// 单个用例里任何一步的超时预算。个位数秒——真出问题应该几毫秒就报，
/// 给够余量应付偶尔的调度抖动，不给到"看起来像卡住了"的地步。
const STEP_BUDGET: Duration = Duration::from_secs(5);

/// 给一个 future 套上 [`STEP_BUDGET`] 超时：超时即 panic，把"在等什么"
/// 写进失败信息里，而不是让测试无限期挂起——这正是这个模块第一版踩过
/// 的坑，见模块顶部"第一版死锁及其修复"。
pub(crate) async fn with_timeout<F: Future>(what: &str, fut: F) -> F::Output {
    tokio::time::timeout(STEP_BUDGET, fut)
        .await
        .unwrap_or_else(|_| panic!("等待「{what}」超过 {STEP_BUDGET:?} 仍未完成，判定为死锁"))
}

/// 固定的测试专用 Ed25519 私钥（OpenSSH PEM），本地用
/// `ssh-keygen -t ed25519` 生成，只用来跑进程内假 Gateway，不是任何
/// 真实环境的凭据。固定下来而不是每次随机生成，是为了让期望指纹
/// （[`expected_fingerprint`]/[`expected_openssh_fingerprint`]）可以是
/// 编译期就能算出来的常量，不需要在每个测试里现算一遍再传来传去。
///
/// **控制者补充第 1 条**：这把私钥确实是 ed25519（base64 里看得到
/// `ssh-ed25519`），所以 `check_server_key` 里 `key_data().ed25519()`
/// 这一支在测试里走得到；「不是 ed25519」那一支目前找不到别的办法验证
/// ——本 crate 没有现成的非 ed25519（比如 RSA/ECDSA）host key 测试
/// 夹具，见 `ssh::mod::tests` 顶部关于这件事的说明。
const TEST_HOST_KEY_OPENSSH_PEM: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC04AS5X0Rwa1fyke2kxrkaK18ceNvUghxXexXQGWLROAAAAJhld9/5ZXff
+QAAAAtzc2gtZWQyNTUxOQAAACC04AS5X0Rwa1fyke2kxrkaK18ceNvUghxXexXQGWLROA
AAAEC3/GQ1q1k4J9LUH5hLFt5cBFlebKKBbu6PRTHR9F/Ts7TgBLlfRHBrV/KR7aTGuRor
Xxx429SCHFd7FdAZYtE4AAAAFXJtYy1jb3JlLXRlc3QtaGFybmVzcw==
-----END OPENSSH PRIVATE KEY-----
";

pub(crate) fn test_host_key() -> russh::keys::PrivateKey {
    russh::keys::PrivateKey::from_openssh(TEST_HOST_KEY_OPENSSH_PEM)
        .expect("固定的测试专用私钥必须能解析——这不是可以运行时失败的东西")
}

pub(crate) fn test_gateway_hostport() -> HostPort {
    "in-process-gateway.test:22".parse().unwrap()
}

/// `test_host_key()` 对应的、本任务真正核对的那个指纹——`ServerFingerprint`
/// 对裸 32 字节 ed25519 公钥做哈希，跟 `ClientHandler::check_server_key`
/// 走的是同一条算法。**不要跟 [`expected_openssh_fingerprint`] 混用**：
/// 两者不是一回事，见 `knownhosts.rs` 模块文档。
pub(crate) fn expected_fingerprint() -> ServerFingerprint {
    let key = test_host_key();
    let pk = key.public_key();
    let ed = pk
        .key_data()
        .ed25519()
        .expect("固定的测试专用私钥必须是 ed25519");
    ServerFingerprint::of_ed25519_public(&ed.0)
}

/// `test_host_key()` 对应的 OpenSSH 风格指纹（`SHA256:...`，对整个公钥
/// blob 做哈希）——`preflight.rs` 探测一体机 host key 那一步用的是这个
/// 算法（给人看的展示指纹，不是我们钉死比对的那个），见
/// `knownhosts.rs` 模块文档「两套指纹算法不是一回事」。
pub(crate) fn expected_openssh_fingerprint() -> Fingerprint {
    use russh::keys::PublicKeyBase64;
    fingerprint_of(&test_host_key().public_key().public_key_bytes())
}

pub(crate) fn test_params() -> TunnelParams {
    test_params_with_password(TEST_PASSWORD)
}

pub(crate) fn test_params_with_password(password: &str) -> TunnelParams {
    TunnelParams {
        username: TEST_USER.into(),
        password: Zeroizing::new(password.to_string()),
        gateway: test_gateway_hostport(),
        appliance: "192.168.100.10:61001".parse().unwrap(),
        fingerprint: expected_fingerprint(),
    }
}

/// 指纹错的夹具：跟 [`test_params`] 相同，只是 `fingerprint` 换成一个
/// 保证跟 `test_host_key()` 不一致的值。
pub(crate) fn test_params_with_fingerprint(fingerprint: ServerFingerprint) -> TunnelParams {
    TunnelParams {
        fingerprint,
        ..test_params()
    }
}

pub(crate) async fn drain_authenticated_and_forward_registered(rx: &mut mpsc::Receiver<TunnelMsg>) {
    for _ in 0..2 {
        let _ = next_msg(rx).await;
    }
}

pub(crate) async fn next_msg(rx: &mut mpsc::Receiver<TunnelMsg>) -> TunnelMsg {
    with_timeout("等隧道消息", rx.recv())
        .await
        .expect("隧道消息通道已关闭")
}

/// `Box<dyn TunnelHandle>` 没有 `Debug`，`unwrap_err()` 编译不过，
/// 跟 tests/transport.rs、tests/ssh_tunnel.rs 里的 `expect_err` 是
/// 同一个理由。
pub(crate) fn expect_err(r: crate::error::Result<Box<dyn TunnelHandle>>) -> Error {
    match r {
        Ok(_) => panic!("期望建立隧道失败，实际却成功了"),
        Err(e) => e,
    }
}

/// 每次读到非空数据就记一个时间戳。keepalive 请求（`"keepalive@openssh.com"`
/// 全局请求）在 russh 服务端这一侧走的是"未命名具名请求"的兜底分支
/// （见 russh 0.63.3 `src/server/encrypted.rs` 里 `GLOBAL_REQUEST` 的
/// `match req_type.as_str()`，`"tcpip-forward"`/`"cancel-tcpip-forward"`/
/// `"streamlocal-forward@openssh.com"`/`"cancel-streamlocal-forward@openssh.com"`
/// 四个具名分支之外一律直接回 REQUEST_FAILURE，不经过 `Handler` 的任何
/// 回调），`server::Handler` trait 上没有任何钩子能观察到它。要证明
/// "客户端确实按配置的间隔发送 keepalive"，只能不解密协议、单纯数
/// "多久来一批字节"——这正是这个包装器存在的原因。
///
/// 时间戳用 `tokio::time::Instant` 而不是 `std::time::Instant`：前者在
/// `#[tokio::test(start_paused = true)]` 之下会跟着虚拟时钟走，后者只
/// 认真实挂钟时间，暂停时钟对它没有意义——`keepalive_interval_matches_
/// the_configured_ten_seconds` 需要的正是"虚拟时间上过了几秒"，不是
/// "真实等了几秒"。
#[derive(Clone, Default)]
pub(crate) struct ReadTimestamps(Arc<Mutex<Vec<Instant>>>);

impl ReadTimestamps {
    pub(crate) fn snapshot(&self) -> Vec<Instant> {
        self.0.lock().unwrap().clone()
    }
}

pub(crate) struct Sniff<S> {
    inner: S,
    reads: ReadTimestamps,
}

impl<S> Sniff<S> {
    fn new(inner: S) -> (Self, ReadTimestamps) {
        let reads = ReadTimestamps::default();
        (
            Self {
                inner,
                reads: reads.clone(),
            },
            reads,
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Sniff<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            if buf.filled().len() > before {
                this.reads.0.lock().unwrap().push(Instant::now());
            }
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Sniff<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// 进程内假 Gateway 的 `server::Handler`：只实现测试需要的两个回调，
/// 其余用 trait 的默认实现（默认拒绝一切）。
struct GatewayHandler {
    /// 客户端申请端口 0 时回填的端口——Task 10 起，生产客户端
    /// (`ssh::establish_over`) 永远申请 0，服务端决定实际端口。
    permitted_port: u32,
    accept_password: bool,
    /// 模拟"服务端拒绝这次反向端口注册"（比如同账号已有一条隧道在线）
    /// ——`false` 时 `tcpip_forward` 恒返回 `Ok(false)`，客户端会收到
    /// `russh::Error::RequestDenied`，映射成 `Error::ForwardPortBusy`。
    accept_forward: bool,
    /// R10-3（修复轮 1）：`auth_password` 每被调用一次就
    /// `fetch_add(1)`——独立于 `Sniff` 的读时间戳之外，直接钉住"口令有
    /// 没有被发出去"这件事本身，不依赖"没有任何观测手段能看穿协议"这条
    /// 迂回推理。`spawn_gateway` 把这个计数器原样返出去，调用方能在两个
    /// 方向上核对：指纹对时确实发生过一次认证尝试，指纹错时一次都没有。
    auth_attempts: Arc<AtomicUsize>,
}

impl russh::server::Handler for GatewayHandler {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        self.auth_attempts.fetch_add(1, Ordering::SeqCst);
        if self.accept_password && user == TEST_USER && password == TEST_PASSWORD {
            Ok(russh::server::Auth::Accept)
        } else {
            Ok(russh::server::Auth::reject())
        }
    }

    /// Task 10：客户端永远申请端口 0（见 `ssh::establish_over`），服务端
    /// 按账号回填实际端口——这里用 `permitted_port` 模拟"这个账号分配
    /// 到的端口"。`accept_forward = false` 模拟服务端拒绝这次注册（比如
    /// 同账号已有一条隧道在线，对应真实环境里的 `Error::ForwardPortBusy`）。
    ///
    /// 非 0 请求那一支保留是为了这个假 Gateway 本身仍然是一个协议层面
    /// 合理的实现（不会在收到非 0 请求时无条件放行任意端口），生产客户端
    /// 不会走到这一支。
    async fn tcpip_forward(
        &mut self,
        _address: &str,
        port: &mut u32,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        if !self.accept_forward {
            return Ok(false);
        }
        if *port == 0 {
            *port = self.permitted_port;
            return Ok(true);
        }
        Ok(*port == self.permitted_port)
    }
}

pub(crate) struct GatewayConfig {
    pub permitted_port: u32,
    pub accept_password: bool,
    pub accept_forward: bool,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            permitted_port: 22001,
            accept_password: true,
            accept_forward: true,
        }
    }
}

/// 服务端的会话句柄还没准备好，但已经知道迟早会有——见模块顶部
/// "第一版死锁及其修复"。**只能在调用方已经用 `spawn_gateway` 返回的
/// `Box<dyn Io>` 驱动过一轮真实的字节交换之后才能 `.await` 这个类型**
/// （也就是先跑 `establish_over(...)` 或至少
/// `russh::client::connect_stream(...)`），否则会跟 `run_stream`
/// 内部"先读到客户端的 SSH 版本行才返回"这一步互相等待，重新踩回
/// 同一个死锁——`get()` 内部套了 [`STEP_BUDGET`] 超时，误用会在几秒内
/// panic 报出来，不会再无限期挂起。
pub(crate) struct PendingHandle(oneshot::Receiver<russh::server::Handle>);

impl PendingHandle {
    pub(crate) async fn get(self) -> russh::server::Handle {
        with_timeout("拿服务端 handle（run_stream 完成握手起步）", self.0)
            .await
            .expect("进程内假 Gateway 从没能返回一个 handle——run_stream 大概率失败了")
    }
}

/// Task 10 新增：让底层连接可以在测试需要的时刻被"冻结"——冻结后
/// `poll_read`/`poll_write` 恒定返回 `Poll::Pending`，不注册、也不触发
/// 任何 waker。这不是协议层面的优雅断开（不会产生 EOF、不会发
/// SSH_MSG_DISCONNECT），而是模拟一个已经不再应答、但连接本身尚未被
/// 判定关闭的黑洞对端——真实世界里的网络分区、防火墙静默丢包都是这种
/// 表现：客户端能写（写进内核缓冲区不会立刻报错），只是永远收不到
/// 任何回应。这正是方案设计.md §3.4 要求实测的场景："让链路真的安静
/// 下来（例如服务端不再应答）"，不是"服务端主动挂断"。
///
/// 用于 `supervisor.rs` 里端到端测量 keepalive 断线判定耗时的测试：先用
/// `spawn_freezable_gateway` 建立一条真实握手成功的隧道，再在合适的时机
/// 调用 `FreezeSwitch::freeze()`，掐表量从冻结时刻到状态机进入
/// `State::Backoff` 实际用了多久。
#[derive(Clone, Default)]
pub(crate) struct FreezeSwitch(Arc<AtomicBool>);

impl FreezeSwitch {
    pub(crate) fn freeze(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn is_frozen(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

pub(crate) struct Freezable<S> {
    inner: S,
    switch: FreezeSwitch,
}

impl<S> Freezable<S> {
    fn new(inner: S) -> (Self, FreezeSwitch) {
        let switch = FreezeSwitch::default();
        (
            Self {
                inner,
                switch: switch.clone(),
            },
            switch,
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Freezable<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.switch.is_frozen() {
            return Poll::Pending;
        }
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Freezable<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.switch.is_frozen() {
            return Poll::Pending;
        }
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.switch.is_frozen() {
            return Poll::Pending;
        }
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.switch.is_frozen() {
            return Poll::Pending;
        }
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// 与 [`spawn_gateway`] 相同的接线方式，只是服务端一侧的连接额外裹了一层
/// [`Freezable`]：调用方可以在任意时刻冻结它，模拟"服务端不再应答"。
pub(crate) fn spawn_freezable_gateway(
    cfg: GatewayConfig,
) -> (ReadTimestamps, FreezeSwitch, PendingHandle, Box<dyn Io>) {
    let key = test_host_key();
    let server_config = Arc::new(russh::server::Config {
        keys: vec![key],
        ..Default::default()
    });

    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let (frozen_server_side, switch) = Freezable::new(server_side);
    let (sniffed_server_side, server_reads) = Sniff::new(frozen_server_side);
    let handler = GatewayHandler {
        permitted_port: cfg.permitted_port,
        accept_password: cfg.accept_password,
        accept_forward: cfg.accept_forward,
        auth_attempts: Arc::new(AtomicUsize::new(0)),
    };

    let (handle_tx, handle_rx) = oneshot::channel();
    tokio::spawn(async move {
        // `Err(_)` 时 `handle_tx` 直接被丢弃；调用方 `PendingHandle::get()`
        // 会在 `RecvError` 处得到一个说得清楚的 panic，而不是挂起。
        if let Ok(running) =
            russh::server::run_stream(server_config, sniffed_server_side, handler).await
        {
            let handle = running.handle();
            let _ = handle_tx.send(handle);
            let _ = running.await;
        }
    });

    (
        server_reads,
        switch,
        PendingHandle(handle_rx),
        Box::new(client_side),
    )
}

/// 起一个跑在内存管道上的假 Gateway。返回：服务端读到的字节时间戳、
/// 一个"稍后才能要"的服务端句柄、以及客户端要用的连接
/// （`establish_over` 的 `conn` 参数）。
///
/// 不在这个函数内部等 `run_stream` 完成——它要先读到客户端的第一个
/// 字节才会返回，而客户端要等这个函数把 `Box<dyn Io>` 交回去之后才有
/// 机会发送任何东西。把 `run_stream(...).await` 丢进独立任务，函数
/// 立刻带着连接返回，`PendingHandle` 留给调用方在真正驱动过客户端
/// 之后再兑现。
/// `Arc<AtomicUsize>` 的最后一个返回值：R10-3（修复轮 1）新增，`auth_
/// password` 每被调用一次自增一次——独立于 `Sniff` 的读时间戳，直接
/// 钉住"口令有没有被发出去"，见 `GatewayHandler::auth_attempts` 上的
/// 说明。绝大多数既有调用点不关心这个值，用 `..` 忽略它即可。
pub(crate) fn spawn_gateway(
    cfg: GatewayConfig,
) -> (ReadTimestamps, PendingHandle, Box<dyn Io>, Arc<AtomicUsize>) {
    let key = test_host_key();
    let server_config = Arc::new(russh::server::Config {
        keys: vec![key],
        ..Default::default()
    });

    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let (sniffed_server_side, server_reads) = Sniff::new(server_side);
    let auth_attempts = Arc::new(AtomicUsize::new(0));
    let handler = GatewayHandler {
        permitted_port: cfg.permitted_port,
        accept_password: cfg.accept_password,
        accept_forward: cfg.accept_forward,
        auth_attempts: auth_attempts.clone(),
    };

    let (handle_tx, handle_rx) = oneshot::channel();
    tokio::spawn(async move {
        match russh::server::run_stream(server_config, sniffed_server_side, handler).await {
            Ok(running) => {
                let handle = running.handle();
                let _ = handle_tx.send(handle);
                // 让后台任务的生命周期跟会话本身对齐，而不是送出 handle
                // 就立刻退出——纯粹是为了这个任务在 `cargo test`
                // 输出里表现得更直观，不是正确性所必需（`JoinHandle`
                // 被丢弃不会取消 `tokio::spawn` 出去的任务）。
                let _ = running.await;
            }
            Err(_) => {
                // handle_tx 被 drop；调用方 `PendingHandle::get()` 会在
                // `RecvError` 处得到一个说得清楚的 panic，而不是挂起。
            }
        }
    });

    (
        server_reads,
        PendingHandle(handle_rx),
        Box::new(client_side),
        auth_attempts,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorClass;
    use crate::tunnel::TunnelMsg;

    // --- Task 10：host key 首次记录/变更拒绝那两条测试（FirstSeen →
    // Matched）已经跟着 `KnownHosts` 一起删掉——SSH host key 校验换成了
    // 核对连接码里的指纹，没有本地状态、也没有"首次连接自动信任"这一说。
    // 等价的正/反两面证据现在在 `ssh::mod::tests`：
    // `pinned_fingerprint_matches_and_the_port_comes_back_from_the_server`
    // （指纹对）与 `a_wrong_fingerprint_is_fatal_before_any_password_is_sent`
    // （指纹错，Fatal）。

    // --- 专门写给 `Ok(false)` 这条路径的负面测试（R40 点名要求）---

    #[tokio::test]
    async fn check_server_key_returning_ok_false_is_not_fatal() {
        // 不是 `ssh::handler::ClientHandler`——这个 handler 只用来演示
        // "如果 check_server_key 老老实实返回 Ok(false)（不传播具体错误），
        // russh 与本 crate 现有的错误映射会把它变成什么"，跟真实实现
        // 是否会走到这里无关（真实实现从不返回 Ok(false)，见 handler.rs）。
        struct AlwaysRejectHostKey;

        impl russh::client::Handler for AlwaysRejectHostKey {
            type Error = Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &russh::keys::PublicKeyOrCertificate,
            ) -> Result<bool, Self::Error> {
                Ok(false)
            }
        }

        let (_reads, pending, conn, ..) = spawn_gateway(GatewayConfig::default());
        let result = with_timeout(
            "connect_stream（预期因 check_server_key 返回 Ok(false) 而失败）",
            russh::client::connect_stream(client_config(), conn, AlwaysRejectHostKey),
        )
        .await;
        let err = match result {
            Ok(_) => panic!("check_server_key 返回 Ok(false) 时握手不应该成功"),
            Err(e) => e,
        };
        // 刻意断言"不是 Fatal"，而不是断言它应该是什么——这条测试记录的
        // 是一个真实存在、值得被看见的危险：russh 把 Ok(false) 转成
        // `crate::Error::UnknownKey`，本 crate 笼统的
        // `From<russh::Error>`（error.rs）把它落到 SshTransport/Network，
        // 不是 Fatal。这正是 R40 描述的那次变异改出来的效果——`?` 传播被
        // 换成"诚实地返回 false"之后，看起来像是没有偷懒，实际后果是
        // 一次伪造的 host key 会被当成网络抖动无限重连。
        assert_ne!(
            err.class(),
            ErrorClass::Fatal,
            "这条断言本身就是在演示危险：{err:?} 不是 Fatal"
        );
        drop(pending);
    }

    // --- 口令错误 → AuthRejected / Auth ---

    #[tokio::test]
    async fn wrong_password_is_auth_rejected() {
        let (_reads, pending, conn, ..) = spawn_gateway(GatewayConfig::default());
        let (tx, _rx) = mpsc::channel(32);
        let err = expect_err(
            with_timeout(
                "establish_over",
                establish_over(conn, test_params_with_password("definitely-wrong"), tx),
            )
            .await,
        );
        assert!(matches!(err, Error::AuthRejected), "实际 {err:?}");
        assert_eq!(err.class(), ErrorClass::Auth);
        drop(pending);
    }

    // --- tcpip_forward 被拒 → ForwardPortBusy：等价证据在
    // `ssh::mod::tests::a_denied_forward_is_port_busy_class`（用
    // `GatewayConfig { accept_forward: false, .. }` 模拟服务端拒绝）。

    // --- keepalive 间隔：数服务端收到字节的时间戳，不解密协议
    // （R43，评审明确要求"protocol 级别数 keepalive 请求"，跟
    // ssh::tests::client_config_keepalive_matches_the_operator_runbook_numbers
    // 那条快速的直接断言互补：那条钉的是"字面量没被改错"，这条钉的是
    // "这个字面量真的在协议里起作用"）。
    //
    // `start_paused = true`：时钟暂停之后，`tokio::time::sleep` 会在
    // "没有别的活干"时自动把虚拟时钟推进到下一个到期的定时器（这里是
    // 客户端内部的 keepalive 定时器），协议往返仍按真实的 poll 顺序
    // 发生，只是不用真的等 10 秒挂钟时间——整条用例应该在几毫秒的
    // 真实时间内跑完。见模块顶部"第一版死锁及其修复"。

    #[tokio::test(start_paused = true)]
    async fn keepalive_interval_matches_the_configured_ten_seconds() {
        let (reads, pending, conn, ..) = spawn_gateway(GatewayConfig::default());
        let (tx, mut rx) = mpsc::channel(32);
        let handle = with_timeout("establish_over", establish_over(conn, test_params(), tx))
            .await
            .unwrap();
        drain_authenticated_and_forward_registered(&mut rx).await;
        let _server_handle = pending.get().await;

        // t0 不取"我这个测试任务此刻的 Instant::now()"：`establish_over`
        // 返回、两条 TunnelMsg 也收完了，不代表服务端那个独立
        // `tokio::spawn` 出来的任务已经把 tcpip-forward 应答之后的最后
        // 几个字节读完——这是两个任务之间的调度竞争，不是时间上的先后。
        // 第一次跑这条测试时就在这里踩到过：`elapsed` 量出来是 `0ns`，
        // 因为 t0 卡在了握手收尾的字节被服务端实际读到之前。稳妥的锚点
        // 是"已经记录到的最后一次读取"本身，而不是"我此刻检查的时刻"。
        let t0 = reads
            .snapshot()
            .into_iter()
            .max()
            .expect("握手/认证/反向端口注册期间服务端应该至少读到过字节");
        // 握手/认证/反向端口注册的流量都发生在 t0 之前，t0 之后如果
        // 客户端保持空闲，唯一还会主动发东西的理由就是 keepalive
        // 定时器——时钟暂停之下，这一步会自动快进到那个定时器到期的
        // 那一刻，不需要真的等待。
        //
        // 这里不能用 [`with_timeout`]：它的 5 秒预算是按真实时间设计的
        // 兜底，但在 `start_paused = true` 之下 `tokio::time::timeout`
        // 同样活在虚拟时钟里——套一个 5 秒的虚拟超时去等一个 12 秒的
        // 虚拟 sleep，超时会先触发（这是本文件第一次改这条测试时踩到的
        // 现成教训）。虚拟时间不花真实挂钟时间，这里的超时预算可以给得
        // 比真正要等的 12 秒宽裕得多，不需要跟 [`STEP_BUDGET`] 共用同一个
        // 数字。
        tokio::time::timeout(
            Duration::from_secs(30),
            tokio::time::sleep(Duration::from_secs(12)),
        )
        .await
        .expect("虚拟时钟 12 秒内应该能推进完——这一步不该超时");

        let first_after_t0 = reads.snapshot().into_iter().filter(|t| *t > t0).min();
        let first_after_t0 = first_after_t0.expect(
            "12 秒（虚拟时间）内应该收到至少一次 keepalive；如果这里是空的，\
             说明 keepalive_interval 被改大了（例如误改成 1000 秒）",
        );
        let elapsed = first_after_t0.duration_since(t0);
        assert!(
            elapsed >= Duration::from_secs(5),
            "第一次 keepalive 到达得太早（{elapsed:?}，期望接近 10 秒），\
             像是 keepalive_interval 被改小了"
        );

        handle.shutdown().await;
    }

    // --- 7/8. reply.accept()/reply.reject() 在协议层面的证据（评审
    // 明确指出这比"连原始 TCP、看读超时还是读到 EOF"更直接、也不依赖
    // `Channel` 的 drop 语义）---

    #[tokio::test]
    async fn forwarded_channel_open_is_confirmed_when_port_matches() {
        let (_reads, pending, conn, ..) = spawn_gateway(GatewayConfig::default());
        let (tx, mut rx) = mpsc::channel(32);
        let handle = with_timeout("establish_over", establish_over(conn, test_params(), tx))
            .await
            .unwrap();
        drain_authenticated_and_forward_registered(&mut rx).await;
        let server_handle = pending.get().await;

        // 服务端主动发起一个 forwarded-tcpip 通道，端口跟客户端注册的
        // 一致——模拟"有人真的连上了反向端口"。
        let channel = with_timeout(
            "channel_open_forwarded_tcpip（端口匹配）",
            server_handle.channel_open_forwarded_tcpip("127.0.0.1", 22001, "203.0.113.5", 54321),
        )
        .await;
        assert!(
            channel.is_ok(),
            "端口匹配时应该收到 CHANNEL_OPEN_CONFIRMATION，实际 {channel:?}——\
             如果 handler.rs 把 reply 命名成 _reply 直接丢弃，这里会变成 \
             CHANNEL_OPEN_FAILURE"
        );

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn forwarded_channel_open_is_rejected_when_port_does_not_match() {
        let (_reads, pending, conn, ..) = spawn_gateway(GatewayConfig::default());
        let (tx, mut rx) = mpsc::channel(32);
        let handle = with_timeout("establish_over", establish_over(conn, test_params(), tx))
            .await
            .unwrap();
        drain_authenticated_and_forward_registered(&mut rx).await;
        let server_handle = pending.get().await;

        // 端口跟客户端注册的（22001）不一致，模拟服务端把不相干的通道
        // 塞进来——handler.rs 应该拒绝，不是巧合地也接受。
        let channel = with_timeout(
            "channel_open_forwarded_tcpip（端口不匹配）",
            server_handle.channel_open_forwarded_tcpip("127.0.0.1", 22002, "203.0.113.5", 54321),
        )
        .await;
        assert!(
            channel.is_err(),
            "端口不匹配时应该收到 CHANNEL_OPEN_FAILURE，实际 {channel:?}"
        );

        handle.shutdown().await;
    }

    // --- 指纹渲染：进程内假 Gateway 的 key 与 ClientHandler 算出来的
    // 指纹是否一致，作为 knownhosts.rs 里那条对着 harness 真实 key 的
    // 黄金向量测试（R44）的补充——这条覆盖的是"真的握手一次、
    // Authenticated 消息里报的指纹是否等于我们独立算出来的期望值"。

    #[tokio::test]
    async fn authenticated_message_reports_the_expected_fingerprint() {
        let (_reads, pending, conn, ..) = spawn_gateway(GatewayConfig::default());
        let (tx, mut rx) = mpsc::channel(32);
        let handle = with_timeout("establish_over", establish_over(conn, test_params(), tx))
            .await
            .unwrap();

        match next_msg(&mut rx).await {
            TunnelMsg::Authenticated { fingerprint } => {
                assert_eq!(fingerprint, expected_fingerprint());
            }
            other => panic!("{other:?}"),
        }

        handle.shutdown().await;
        drop(pending);
    }
}
