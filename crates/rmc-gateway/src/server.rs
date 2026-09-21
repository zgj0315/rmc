//! 接入层：TLS 1.3 → russh 服务端 → 口令认证。只实现口令认证与（Task 5 的）
//! 一条反向转发；其余请求让 russh 的默认行为去拒——`ChannelOpenHandle` 被
//! 丢弃而没调 `accept()`/`reject()` 时自动回 `AdministrativelyProhibited`
//! （`russh-0.63.3/src/lib_inner.rs:573-618`，`Handler` 的默认 trait 方法
//! 都是这么写的：拿到 `reply` 就在 async 块里直接返回，从不调用它）。
//!
//! 所以 `ConnHandler` **不实现** `channel_open_session`、
//! `channel_open_direct_tcpip`、`tcpip_forward`、`auth_publickey`
//! 等任何别的回调——一个都不写，就是拒绝。这不是靠写一堆 `reject()`
//! 做到的，是靠"不写代码"。

use crate::accounts::{AccountReader, Verify};
use crate::cidr::Cidr;
use crate::datadir::DataDir;
use crate::identity::Identity;
use crate::{Error, Result};
use rmc_core::code::{AccountName, ServerFingerprint};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinSet;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct Timings {
    pub keepalive: Duration,
    pub keepalive_max: usize,
    pub sweep: Duration,
    pub handshake: Duration,
    pub max_engineers_per_tunnel: usize,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            keepalive: Duration::from_secs(10),
            keepalive_max: 3,
            sweep: Duration::from_secs(10),
            handshake: Duration::from_secs(20),
            max_engineers_per_tunnel: 16,
        }
    }
}

impl Timings {
    /// 测试用：把秒改成几百毫秒，别的不变。
    ///
    /// **控制者订正 R4**：`handshake` 这里**不能**跟 `keepalive`/`sweep`
    /// 一样缩到 200ms——`auth_rejection_time` 是固定 1 秒
    /// （见 `Server::bind`），三次口令失败要走满 3 秒才会触发第四次那声
    /// "断开"；如果 `handshake` 也是几百毫秒，`three_failures_end_the_connection`
    /// 会在三次认证走完之前就被握手超时抢先掐断连接——测试照样绿，但绿的
    /// 理由是"握手超时"而不是"三次失败后被服务端断开"，这是一张假绿。
    /// 真正要验握手超时的两条测试自己构造
    /// `Timings { handshake: Duration::from_millis(500), ..Timings::fast() }`。
    pub fn fast() -> Self {
        Self {
            keepalive: Duration::from_millis(200),
            keepalive_max: 3,
            sweep: Duration::from_millis(200),
            handshake: Duration::from_secs(10),
            max_engineers_per_tunnel: 16,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub data: DataDir,
    /// 反向端口绑在哪个地址上：生产 0.0.0.0，测试 127.0.0.1。
    pub reverse_bind: IpAddr,
    pub timings: Timings,
    /// `--engineer-allow` 的网段列表；空 = 不过滤，任何来源都能连反向端口。
    pub engineer_allow: Vec<Cidr>,
}

/// 一条隧道在服务端这一侧的全部状态。Task 6 的吊销扫描与 Task 7 的
/// `status.json` 都读这张表（经 `Running::tunnels_snapshot`），本任务只写。
///
/// **偏离 brief 字面 Step 3**：brief 的伪代码里还有一个 `since:
/// SystemTime` 字段。本任务的 `tunnels_snapshot` 契约元组
/// `(AccountName, u16, SocketAddr, usize)`（brief 自己「Produces」那节给的
/// 签名）里没有它的位置，本任务也没有别的读者——加上就是又一个「只写不读
/// 的字段」，`clippy -D warnings` 的 `dead_code` 当场红（这正是 Task 4
/// 那条「`account` 字段只写不读」踩过的坑，也是这份 GLOBAL.md 里反复强调
/// 的原则）。等 Task 6/7 真要展示隧道存活时长时再加，到时候顺带扩一下
/// `tunnels_snapshot` 的元组形状（或另开一个访问器），「字段有读者」这个
/// 前提自然就满足了。
pub(crate) struct TunnelInfo {
    pub port: u16,
    pub peer: SocketAddr,
    pub engineers: Arc<AtomicUsize>,
    pub stop: watch::Sender<bool>,
}

/// 挂在 `ConnHandler` 上；`ConnHandler`（连同它）随会话真正结束时被丢弃
/// （会话正常收尾、心跳失联、或有人主动发了 `Handle::disconnect`——认证
/// 超时与 `Running::shutdown()` 现在都是走后面这条路，见 `Shared.connections`
/// 上的注释：光靠 `handle_connection` 自己的 `select!` 提前返回摸不到
/// 真正持有 `ConnHandler` 的那个内部任务），这里把隧道从表里摘掉并停掉
/// 反向监听任务。这是「摘表 + 停监听」唯一的出口。
pub(crate) struct TunnelGuard {
    shared: Arc<Shared>,
    account: AccountName,
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        if let Some(info) = lock(&self.shared.tunnels).remove(&self.account) {
            let _ = info.stop.send(true);
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// 挂在 `handle_connection` 的会话主循环期间：SSH 握手成功、拿到
/// `RunningSession::handle()` 之后创建，离开作用域（会话正常结束、认证
/// 超时、未来任何新增的提前返回——任何一条路）都会把这条连接从
/// `Shared.connections` 里摘掉，防止那张表随着连接来去无限增长。
struct ConnHandleGuard {
    shared: Arc<Shared>,
    peer: SocketAddr,
}

impl Drop for ConnHandleGuard {
    fn drop(&mut self) {
        lock(&self.shared.connections).remove(&self.peer);
    }
}

pub(crate) struct Shared {
    pub tls: tokio_rustls::TlsAcceptor,
    pub ssh: Arc<russh::server::Config>,
    pub accounts: AccountReader,
    pub timings: Timings,
    /// 反向端口绑在哪个地址上（生产 0.0.0.0，测试 127.0.0.1）。
    pub reverse_bind: IpAddr,
    pub engineer_allow: Vec<Cidr>,
    pub tunnels: Mutex<HashMap<AccountName, TunnelInfo>>,
    /// 每条已完成 SSH 握手（`run_stream` 已经返回）的连接的 `Handle`，
    /// 键是它的来源地址。
    ///
    /// **这张表存在的原因（评审第 1 轮挖出来的缺口）**：`russh::server::
    /// run_stream` 内部用 `russh_util::runtime::spawn`（本质就是裸
    /// `tokio::spawn`）另起一个任务去跑真正的消息循环
    /// （`Session::run`），那个任务才是真正持有 `ConnHandler`（连同它的
    /// `TunnelGuard`）的地方。它返回的 `RunningSession::join` 是
    /// `russh_util` 自己的 `JoinHandle`——内部只是一个
    /// `tokio::sync::oneshot::Receiver`，**没有 `abort()`**
    /// （`russh-util-0.52.0/src/runtime.rs:16-20`）。`handle_connection`
    /// 自己这层 wrapper 被摘掉（不管是 `accept_task.abort()` 级联把
    /// `JoinSet` 一起丢掉，还是这层函数自己的 `select!` 因为认证超时提前
    /// 返回）都摸不到那个内部任务——它会继续裸跑，`ConnHandler`/
    /// `TunnelGuard` 不会被丢弃，隧道端口不会被释放，未认证连接名额也
    /// 不会被真正腾出来。唯一能让它自己走完退出的路是给它发一条
    /// `Handle::disconnect(...)`：这条消息进了它自己的 mpsc，
    /// `dispatch_msg` 处理后把 `common.disconnected` 设成 `true`，它的
    /// 消息循环下一轮检查这个标志位（`server/session.rs` 里
    /// `while !self.common.disconnected`）就会自然退出。所以要留一份
    /// 每条连接的 `Handle`，好在 `Running::shutdown()` 与认证超时那两处
    /// 主动发这条消息。
    ///
    /// **跟 Task 6 吊销扫描的关系**：这张表按来源地址（`peer`）索引，
    /// 粒度是"连接"，不是"隧道"；`tunnels` 那张表才是按账号索引的隧道
    /// 状态。Task 6 如果要按账号找到对应连接的 `Handle` 去吊销，可以
    /// 直接复用这张表（拿 `TunnelInfo.peer` 去查）,也可以在 `TunnelInfo`
    /// 里再存一份 `Handle`（跟 `stop` 字段类似，反正 `Handle: Clone`
    /// 很便宜）——这里不预先做归并，留给 Task 6 的实现者按它吊销扫描的
    /// 实际查找模式决定，但基础设施（"发 disconnect 能让内部任务自己
    /// 退出"这条路）已经在这里立住了，不需要 Task 6 重新发现。
    pub connections: Mutex<HashMap<SocketAddr, russh::server::Handle>>,
}

pub struct Server;

pub struct Running {
    local_addr: SocketAddr,
    fingerprint: ServerFingerprint,
    stop: watch::Sender<bool>,
    accept_task: tokio::task::JoinHandle<()>,
    shared: Arc<Shared>,
}

impl Running {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    pub fn fingerprint(&self) -> ServerFingerprint {
        self.fingerprint
    }
    /// 测试与（Task 7）status 用：当前每条隧道的账号名、端口、来源地址、
    /// 在线工程师连接数。
    ///
    /// **偏离 brief 字面**：brief 的接口表把这个方法写成不带可见性限定
    /// （在 gateway 自己的模块体系里那就是 `pub(crate)`）。本任务实测发现
    /// 那样会被 `dead_code` 打红：它现在只有 `#[cfg(test)] mod tests`
    /// 里的调用者，`cargo clippy --all-targets` 里那个不带 `--cfg test`
    /// 的普通 lib 编译单元看不到 `mod tests`，判定这个方法从未被调用，
    /// 顺着牵连到 `Running.shared`、`TunnelInfo::port/peer` 一起变成
    /// 「只写不读」。跟 `Running::local_addr`/`fingerprint` 同理开成完全
    /// `pub`——它们本来就是给外部消费者（未来的 `cli.rs`/`status.rs`，
    /// 乃至这个 crate 之外的调用方）看服务器状态的自省接口，这个方法性质
    /// 一样。
    pub fn tunnels_snapshot(&self) -> Vec<(AccountName, u16, SocketAddr, usize)> {
        lock(&self.shared.tunnels)
            .iter()
            .map(|(name, info)| {
                (
                    name.clone(),
                    info.port,
                    info.peer,
                    info.engineers.load(Ordering::SeqCst),
                )
            })
            .collect()
    }
    /// 测试用：当前注册表里还有几条"已完成 SSH 握手"的连接。见
    /// `Shared.connections` 上的长注释——这个数字从非零变成零，是"这条
    /// 连接真的被服务端关掉了（内部消息循环任务真的退出、`ConnHandler`
    /// 真的被丢弃）"唯一可观察、不依赖 `is_closed()`（客户端自己怎么看
    /// 这条连接）的服务端侧判据。跟 `tunnels_snapshot` 同理开成 `pub`：
    /// 唯一调用者目前是测试，`pub(crate)` 会在不带 `--cfg test` 的普通
    /// lib 编译单元上被 `dead_code` 打红。
    pub fn connections_count(&self) -> usize {
        lock(&self.shared.connections).len()
    }
    /// **评审第 1 轮挖出来的缺口，已修**：光靠 `accept_task.abort()`
    /// 关不掉已经建立的会话——那只摘掉 `handle_connection` 这层 wrapper
    /// 和 accept 循环，真正跑消息循环、持有 `ConnHandler`/`TunnelGuard`
    /// 的内部任务是 russh 自己另起的，摸不到（见 `Shared.connections`
    /// 上的长注释）。这里先挨个给已注册的连接发 `disconnect`，让它们自己
    /// 走「`dispatch_msg` → `disconnected = true` → 消息循环退出」这条
    /// 路真正收尾（`ConnHandler` 被丢弃、`TunnelGuard` 跟着把隧道端口
    /// 释放掉），再摘 accept 循环。
    pub async fn shutdown(self) {
        let handles: Vec<russh::server::Handle> =
            lock(&self.shared.connections).values().cloned().collect();
        for h in handles {
            let _ = h
                .disconnect(
                    russh::Disconnect::ByApplication,
                    String::new(),
                    String::new(),
                )
                .await;
        }
        let _ = self.stop.send(true);
        self.accept_task.abort();
        let _ = self.accept_task.await;
    }
}

impl Server {
    pub async fn bind(cfg: ServerConfig) -> Result<Running> {
        let identity = Identity::load_from(&cfg.data)?;
        let fingerprint = identity.fingerprint();
        let tls = tokio_rustls::TlsAcceptor::from(identity.tls_server_config()?);
        let ssh = Arc::new(russh::server::Config {
            keys: vec![identity.ssh_host_key()],
            methods: russh::MethodSet::from(&[russh::MethodKind::Password][..]),
            max_auth_attempts: 3,
            auth_rejection_time: Duration::from_secs(1),
            inactivity_timeout: None,
            keepalive_interval: Some(cfg.timings.keepalive),
            keepalive_max: cfg.timings.keepalive_max,
            nodelay: true,
            ..Default::default()
        });
        // 建好之后立刻 clone 进 accept 任务，不要整个 move：`Running` 也存了
        // 一份（`tunnels_snapshot`），Task 6/7 的吊销扫描与发布状态都从
        // `Running.shared` 再拿一份。
        let shared = Arc::new(Shared {
            tls,
            ssh,
            accounts: AccountReader::new(&cfg.data),
            timings: cfg.timings.clone(),
            reverse_bind: cfg.reverse_bind,
            engineer_allow: cfg.engineer_allow.clone(),
            tunnels: Mutex::new(HashMap::new()),
            connections: Mutex::new(HashMap::new()),
        });
        let listener = tokio::net::TcpListener::bind(cfg.listen)
            .await
            .map_err(|e| Error::Listen(format!("{}：{e}", cfg.listen)))?;
        let local_addr = listener.local_addr()?;
        let (stop, mut stop_rx) = watch::channel(false);
        let accept_shared = shared.clone();
        let accept_task = tokio::spawn(async move {
            let shared = accept_shared;
            let mut conns = JoinSet::new();
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    accepted = listener.accept() => match accepted {
                        Ok((sock, peer)) => { conns.spawn(handle_connection(shared.clone(), sock, peer)); }
                        Err(e) => { tracing::warn!(error = %e, "accept 失败"); tokio::time::sleep(Duration::from_millis(50)).await; }
                    },
                    Some(_) = conns.join_next(), if !conns.is_empty() => {}
                }
            }
            conns.abort_all();
        });
        Ok(Running {
            local_addr,
            fingerprint,
            stop,
            accept_task,
            shared,
        })
    }
}

/// 一条连接的全程：TLS 握手 + SSH 认证必须在 `handshake` 内完成，否则直接关掉。
async fn handle_connection(shared: Arc<Shared>, sock: tokio::net::TcpStream, peer: SocketAddr) {
    let started = tokio::time::Instant::now();
    let deadline = tokio::time::sleep_until(started + shared.timings.handshake);
    tokio::pin!(deadline);
    let _ = sock.set_nodelay(true);
    let tls = tokio::select! {
        r = shared.tls.accept(sock) => match r {
            Ok(t) => t,
            Err(e) => { tracing::debug!(%peer, error = %e, "TLS 握手失败"); return; }
        },
        _ = &mut deadline => { tracing::info!(%peer, "TLS 握手超时"); return; }
    };
    let authed = Arc::new(AtomicBool::new(false));
    let handler = ConnHandler {
        shared: shared.clone(),
        peer,
        authed: authed.clone(),
        account: None,
        tunnel: None,
    };
    let running = tokio::select! {
        r = russh::server::run_stream(shared.ssh.clone(), tls, handler) => match r {
            Ok(s) => s,
            Err(e) => { tracing::debug!(%peer, error = %e, "SSH 握手失败"); return; }
        },
        _ = &mut deadline => { tracing::info!(%peer, "SSH 握手超时"); return; }
    };
    // **评审第 1 轮挖出来的缺口，已修**：`running`（`RunningSession`）只是
    // 一个薄包装，`Future::poll` 转发给内部 `join`（`russh_util` 自己的
    // `JoinHandle`，本质是 `oneshot::Receiver`，见 `Shared.connections`
    // 上的长注释）。真正持有 `ConnHandler` 的任务是 russh 内部用
    // `russh_util::runtime::spawn`（裸 `tokio::spawn`）另起的，跟这层
    // `handle_connection` 的生死没有关系——这层函数无论从哪条路返回都
    // 摸不到它，除非主动发 `disconnect`。所以先把这条连接的 `Handle`
    // 注册进 `shared.connections`（`ConnHandleGuard` 保证离开这个函数时
    // 一定会被摘掉），后面认证超时那一支才有东西可以发。
    let handle = running.handle();
    lock(&shared.connections).insert(peer, handle.clone());
    let _conn_guard = ConnHandleGuard {
        shared: shared.clone(),
        peer,
    };
    tokio::pin!(running);
    // **偏离 brief 字面 Step 2**：brief 的伪代码在这里外面包了一层
    // `loop { tokio::select! {...} }`。`cargo clippy -D warnings` 的
    // `never_loop` 直接把它判红：两个分支都以 `return` 收尾，`select!`
    // 选中任意一支都会跳出函数，`loop` 从来没有机会真正"再循环一次"
    // ——是死代码，不是留着等下一轮再 select 的活代码。去掉这层 `loop`：
    // `running`（整条会话，认证成功之后也在这个 future 里继续跑 keepalive
    // 等消息处理）与 `deadline`（认证超时）两个 future 本来就是并发轮询，
    // 谁先完成 `select!` 就返回谁那一支——一次 `select!` 已经等价于"一直
    // 等到会话结束或认证超时二者谁先到"，不需要外层循环。
    tokio::select! {
        r = &mut running => {
            if let Err(e) = r {
                tracing::debug!(%peer, error = %e, "会话结束");
            }
        }
        _ = &mut deadline, if !authed.load(Ordering::SeqCst) => {
            tracing::info!(%peer, "认证超时，断开");
            // 这个分支只是让 `handle_connection` 自己的 `select!` 提前
            // 返回——真正跑消息循环的内部任务不受这层 `select!` 影响，
            // 还在裸跑。必须主动发 `disconnect` 让它自己走
            // `dispatch_msg` → `disconnected = true` → 循环退出这条路，
            // 否则这条连接根本没有真的关闭：Task 6「全局最多 64 条、
            // 每 IP 最多 8 条未认证连接」那个上限就是靠这份名额算的，
            // 名额被这个函数返回而释放、连接却没死，上限就是错的。
            let _ = handle
                .disconnect(russh::Disconnect::ByApplication, String::new(), String::new())
                .await;
        }
    }
}

/// **偏离 brief 字面 Step 2 的关键一处，实测撞出来的，不是猜的**：brief
/// 的伪代码在拒绝时直接用 `russh::server::Auth::reject()`
/// （`proceed_with_methods: None`）。实测（把这条测试跑起来，开
/// `RUST_LOG=trace` 看 russh 内部日志）发现：`server_read_auth_request`
/// 处理 password 方法的分支里（`russh-0.63.3/src/server/encrypted.rs:757-774`），
/// 只要 `Auth::Reject.proceed_with_methods` 是 `None`，就会执行
/// `auth_request.methods.remove(MethodKind::Password)`——把 password 从
/// 「这次绑定还能再试的方法」里永久删掉。本服务端的 `methods` 只登记了
/// Password 一种，删掉之后 `auth_request.methods` 变空集，服务端把这个
/// 空集合当作 `remaining_methods` 回给客户端；**russh 的客户端一看
/// `remaining_methods` 是空的就自己认定"没有方法可试了"，主动断开
/// （`Error::NoAuthMethod`）**——不是我们的服务端主动踢的，是客户端库自己
/// 放弃重试。第一次 `sed`/print 调试看到的现象是：
/// `password_auth_accepts_the_live_account_and_rejects_everything_else`
/// 在第一次错口令之后就整条连接断了，第二、三次调用直接拿到 `SendError`
/// （通道已经关闭），跟"三次失败才断开"（spec §6）完全对不上。
///
/// 修法：拒绝时显式给 `proceed_with_methods: Some(MethodSet::from(&[Password]))`，
/// 这样 russh 每次都把 `auth_request.methods` 重新设成「仍然是 Password」，
/// 客户端看到"还能试 password"就会继续重试，直到 russh 自己的
/// `max_auth_attempts`（配置成 3）在第 4 次请求之前用
/// `rejection_count >= max_auth_attempts` 这条检查把连接断掉——这才是
/// spec §6"每连接最多 3 次"真正生效的机制。`auth_none`（默认实现）不受
/// 影响，因为它删掉的是 `MethodKind::None`，不影响 `methods` 里的
/// `Password`（这也是为什么 `only_password_is_advertised` 那条测试一开始
/// 就是绿的，没暴露这个坑）。
fn reject_but_let_client_retry_password() -> russh::server::Auth {
    russh::server::Auth::Reject {
        proceed_with_methods: Some(russh::MethodSet::from(&[russh::MethodKind::Password][..])),
        partial_success: false,
    }
}

pub(crate) struct ConnHandler {
    pub shared: Arc<Shared>,
    pub peer: SocketAddr,
    pub authed: Arc<AtomicBool>,
    pub account: Option<(AccountName, u16)>,
    /// `Some` 一旦这条会话开成了一条反向隧道。`Drop` 落在 `TunnelGuard`
    /// 上：会话结束（无论哪条路）时，`ConnHandler` 被丢弃，这个字段随之
    /// 被丢弃，隧道跟着被摘掉、监听任务被停掉。
    pub tunnel: Option<TunnelGuard>,
}

impl russh::server::Handler for ConnHandler {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> std::result::Result<russh::server::Auth, Self::Error> {
        // 账号名先按字符集校验：不合法直接拒，不跑哈希（字符集是公开规则，
        // 不泄露账号是否存在）。
        let Ok(name) = AccountName::parse(user) else {
            return Ok(reject_but_let_client_retry_password());
        };
        let shared = self.shared.clone();
        let n = name.clone();
        let password = Zeroizing::new(password.to_string());
        // argon2 是几十毫秒的 CPU 活，别在 reactor 线程上做。
        let verdict =
            tokio::task::spawn_blocking(move || shared.accounts.verify(n.as_str(), &password))
                .await
                .unwrap_or(Verify::Rejected);
        match verdict {
            Verify::Ok { port } => {
                self.authed.store(true, Ordering::SeqCst);
                self.account = Some((name.clone(), port));
                tracing::info!(peer = %self.peer, account = %name, "口令认证成功");
                Ok(russh::server::Auth::Accept)
            }
            Verify::Rejected => {
                tracing::debug!(peer = %self.peer, account = %name, "口令认证失败");
                Ok(reject_but_let_client_retry_password())
            }
        }
    }

    /// `port == 0` 时把账号绑定的反向端口回填给客户端；申请一个别的端口
    /// 一律拒绝。同一账号同一时刻只允许一条隧道活着。
    async fn tcpip_forward(
        &mut self,
        _address: &str,
        port: &mut u32,
        session: &mut russh::server::Session,
    ) -> std::result::Result<bool, Self::Error> {
        let Some((account, account_port)) = self.account.clone() else {
            return Ok(false);
        };
        if *port != 0 && *port != u32::from(account_port) {
            return Ok(false);
        }
        if self.tunnel.is_some() {
            // 这条会话自己已经有一条隧道了。
            return Ok(false);
        }
        {
            let mut t = lock(&self.shared.tunnels);
            if t.contains_key(&account) {
                return Ok(false);
            }
            // 先占位再 bind：同账号并发的第二次申请立刻在这道
            // `contains_key` 上被拒，不需要等 OS 级别的 `EADDRINUSE`。
            let (stop, _) = watch::channel(false);
            t.insert(
                account.clone(),
                TunnelInfo {
                    port: account_port,
                    peer: self.peer,
                    engineers: Arc::new(AtomicUsize::new(0)),
                    stop,
                },
            );
        }
        // bind 短重试：`TunnelGuard::drop` 摘表是同步的，但上一个反向监听
        // 任务收到 `stop` 是异步的——它手里的 `TcpListener` 要等任务真正
        // 跳出循环、局部变量被丢弃才关闭。所以「表里没有这个账号了」和
        // 「端口真的能 bind 了」之间有一个短暂窗口：客户端断线后很快重连
        // 可能在这个窗口里撞上 `EADDRINUSE`。这里重试是为了盖住这个窗口，
        // **不是**为了盖住「上一条隧道真的还活着」——那种情况上面的
        // `contains_key` 已经拒绝了，重试也拿不到端口，3 次很快就会用完。
        let mut bound = None;
        for attempt in 0..3u32 {
            match tokio::net::TcpListener::bind((self.shared.reverse_bind, account_port)).await {
                Ok(l) => {
                    bound = Some(l);
                    break;
                }
                Err(e) => {
                    tracing::debug!(%account, account_port, attempt, error = %e, "反向端口绑定失败，准备重试");
                    if attempt + 1 < 3 {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
        let listener = match bound {
            Some(l) => l,
            None => {
                tracing::warn!(%account, account_port, "反向端口绑定失败（重试 3 次后仍失败）");
                lock(&self.shared.tunnels).remove(&account);
                return Ok(false);
            }
        };
        let (stop_rx, engineers) = {
            let t = lock(&self.shared.tunnels);
            let info = t.get(&account).expect("刚插的");
            (info.stop.subscribe(), info.engineers.clone())
        };
        *port = u32::from(account_port);
        tokio::spawn(reverse_accept_loop(
            self.shared.clone(),
            account.clone(),
            account_port,
            listener,
            session.handle(),
            stop_rx,
            engineers,
        ));
        self.tunnel = Some(TunnelGuard {
            shared: self.shared.clone(),
            account,
        });
        Ok(true)
    }

    /// 主动取消转发：丢掉 `TunnelGuard` 就是全部——摘表、停监听、断工程师，
    /// 但不断这条 SSH 会话本身。
    async fn cancel_tcpip_forward(
        &mut self,
        _address: &str,
        _port: u32,
        _session: &mut russh::server::Session,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(self.tunnel.take().is_some())
    }
}

/// 反向监听：接受工程师的 TCP 连接，来源白名单过滤，每条隧道最多
/// `max_engineers_per_tunnel` 条并发，逐条开 `forwarded-tcpip` 通道并
/// `copy_bidirectional` 到现场客户端。`stop` 一响就退出循环——退出之后
/// `listener` 随局部变量丢弃而关闭，端口才真正释放；这正是
/// `tcpip_forward` 里那段短重试要盖住的窗口的另一半。
async fn reverse_accept_loop(
    shared: Arc<Shared>,
    account: AccountName,
    port: u16,
    listener: tokio::net::TcpListener,
    handle: russh::server::Handle,
    mut stop: watch::Receiver<bool>,
    engineers: Arc<AtomicUsize>,
) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let Ok((mut sock, peer)) = accepted else { continue };
                if !crate::cidr::allowed(&shared.engineer_allow, peer.ip()) {
                    tracing::info!(%account, port, %peer, "工程师来源不在白名单，拒绝");
                    continue; // sock 随作用域关闭
                }
                let prev = engineers.fetch_add(1, Ordering::SeqCst);
                if prev >= shared.timings.max_engineers_per_tunnel {
                    engineers.fetch_sub(1, Ordering::SeqCst);
                    tracing::info!(%account, port, %peer, "工程师连接数已达上限，拒绝");
                    continue;
                }
                let handle = handle.clone();
                let engineers = engineers.clone();
                let account = account.clone();
                let _ = sock.set_nodelay(true);
                tasks.spawn(async move {
                    let opened = handle
                        .channel_open_forwarded_tcpip(
                            "127.0.0.1",
                            u32::from(port),
                            peer.ip().to_string(),
                            u32::from(peer.port()),
                        )
                        .await;
                    match opened {
                        Ok(ch) => {
                            let mut st = ch.into_stream();
                            let r = tokio::io::copy_bidirectional(&mut sock, &mut st).await;
                            tracing::debug!(%account, port, %peer, ?r, "工程师连接结束");
                        }
                        Err(e) => {
                            tracing::warn!(%account, port, %peer, error = %e, "开 forwarded-tcpip 通道失败");
                        }
                    }
                    engineers.fetch_sub(1, Ordering::SeqCst);
                });
            }
        }
    }
    // stop 之后：监听随 listener 局部变量丢弃而释放，工程师连接全部中止。
    tasks.abort_all();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::AccountStore;
    use crate::cidr::Cidr;
    use crate::config::GatewayConfig;
    use crate::datadir::DataDir;
    use crate::identity::Identity;
    use crate::testing_verifier::{ssh_connect, ssh_connect_echo};
    use rmc_core::code::AccountName;
    use std::time::Duration;

    /// 一个带一个账号的服务端。返回 (running, 口令, 临时目录)。
    ///
    /// **控制者补充的坑，实测踩到过**：挑反向端口那一步「bind
    /// `127.0.0.1:0` 拿到端口号再 drop」是 TOCTOU——从 drop 到账号真正用
    /// 上这个号之间，这个号理论上可能被别的进程/别的测试抢走；本机串行跑
    /// 不容易撞上，CI 并行跑就说不准了。**实测还踩到了这个坑的一个变种**：
    /// 第一版把账号端口区间写成 `20000..=60000`，本机（macOS）临时端口
    /// 分配范围会给到 60000 以上（实测拿到过 `60118`），`store.add` 因为
    /// "不在区间内"直接报错——`Accounts("60118 不在反向端口区间
    /// 20000-60000 内")`，是真的红过一次，不是假设。这不是"别的进程抢走
    /// 端口"那种 TOCTOU，是"操作系统临时端口范围比我们的账号端口区间还
    /// 宽"，同一类"探出来的号不一定能用"的问题。
    ///
    /// 按控制者订正的默认选项处理：**重试，不改产生端口的方式**——把
    /// 「探号 + 区间给到最大（`1..=65535`，把区间不匹配这条路也堵死）+
    /// `store.add`」包进一个最多 5 次的循环，某次探到的号用不了（区间不
    /// 对，或者真的被抢先绑定）就换一个号重试。
    pub(crate) async fn server_with_account(
        name: &str,
    ) -> (Running, zeroize::Zeroizing<String>, tempfile::TempDir) {
        server_with_account_and(name, Timings::fast(), Vec::new()).await
    }

    async fn server_with_account_and_timings(
        name: &str,
        timings: Timings,
    ) -> (Running, zeroize::Zeroizing<String>, tempfile::TempDir) {
        server_with_account_and(name, timings, Vec::new()).await
    }

    async fn server_with_account_and_allow(
        name: &str,
        allow: Vec<Cidr>,
    ) -> (Running, zeroize::Zeroizing<String>, tempfile::TempDir) {
        server_with_account_and(name, Timings::fast(), allow).await
    }

    async fn server_with_account_and(
        name: &str,
        timings: Timings,
        engineer_allow: Vec<Cidr>,
    ) -> (Running, zeroize::Zeroizing<String>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let d = DataDir::at(tmp.path().to_path_buf());
        d.create().unwrap();
        Identity::create_in(&d).unwrap();
        let mut cfg = GatewayConfig::new("127.0.0.1:22000".parse().unwrap());
        // 区间给到几乎整个 u16 空间，好接受操作系统探出来的任何临时端口号
        // （见下面 `server_with_account` 挑号那段的注释）。
        cfg.reverse_port_min = 1;
        cfg.reverse_port_max = 65535;
        cfg.save(&d).unwrap();
        let store = AccountStore::open(&d, &cfg, 22000);
        let name = AccountName::parse(name).unwrap();
        let pw = (0..5)
            .find_map(|_| {
                let free = {
                    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                    l.local_addr().unwrap().port()
                };
                store.add(&name, Some(free), "").map(|(_, pw)| pw).ok()
            })
            .expect("5 次都没探到一个能用的反向端口");
        let running = Server::bind(ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            data: d,
            reverse_bind: "127.0.0.1".parse().unwrap(),
            timings,
            engineer_allow,
        })
        .await
        .unwrap();
        (running, pw, tmp)
    }

    async fn within<T>(what: &str, f: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(20), f)
            .await
            .unwrap_or_else(|_| panic!("{what} 超时"))
    }

    /// 改红：`auth_password` 里不看 `verify` 的结果、一律 `Accept`
    /// ——第二、三格红（错口令、不存在的账号都会被当成认证成功）。
    #[tokio::test]
    async fn password_auth_accepts_the_live_account_and_rejects_everything_else() {
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect(srv.local_addr())).await;
        assert!(!s
            .authenticate_password("zhang", "wrong")
            .await
            .unwrap()
            .success());
        assert!(!s
            .authenticate_password("nobody", pw.as_str())
            .await
            .unwrap()
            .success());
        assert!(s
            .authenticate_password("zhang", pw.as_str())
            .await
            .unwrap()
            .success());
        srv.shutdown().await;
    }

    /// 服务端只登记 password 一种方法。改红：`methods` 用
    /// `MethodSet::server_supported()`（登记全部方法，包括 publickey）。
    #[tokio::test]
    async fn only_password_is_advertised() {
        let (srv, _pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect(srv.local_addr())).await;
        match s.authenticate_none("zhang").await.unwrap() {
            russh::client::AuthResult::Failure {
                remaining_methods, ..
            } => {
                assert_eq!(
                    remaining_methods,
                    russh::MethodSet::from(&[russh::MethodKind::Password][..])
                );
            }
            other => panic!("none 认证不该成功：{other:?}"),
        }
        srv.shutdown().await;
    }

    /// 认证之后，session 通道与正向转发都被拒——服务端根本没实现它们。
    /// 改红：给 `ConnHandler` 实现 `channel_open_session` 并 `reply.accept()`
    /// ——第一格红（session 通道能开成）。
    #[tokio::test]
    async fn session_and_direct_tcpip_channels_are_refused_after_auth() {
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect(srv.local_addr())).await;
        assert!(s
            .authenticate_password("zhang", pw.as_str())
            .await
            .unwrap()
            .success());
        assert!(
            s.channel_open_session().await.is_err(),
            "session 通道必须被拒"
        );
        assert!(
            s.channel_open_direct_tcpip("127.0.0.1", 22, "127.0.0.1", 1)
                .await
                .is_err(),
            "正向转发必须被拒"
        );
        srv.shutdown().await;
    }

    /// 三次口令失败后服务端断开。
    ///
    /// **控制者订正 R4**：只断言「第四次失败」证明不了前三次真的发生过
    /// （比如一个总是 reject 的实现，第四次当然也失败，但那不是「三次
    /// 之后」断开，是「一次都没通过」）。这里分别断言第 1、2、3 次
    /// `authenticate_password` 各自返回「不成功」（服务端确实在逐次拒绝、
    /// 连接还活着能接着认证），第 4 次才断言错误或连接已关。
    ///
    /// 改红：`max_auth_attempts` 改回默认的 10——第 4 次不会被切断
    /// （连接还能继续认证），下面 `within` 会等到 20 秒超时 panic。
    ///
    /// **修复轮 1/5**：循环里原来是
    /// `r.map(|a| !a.success()).unwrap_or(true)`——`r` 是 `Err` 时
    /// `unwrap_or(true)` 直接放行，跟这句断言自己的文案「不是连接错误」
    /// 自相矛盾。回归场景：如果 `max_auth_attempts` 被误改成 1，第 2 次
    /// `authenticate_password` 在 russh 内部 `rejection_count(1) >= max(1)`
    /// 那道检查上就会被直接断开（连 `auth_password` 都不会被调用），
    /// `r` 变成 `Err`，旧断言照样放行，循环外「三次之后…」那句在已经关闭
    /// 的连接上自然成立——整条测试全绿，但服务端实际只给了 1 次机会。
    /// 改用 `match`：`Err` 直接 `panic!`，不再被 `unwrap_or` 悄悄吞掉。
    /// 改红：把 `max_auth_attempts` 改成 `1`（实测记录见
    /// task-4-report.md「修复轮 1/5」：修复前这一改仍然绿，修复后才红）。
    #[tokio::test]
    async fn three_failures_end_the_connection() {
        let (srv, _pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect(srv.local_addr())).await;
        for n in 1..=3 {
            match within("第几次认证", s.authenticate_password("zhang", "wrong")).await {
                Ok(a) => assert!(!a.success(), "第 {n} 次不该认证成功"),
                Err(e) => panic!("第 {n} 次应当是普通的认证失败，不是连接错误：{e}"),
            }
        }
        let r = within("第四次", s.authenticate_password("zhang", "wrong")).await;
        assert!(
            r.is_err() || s.is_closed(),
            "三次之后连接应当被服务端断开：{r:?}"
        );
        srv.shutdown().await;
    }

    /// 只连 TCP、什么都不发：到期被服务端关掉。
    ///
    /// 改红：`handle_connection` 里把 `deadline` 那一支删掉——这条超时红
    /// （永远等不到 EOF，5 秒后 `timeout` 本身 panic）。
    ///
    /// 这条测试专门验证握手超时，所以**自己构造**一个 500ms 的
    /// `handshake`（不用 `Timings::fast()` 默认的 10 秒——那是为了不跟
    /// `three_failures_end_the_connection` 的 3 秒认证窗口打架，见 R4）。
    ///
    /// **这条测试到底在验什么（修复轮 1/5，评审要求核实，已核实）**：
    /// 客户端只连了裸 TCP，从没发过 TLS ClientHello，所以服务端这边卡在
    /// `handle_connection` 的**第一个** `select!`（`shared.tls.accept(sock)`
    /// 对 `deadline`），根本没走到 `russh::server::run_stream(...)`——也
    /// 就是说这个场景下**从来没有那个被 `russh_util::runtime::spawn`
    /// detach 出去的内部任务**（那个任务要等 SSH 版本号交换完、
    /// `run_stream` 已经在往回走的路上才会被 spawn 出来）。`deadline` 赢
    /// 了之后，被丢弃的是 `shared.tls.accept(sock)` 这个 future 本身，
    /// 它内部持有的 `TcpStream` 随之被真的 drop、真的关闭——客户端读到
    /// 的 EOF 是这次真实关闭的结果，不是别的机制顶上来的假象。跟下面
    /// `tls_ok_but_no_auth_is_also_closed_at_the_deadline` 不一样：那条
    /// 测试的 TLS 握手是真的完成了的，服务端已经跑过第一个 `select!`、
    /// 进了第二个（`running` 对 `deadline`），这时候内部任务确实已经被
    /// spawn 出来、脱离了这层 `select!` 的管辖——才需要修复轮 1/5 里那个
    /// 主动发 `disconnect` 的补丁。这条测试没有这个问题，不用改。
    #[tokio::test]
    async fn an_idle_unauthenticated_connection_is_closed_at_the_deadline() {
        use tokio::io::AsyncReadExt;
        let (srv, _pw, _tmp) = server_with_account_and_timings(
            "zhang",
            Timings {
                handshake: Duration::from_millis(500),
                ..Timings::fast()
            },
        )
        .await;
        let mut sock = tokio::net::TcpStream::connect(srv.local_addr())
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
            .await
            .expect("服务端 500ms 内该关掉它")
            .unwrap();
        assert_eq!(n, 0, "应当读到 EOF");
        srv.shutdown().await;
    }

    /// TLS 握手成功但 SSH 认证迟迟不来：同样到期关掉（同一个 deadline 管
    /// 两段）。同上，自己构造 500ms 的 `handshake`。
    ///
    /// **修复轮 1/5，评审挖出来的假绿，已实测确认并修**：这条测试原来只
    /// 断言 `s.is_closed()`（客户端自己怎么看这条连接），用的 keepalive
    /// 是 `Timings::fast()` 默认的 200ms/最多 3 次——到 600~800ms 服务端
    /// 自己的心跳机制就会把这条空闲连接顺手踢掉，跟"认证超时那条 deadline
    /// 分支到底做没做事"完全无关。**实测确认过这个假绿是真的**：把
    /// `handle_connection` 认证超时那一支还原成"只打日志、不发
    /// disconnect"（也就是评审指出的那个原始 bug），配合把 keepalive 调成
    /// 1 小时（让心跳兜底不了），900ms 后 `is_closed()` 仍然是 `false`——
    /// 说明原来那条 `assert!(s.is_closed())` 之所以能过，靠的是
    /// `Timings::fast()` 的心跳，不是 deadline 逻辑本身。
    ///
    /// 修完之后这条测试做了两处强化：① keepalive 故意设得极长
    /// （1 小时/最多 1000 次），堵死心跳兜底这条路，保证 900ms 内只有
    /// `handle_connection` 里的 deadline 分支能关掉这条连接；②
    /// 除了客户端侧的 `is_closed()`，再加一句服务端侧的判据
    /// `srv.connections_count() == 0`——见 `Running::connections_count`
    /// 与 `Shared.connections` 上的注释：这张表的条目只有在真正持有
    /// `ConnHandler` 的内部任务退出（`ConnHandleGuard::drop` 触发）时才会
    /// 被摘掉，所以"这个数字变成 0"直接证明"服务端那一侧真的把这条连接
    /// 收尾了"，不只是"客户端自己觉得断了"。
    ///
    /// **防 flake 提醒（控制者订正，仍然适用）**：`is_closed()`/
    /// `connections_count()` 变成预期值依赖服务端发出 `disconnect` 之后
    /// 内部任务被调度到、真正走完退出逻辑，中间有调度延迟；500ms 的
    /// deadline + 900ms 的等待留了 400ms 余量。万一 flake，加长等待，
    /// 不要缩短 deadline——deadline 是被测对象，等待只是观测手段。
    #[tokio::test]
    async fn tls_ok_but_no_auth_is_also_closed_at_the_deadline() {
        let (srv, _pw, _tmp) = server_with_account_and_timings(
            "zhang",
            Timings {
                handshake: Duration::from_millis(500),
                // 见上面的函数级注释：故意堵死心跳兜底这条路。
                keepalive: Duration::from_secs(3600),
                keepalive_max: 1000,
                ..Timings::fast()
            },
        )
        .await;
        let s = within("connect", ssh_connect(srv.local_addr())).await;
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(s.is_closed(), "500ms 没认证，服务端该断开");
        assert_eq!(
            srv.connections_count(),
            0,
            "服务端这一侧也要真的把这条连接收尾掉，不能只是客户端自己看到断线"
        );
        srv.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_stops_accepting() {
        let (srv, _pw, _tmp) = server_with_account("zhang").await;
        let addr = srv.local_addr();
        srv.shutdown().await;
        assert!(tokio::net::TcpStream::connect(addr).await.is_err());
    }

    async fn engineer_roundtrip(port: u16, msg: &[u8]) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("连反向端口");
        s.write_all(msg).await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf))
            .await
            .expect("读超时")
            .unwrap();
        buf.truncate(n);
        buf
    }

    /// 探针 2 的场景：端口 0 → 回填；工程师的字节到客户端再回来。
    /// 改红：`tcpip_forward` 里不写 `*port = account_port`——第一格红；
    /// 反向监听里不开 forwarded-tcpip 通道——第二格红。
    #[tokio::test]
    async fn port_zero_is_filled_with_the_account_port_and_bytes_flow_both_ways() {
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect_echo(srv.local_addr())).await;
        assert!(s
            .authenticate_password("zhang", pw.as_str())
            .await
            .unwrap()
            .success());
        let got = s.tcpip_forward("", 0).await.expect("tcpip_forward");
        let expected = srv.tunnels_snapshot()[0].1;
        assert_eq!(got as u16, expected);
        assert_eq!(engineer_roundtrip(expected, b"hello").await, b"echo:hello");
        srv.shutdown().await;
    }

    #[tokio::test]
    async fn a_request_for_a_different_port_is_denied() {
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect_echo(srv.local_addr())).await;
        assert!(s
            .authenticate_password("zhang", pw.as_str())
            .await
            .unwrap()
            .success());
        assert!(s.tcpip_forward("", 9).await.is_err());
        assert!(
            srv.tunnels_snapshot().is_empty(),
            "被拒的申请不能留下隧道记录"
        );
        srv.shutdown().await;
    }

    /// 同账号第二条隧道在第一条还活着时被拒（客户端把它映射成「端口占用」）。
    /// 改红：`tcpip_forward` 里把「账号已有隧道」那句判断删掉——第二格绿。
    #[tokio::test]
    async fn a_second_tunnel_for_the_same_account_is_denied_while_the_first_lives() {
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut a = within("a", ssh_connect_echo(srv.local_addr())).await;
        assert!(a
            .authenticate_password("zhang", pw.as_str())
            .await
            .unwrap()
            .success());
        a.tcpip_forward("", 0).await.unwrap();
        let mut b = within("b", ssh_connect_echo(srv.local_addr())).await;
        assert!(
            b.authenticate_password("zhang", pw.as_str())
                .await
                .unwrap()
                .success(),
            "认证是过的"
        );
        assert!(b.tcpip_forward("", 0).await.is_err(), "第二条必须被拒");
        srv.shutdown().await;
    }

    /// 客户端一断，端口**立即**能被别人绑上，工程师的连接也被断掉。
    ///
    /// **「改红」实测记录（brief 里那条是假支票，已改写）**：brief 字面写的
    /// 是「`TunnelGuard::drop` 里不发 `stop`——这条在 bind 那一步红」。照字面
    /// 只删掉 `info.stop.send(true)` 那一行、保留 `remove(&self.account)`，
    /// 实测**全绿**：`tokio::sync::watch::Receiver::changed()` 在
    /// `select!` 里只看"这个 future 有没有 resolve"，不看它 resolve 出的是
    /// `Ok`（真的发了新值）还是 `Err`（Sender 被丢弃）——`remove` 拿到的
    /// `TunnelInfo`（连同它那个 `stop: watch::Sender`）在 `if let` 块结束时
    /// 照样被丢弃，`Receiver::changed()` 照样因为"发送端没了"被唤醒，
    /// 反向监听照样退出、端口照样释放——`.send(true)` 这一行本身其实是
    /// 冗余的（不发也靠 Sender 被 drop 达到同样效果）。真正能打红这条测试
    /// 的注入点是让整个 `drop` 什么都不做（连 `remove` 也不做）：这样
    /// `TunnelInfo`（及其 `stop`）继续留在表里、`Sender` 继续活着，
    /// `changed()` 永远不 resolve，反向监听永远不退出，`bind` 在同一个
    /// 端口上拿到真实的 `AddrInUse`——实测确认过（见 task-5-report.md）。
    ///
    /// **这个 sleep 等的是「旧监听真的关闭」，不是调度余量**（控制者补充）：
    /// `TunnelGuard::drop` 摘表是同步的，但反向监听任务收到 `stop` 是
    /// 异步的——它手里的 `TcpListener` 要等任务真正跳出循环、局部变量被
    /// 丢弃才关闭。这里 200ms 是给那个异步收尾留的时间，不是给 tokio 调度
    /// 器留的余量；`tcpip_forward` 里的短重试盖住的是"没有这 200ms"的
    /// 场景（见下面 `reconnecting_immediately_after_disconnect...` 那条）。
    #[tokio::test]
    async fn disconnecting_frees_the_port_immediately_and_drops_engineers() {
        use tokio::io::AsyncReadExt;
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect_echo(srv.local_addr())).await;
        assert!(s
            .authenticate_password("zhang", pw.as_str())
            .await
            .unwrap()
            .success());
        let port = s.tcpip_forward("", 0).await.unwrap() as u16;
        let mut eng = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        s.disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .unwrap();
        // 旧监听真的关闭需要一点时间：见上面的函数级注释。
        tokio::time::sleep(Duration::from_millis(200)).await;
        let l = tokio::net::TcpListener::bind(("127.0.0.1", port)).await;
        assert!(l.is_ok(), "端口没有立即释放：{:?}", l.err());
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), eng.read(&mut buf))
            .await
            .expect("工程师连接应当被断开")
            .unwrap_or(0);
        assert_eq!(n, 0);
        assert!(srv.tunnels_snapshot().is_empty());
        srv.shutdown().await;
    }

    /// **控制者补充的竞态窗口，回归网**：客户端断开后**立即**（不 sleep）
    /// 用同一个账号重新申请隧道，必须成功——`tcpip_forward` 里 bind 失败
    /// 短重试（3 次、每次 50ms）就是为了盖住"表项已摘、旧监听尚未真正
    /// 关闭"这个窗口。
    ///
    /// **实测记录（如实报告，没有删测试）**：把重试次数从 3 改成 1，本机
    /// 连跑 20 次全绿，没有观察到 flake（见 task-5-report.md）。原因：
    /// `TunnelGuard::drop` 是 `handle_connection` 返回时同步跑的（摘表 +
    /// 让 `stop` 这个 `watch::Sender` 被丢弃/发送），发生在"新连接的 SSH
    /// 握手 + 认证 + 再发一次 `tcpip_forward`"这一整套往返之前；本机这套
    /// 往返本身就有几毫秒到几十毫秒，足够 tokio 把反向监听那个任务重新
    /// 调度到、跑完 `break`、丢掉旧 `TcpListener`——窗口在本机这套时序下
    /// 从没被真正撞开过。这不代表窗口不存在（`TunnelGuard::drop` 摘表和
    /// 监听任务真正关闭 listener 之间确实有异步间隔，见 `Drop` impl旁的
    /// 注释），只是本机测得的时间尺度下重试第 1 次几乎总能命中。**按控制者
    /// 的要求保留这条测试当回归网**：一旦调度更慢的机器/CI 环境撞开这个
    /// 窗口，这条测试会红，而短重试本身仍然是兜底——不删测试，也不删重试。
    #[tokio::test]
    async fn reconnecting_immediately_after_disconnect_gets_the_same_port_back() {
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut a = within("a", ssh_connect_echo(srv.local_addr())).await;
        assert!(a
            .authenticate_password("zhang", pw.as_str())
            .await
            .unwrap()
            .success());
        let port = a.tcpip_forward("", 0).await.unwrap() as u16;
        a.disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .unwrap();
        // 不 sleep：立刻用同一个账号重新连接、重新申请隧道。
        let mut b = within("b", ssh_connect_echo(srv.local_addr())).await;
        assert!(b
            .authenticate_password("zhang", pw.as_str())
            .await
            .unwrap()
            .success());
        let got = within("重建隧道", b.tcpip_forward("", 0))
            .await
            .expect("bind 短重试应当盖住旧监听尚未关闭的窗口");
        assert_eq!(got as u16, port);
        srv.shutdown().await;
    }

    #[tokio::test]
    async fn cancel_tcpip_forward_frees_the_port_without_dropping_the_session() {
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect_echo(srv.local_addr())).await;
        assert!(s
            .authenticate_password("zhang", pw.as_str())
            .await
            .unwrap()
            .success());
        let port = s.tcpip_forward("", 0).await.unwrap() as u16;
        s.cancel_tcpip_forward("", port as u32).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .is_ok());
        assert!(!s.is_closed(), "取消转发不该断会话");
        // 还能再申请一次
        assert_eq!(s.tcpip_forward("", 0).await.unwrap() as u16, port);
        srv.shutdown().await;
    }

    /// **修复轮 1/5，评审复现的 Critical，已实测确认并修**：建隧道、
    /// **不断开客户端**、直接 `srv.shutdown()`——评审的复现步骤原样照抄。
    ///
    /// 根因：`russh::server::run_stream` 内部用
    /// `russh_util::runtime::spawn`（裸 `tokio::spawn`）另起一个任务去跑
    /// 真正的消息循环，那个任务才持有 `ConnHandler`/`TunnelGuard`；它的
    /// `RunningSession::join` 是 `russh_util` 自己的 `JoinHandle`——内部
    /// 只是一个 `oneshot::Receiver`，**没有 `abort()`**。旧的
    /// `Running::shutdown()` 只 `abort()` 了 accept 循环这层 wrapper，
    /// 摸不到那个内部任务：客户端不主动断开，服务端这边就永远不会真的
    /// 关闭这条会话，隧道端口永远不会被释放。
    ///
    /// 见 `Running::shutdown()` 与 `Shared.connections` 上的长注释——修法
    /// 是维护一张"连接 → Handle"的注册表，`shutdown()` 先挨个发
    /// `disconnect`，让内部任务自己走`dispatch_msg` → `disconnected =
    /// true` → 循环退出这条路收尾，再摘 accept 循环。
    ///
    /// 改红：把 `Running::shutdown()` 里"挨个发 disconnect"那段循环删掉
    /// ——这条测试在 bind 那一步红（端口还被占着）。
    #[tokio::test]
    async fn shutdown_disconnects_live_sessions_and_frees_tunnel_ports() {
        let (srv, pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect_echo(srv.local_addr())).await;
        assert!(s
            .authenticate_password("zhang", pw.as_str())
            .await
            .unwrap()
            .success());
        let port = s.tcpip_forward("", 0).await.unwrap() as u16;
        // 注意：不调用 s.disconnect(...)——评审复现的正是"客户端不主动
        // 断开"这条路。
        srv.shutdown().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let l = tokio::net::TcpListener::bind(("127.0.0.1", port)).await;
        assert!(l.is_ok(), "shutdown 之后端口应当被释放：{:?}", l.err());
    }

    /// 来源白名单：不在名单里的工程师连接被直接关掉，客户端根本收不到通道。
    /// 改红：`reverse_accept_loop` 里那道 `if !crate::cidr::allowed(...)`
    /// 判断短路成永假（实测：`应当被立刻关掉: Elapsed(())`，读超时 panic，
    /// 见 task-5-report.md）。
    #[tokio::test]
    async fn engineer_allow_list_filters_sources() {
        use tokio::io::AsyncReadExt;
        let (srv, pw, _tmp) =
            server_with_account_and_allow("zhang", vec![Cidr::parse("10.0.0.0/8").unwrap()]).await;
        let mut s = within("connect", ssh_connect_echo(srv.local_addr())).await;
        assert!(s
            .authenticate_password("zhang", pw.as_str())
            .await
            .unwrap()
            .success());
        let port = s.tcpip_forward("", 0).await.unwrap() as u16;
        let mut eng = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), eng.read(&mut buf))
            .await
            .expect("应当被立刻关掉")
            .unwrap_or(0);
        assert_eq!(n, 0);
        srv.shutdown().await;
    }

    /// 每条隧道最多 N 条工程师连接。改红：`engineers.fetch_add` 那句比较删掉。
    #[tokio::test]
    async fn at_most_n_engineers_per_tunnel() {
        use tokio::io::AsyncReadExt;
        let (srv, pw, _tmp) = server_with_account_and_timings(
            "zhang",
            Timings {
                max_engineers_per_tunnel: 2,
                ..Timings::fast()
            },
        )
        .await;
        let mut s = within("connect", ssh_connect_echo(srv.local_addr())).await;
        assert!(s
            .authenticate_password("zhang", pw.as_str())
            .await
            .unwrap()
            .success());
        let port = s.tcpip_forward("", 0).await.unwrap() as u16;
        let _a = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let _b = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf))
            .await
            .expect("第三条应当被关掉")
            .unwrap_or(0);
        assert_eq!(n, 0);
        assert_eq!(srv.tunnels_snapshot()[0].3, 2);
        srv.shutdown().await;
    }
}
