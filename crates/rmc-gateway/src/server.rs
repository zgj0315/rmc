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
use crate::datadir::DataDir;
use crate::identity::Identity;
use crate::{Error, Result};
use rmc_core::code::{AccountName, ServerFingerprint};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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
}

/// **偏离 brief 字面的 Step 2**：brief 的伪代码里 `Shared` 还有 `identity`
/// 与 `reverse_bind` 两个字段。本任务用不上它们——`identity` 在 `bind()`
/// 里派生出 `tls`/`ssh` 之后就没有别的读者，`reverse_bind` 要等 Task 5
/// 实现反向转发、真的去 `bind` 那个地址时才有读者。控制者在「给后面三个
/// 任务留好接口形状」那节明确说了同一条原则（针对 `Running.shared`）：
/// 提前加没人读的字段，`clippy -D warnings` 的 `dead_code` 当场红。这里
/// 按同一原则处理：先不放这两个字段，Task 5 需要哪个就在那时候加哪个
/// ——`bind()` 里 `cfg` 整个都在手上，加字段仍然是一行的事。
pub(crate) struct Shared {
    pub tls: tokio_rustls::TlsAcceptor,
    pub ssh: Arc<russh::server::Config>,
    pub accounts: AccountReader,
    pub timings: Timings,
}

pub struct Server;

pub struct Running {
    local_addr: SocketAddr,
    fingerprint: ServerFingerprint,
    stop: watch::Sender<bool>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl Running {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    pub fn fingerprint(&self) -> ServerFingerprint {
        self.fingerprint
    }
    pub async fn shutdown(self) {
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
        // 建好之后立刻 clone 进 accept 任务，不要整个 move：Task 5/6/7 都要
        // 从 `Running` 上再拿一份 `Arc<Shared>`（快照、吊销扫描、发布状态），
        // 到时候往 `Running` 里加一个 `shared: Arc<Shared>` 字段就是一行的事。
        let shared = Arc::new(Shared {
            tls,
            ssh,
            accounts: AccountReader::new(&cfg.data),
            timings: cfg.timings.clone(),
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
    };
    let running = tokio::select! {
        r = russh::server::run_stream(shared.ssh.clone(), tls, handler) => match r {
            Ok(s) => s,
            Err(e) => { tracing::debug!(%peer, error = %e, "SSH 握手失败"); return; }
        },
        _ = &mut deadline => { tracing::info!(%peer, "SSH 握手超时"); return; }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::AccountStore;
    use crate::config::GatewayConfig;
    use crate::datadir::DataDir;
    use crate::identity::Identity;
    use crate::testing_verifier::ssh_connect;
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
        server_with_account_and_timings(name, Timings::fast()).await
    }

    async fn server_with_account_and_timings(
        name: &str,
        timings: Timings,
    ) -> (Running, zeroize::Zeroizing<String>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let d = DataDir::at(tmp.path().to_path_buf());
        d.create().unwrap();
        Identity::create_in(&d).unwrap();
        let mut cfg = GatewayConfig::new("127.0.0.1:22000".parse().unwrap());
        // 区间给到几乎整个 u16 空间：账号端口本身不是本任务的服务端会去
        // bind 的东西（Task 5 才实现反向转发），这里只是要账号表能接受
        // 操作系统探出来的任何临时端口号。
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
        // 本任务还没实现反向转发，也必须被拒（Task 5 才开这一条路）
        assert!(s.tcpip_forward("", 0).await.is_err());
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
    #[tokio::test]
    async fn three_failures_end_the_connection() {
        let (srv, _pw, _tmp) = server_with_account("zhang").await;
        let mut s = within("connect", ssh_connect(srv.local_addr())).await;
        for n in 1..=3 {
            let r = within("第几次认证", s.authenticate_password("zhang", "wrong")).await;
            assert!(
                r.map(|a| !a.success()).unwrap_or(true),
                "第 {n} 次应当是普通的认证失败，不是连接错误"
            );
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
    /// **防 flake 提醒（控制者订正）**：`is_closed()` 变成 true 依赖服务端
    /// 断开后客户端会话循环结束、handle 的通道关闭，中间有调度延迟；500ms
    /// 的 deadline + 900ms 的等待留了 400ms 余量。万一 flake，加长等待，
    /// 不要缩短 deadline——deadline 是被测对象，等待只是观测手段。
    #[tokio::test]
    async fn tls_ok_but_no_auth_is_also_closed_at_the_deadline() {
        let (srv, _pw, _tmp) = server_with_account_and_timings(
            "zhang",
            Timings {
                handshake: Duration::from_millis(500),
                ..Timings::fast()
            },
        )
        .await;
        let s = within("connect", ssh_connect(srv.local_addr())).await;
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(s.is_closed(), "500ms 没认证，服务端该断开");
        srv.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_stops_accepting() {
        let (srv, _pw, _tmp) = server_with_account("zhang").await;
        let addr = srv.local_addr();
        srv.shutdown().await;
        assert!(tokio::net::TcpStream::connect(addr).await.is_err());
    }
}
