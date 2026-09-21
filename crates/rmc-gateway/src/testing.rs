//! 进程内端到端夹具：一台真的运维服务器、一台假一体机、一个假工程师。
//!
//! Task 12 用这三样把原来那套 docker 集成测试（`gateway/test-env` 的
//! compose + sshd + haproxy）整个替掉。替换的理由不是"docker 慢"，而是
//! **那套夹具从来没有被任何 CI 真的跑过**：`core.yml` 的 `integration`
//! job 要先 `docker compose up`，而它守的那 17 条用例全挂着
//! `#[ignore]`；`gateway.yml` 的 paths 过滤器又从不覆盖 `crates/**`。
//! 这里的东西不需要任何外部进程，所以它们跑在**每一次** `cargo test`
//! 里——这才是它们存在的意义。
//!
//! # 这个模块只在 `feature = "testing"` 下编译
//!
//! `Cargo.toml` 的 `[dev-dependencies]` 有一条 crate 自引用
//! （`rmc-gateway = { path = ".", features = ["testing"] }`），所以
//! `tests/*.rs` 里 `use rmc_gateway::testing::…` 不需要在命令行上带
//! `--features testing`；而 `cargo build --release` 根本不解析
//! dev-dependencies，这个模块不会进发布二进制。`tests/e2e.rs` 的
//! `the_testing_fixtures_are_linked_without_a_feature_flag_on_the_command_line`
//! 钉住前半句（Ruling R7 要的那一步自证：动手写 `TestGateway` 之前，
//! 先确认这条链接真的成立）。

use crate::accounts::AccountStore;
use crate::cidr::Cidr;
use crate::config::GatewayConfig;
use crate::datadir::DataDir;
use crate::identity::Identity;
use crate::server::{Running, Server, ServerConfig, Timings};
use crate::throttle::Limits;
use rmc_core::code::{AccountName, ConnectionCode, ServerFingerprint};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::watch;
use zeroize::Zeroizing;

/// 假一体机认的那一个账号与口令。端到端用例里工程师就是拿这一对登录
/// 假一体机的（`engineer_exec`），跟运维服务器自己的账号口令是两回事。
pub const APPLIANCE_USER: &str = "root";
pub const APPLIANCE_PASSWORD: &str = "appliance-pw";

// ------------------------------------------------------------ TestGateway

/// 一台真的跑起来的运维服务器：真 TCP 监听、真 TLS 1.3、真 russh 服务端、
/// 真 argon2、真审计日志、真 `status.json`。跟 `src/server.rs` 自己
/// `mod tests` 里的 `server_with_account` 是同一个形状，区别只是这份是
/// `pub`、给 `tests/e2e.rs` 用的。
///
/// # 为什么它自己持有 `TempDir`，而 [`Self::shutdown`] 把它**还出去**
///
/// 这是 brief 留的三条出路里的 (a)。要紧的是 `tests/e2e.rs` 里那条
/// "服务端重启之后 supervisor 用留着的凭据重连成功"——凭据里是一条连接
/// 码，连接码里钉着**指纹**，指纹是从数据目录里那把 ed25519 种子派生的。
/// 所以重启必须落回**同一个数据目录**，否则新身份 = 新指纹，客户端会以
/// `TlsPinMismatch` 拒连，那条测试就会验成"重连失败"——跟它名字说的
/// 恰好相反，而且是一条稳定绿着的假绿。
///
/// 如果 `shutdown(self)` 只是把 `TempDir` 一起 drop 掉，那一刻身份种子
/// 连同账号表一起被删，`start_on` 回去就是一台全新的机器。选 (a) 而不是
/// (b)（调用方全程持有）或 (c)（另给一个不消费 `self` 的 `stop_serving`）
/// 的理由：**(a) 把这条约束搬进了类型**。想重启就必须接住
/// `shutdown()` 还回来的那个 `TempDir` 再交给 `start_on`——写不出
/// "重启到一个新身份上"这种错，因为 `start_on` 根本没有第二条造数据目录
/// 的路。(b) 做得到同样的事，但它把"记得把同一个 dir 传回去"留成了
/// 调用方的纪律；(c) 更糟，`shutdown(self)` 与 `stop_serving(&self)`
/// 两个方法语义相近、后果差很远，下一个人照着 `shutdown` 写重启测试
/// 会静默踩坑。
///
/// 不重启的用例照常 `gw.shutdown().await;` —— 还回来的 `TempDir` 当场
/// 被丢弃，目录跟以前一样被删干净，不留垃圾。**没有**用
/// `into_path()`/`mem::forget` 泄漏目录这种绕法。
pub struct TestGateway {
    running: Running,
    dir: TempDir,
    data: DataDir,
    /// **内存里的**配置：`public_addr` 在 `bind` 拿到真实端口之后被改写成
    /// 那个地址，磁盘上那份不动（磁盘那份只是为了让 `GatewayConfig::load`
    /// 在 `start_on` 重启时还读得到反向端口区间）。连接码在内存里生成。
    cfg: GatewayConfig,
}

impl TestGateway {
    /// `Timings::fast()` + `Limits::default()` + 不设来源白名单，
    /// 监听 `127.0.0.1:0`（端口由操作系统挑）。
    pub async fn start() -> Self {
        Self::start_with(Timings::fast(), Limits::default(), Vec::new()).await
    }

    pub async fn start_with(timings: Timings, limits: Limits, allow: Vec<Cidr>) -> Self {
        let dir = tempfile::tempdir().expect("建临时数据目录");
        let data = DataDir::at(dir.path().to_path_buf());
        data.create().expect("建数据目录");
        Identity::create_in(&data).expect("生成身份密钥");
        // 先占位：真实监听端口要等 `bind` 之后才知道，下面 `boot` 会把它
        // 改回内存里这份 `cfg`。端口写 1 而不是 0——`GatewayConfig::validate`
        // 拒绝端口 0。
        let mut cfg = GatewayConfig::new("127.0.0.1:1".parse().expect("字面量"));
        // 反向端口区间放到几乎整个 u16 空间：`add_account` 是靠
        // "bind 0 拿一个操作系统给的空闲端口"来挑号的，而 macOS 的临时
        // 端口范围会给到 60000 以上（`server.rs` 的测试夹具实测栽过一次，
        // 见那里的注释）。区间卡死在 22001-22999 会让挑号稳定失败。
        cfg.reverse_port_min = 1;
        cfg.reverse_port_max = 65535;
        cfg.save(&data).expect("写 config.toml");
        Self::boot(listen_any_port(), dir, data, cfg, timings, limits, allow).await
    }

    /// 重启到**同一个地址**、**同一个数据目录**。两样都收，理由见类型上的
    /// 说明：地址不复用则客户端拨不回来，目录不复用则指纹变了、客户端会
    /// 以 `TlsPinMismatch` 拒连。
    pub async fn start_on(listen: SocketAddr, dir: TempDir) -> Self {
        let data = DataDir::at(dir.path().to_path_buf());
        let cfg = GatewayConfig::load(&data)
            .expect("重启到的数据目录里应该已经有 config.toml——它是上一次 start 写的");
        Self::boot(
            listen,
            dir,
            data,
            cfg,
            Timings::fast(),
            Limits::default(),
            Vec::new(),
        )
        .await
    }

    async fn boot(
        listen: SocketAddr,
        dir: TempDir,
        data: DataDir,
        mut cfg: GatewayConfig,
        timings: Timings,
        limits: Limits,
        engineer_allow: Vec<Cidr>,
    ) -> Self {
        let running = Server::bind(ServerConfig {
            listen,
            data: data.clone(),
            reverse_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            timings,
            engineer_allow,
            limits,
        })
        .await
        .expect("运维服务器没能起来");
        // 只改内存里这份，不重写 config.toml：连接码在内存里生成，磁盘上
        // 那份的 `public_addr` 是什么无关紧要（`start_on` 只从它读端口区间）。
        cfg.public_addr = running.local_addr();
        Self {
            running,
            dir,
            data,
            cfg,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.running.local_addr()
    }

    pub fn fingerprint(&self) -> ServerFingerprint {
        self.running.fingerprint()
    }

    /// 底下那台真服务器，给需要看服务端内部状态的用例用
    /// （`tunnels_snapshot`、`connections_count`、`audit_path_today`）。
    pub fn running(&self) -> &Running {
        &self.running
    }

    pub fn data_dir(&self) -> &DataDir {
        &self.data
    }

    /// 建一个账号，返回它的连接码与一次性口令。
    ///
    /// 反向端口是"bind `127.0.0.1:0` 拿一个空闲号再 drop"探出来的，这是
    /// TOCTOU——从 drop 到 `store.add` 真正用上它之间，这个号理论上会被
    /// 别人抢走。按 `server.rs` 测试夹具里已经定过的办法处理：**重试，
    /// 不改产生端口的方式**，最多 5 次。
    pub fn add_account(&self, name: &str) -> (ConnectionCode, Zeroizing<String>) {
        let name = AccountName::parse(name).expect("测试里的账号名应当合法");
        let store = AccountStore::open(&self.data, &self.cfg, self.addr().port());
        // 改红（实测过）：把 `accounts.rs` 里
        // `            if file.accounts.iter().any(|a| &a.name == name) {`
        // 换成 `            if true {`（`store.add` 稳定失败），下面这个
        // panic 的文案现在说得出真正的原因：
        // ```text
        // 给账号 zhang 挑反向端口试了 5 次都没成；最后一次的失败是：
        // 端口 57224：账号库：账号 zhang 已存在（吊销过的账号名不能复用，换一个名字）
        // ```
        // 上一版同样的注入只会报一句"5 次都没探到一个能用的反向端口"。
        //
        // 修复轮 1/5（复审 R12-8）：上一版是 `(0..5).find_map(...).expect(
        // "5 次都没探到一个能用的反向端口")`——它把 `store.add` 的**每一种**
        // 失败都吞掉：账号重名、账号表 TOML 损坏、磁盘满、数据目录没权限，
        // 一律被报成「端口探测失败」。重试机制本身是对的（挑号是 TOCTOU，
        // 见下面），但诊断不该被它吃掉。现在把最后一次的 `Err` 原文带进
        // panic 文案，重试几次也照样说得清到底败在哪。
        let mut last_err: Option<String> = None;
        let mut pw = None;
        for _ in 0..5 {
            let free = match std::net::TcpListener::bind("127.0.0.1:0")
                .and_then(|l| l.local_addr().map(|a| a.port()))
            {
                Ok(p) => p,
                Err(e) => {
                    last_err = Some(format!("探空闲端口失败：{e}"));
                    continue;
                }
            };
            match store.add(&name, Some(free), "") {
                Ok((_, p)) => {
                    pw = Some(p);
                    break;
                }
                Err(e) => last_err = Some(format!("端口 {free}：{e}")),
            }
        }
        let pw = pw.unwrap_or_else(|| {
            panic!(
                "给账号 {name} 挑反向端口试了 5 次都没成；最后一次的失败是：{}",
                last_err
                    .as_deref()
                    .unwrap_or("（没记到错误，这本身就不正常）")
            )
        });
        // `.expect`：`addr()` 是 `TcpListener::local_addr()` 的返回值，
        // 一个真的绑上了的监听地址端口不可能是 0，而 `ConnectionCode::new`
        // 只在端口为 0 时才拒绝。
        let code = ConnectionCode::new(
            name,
            self.addr().ip(),
            self.addr().port(),
            self.fingerprint(),
        )
        .expect("监听地址的端口不可能是 0");
        (code, pw)
    }

    /// 某个账号分配到的反向端口。端到端用例拿它跟服务端回填给客户端的
    /// `TunnelMsg::ForwardRegistered { port }` 对。
    pub fn account_port(&self, name: &str) -> u16 {
        let store = AccountStore::open(&self.data, &self.cfg, self.addr().port());
        store
            .list()
            .expect("读账号表")
            .into_iter()
            .find(|a| a.name.as_str() == name)
            .unwrap_or_else(|| panic!("账号表里没有 {name}"))
            .port
    }

    pub fn revoke(&self, name: &str) {
        let name = AccountName::parse(name).expect("测试里的账号名应当合法");
        let store = AccountStore::open(&self.data, &self.cfg, self.addr().port());
        store.revoke(&name).expect("吊销失败");
    }

    /// 今天这一份审计日志的全文。文件还不存在时返回空串——"一个事件都
    /// 没记过"与"记了但没有我要找的那一行"在调用方看来是同一件事。
    pub fn audit_text(&self) -> String {
        std::fs::read_to_string(self.running.audit_path_today()).unwrap_or_default()
    }

    /// 停服务，把数据目录的所有权还给调用方——接住它就能
    /// [`Self::start_on`] 回同一个身份，丢掉它目录就被删干净。
    pub async fn shutdown(self) -> TempDir {
        self.running.shutdown().await;
        self.dir
    }
}

fn listen_any_port() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

// ----------------------------------------------------------- FakeAppliance

/// 假一体机：一个最小的 russh 服务端，认 `root`/[`APPLIANCE_PASSWORD`]，
/// 对任何 `exec` 回一行 `ok:<命令>\n` 然后 exit 0，别的请求一概不实现
/// （russh 的默认行为就是拒绝）。
///
/// 它存在的理由是端到端链路的最后一跳：工程师 → 运维服务器反向端口 →
/// 现场客户端 → **这里**。`engineer_exec` 拿到 `ok:uptime\n` 这七个字节，
/// 就证明字节真的从工程师那一端流到了一体机这一端再流回来——这是
/// "e2e 真的连上了"唯一不可伪造的证据。
pub struct FakeAppliance {
    addr: SocketAddr,
    fingerprint: String,
    stop: watch::Sender<bool>,
    accept_task: tokio::task::JoinHandle<()>,
}

struct ApplianceHandler;

impl russh::server::Handler for ApplianceHandler {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        pw: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        Ok(if user == APPLIANCE_USER && pw == APPLIANCE_PASSWORD {
            russh::server::Auth::Accept
        } else {
            russh::server::Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        // `session.data` 收 `impl Into<bytes::Bytes>`，`Vec<u8>` 就满足——
        // 不为这一行给 rmc-gateway 新加一个 `bytes` 依赖。
        let reply = format!("ok:{}\n", String::from_utf8_lossy(data)).into_bytes();
        session.data(channel, reply)?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

impl FakeAppliance {
    /// **只监听 `127.0.0.1:0`，永远不绑别的地址。**
    ///
    /// 修复轮 1/5（复审 R12-4）：上一版为了让走 `Command::Start` 的那两条
    /// 用例过得了「一体机不能是本机回环」那道校验，提供过一个
    /// `start_at(ip)` 并在那两条里传 `0.0.0.0`——于是测试跑的那几秒里，
    /// 一台认 `root`/`appliance-pw`、任何 `exec` 都照回 `ok:<命令>` 的
    /// SSH 服务端对**整个局域网**可见。在共享的 CI runner 上这是一个不该
    /// 存在的暴露面，而且它对测试本身一点用都没有。
    ///
    /// 现在的做法：监听**只**绑回环，客户端那一侧仍然拨 `0.0.0.0`
    /// ——`0.0.0.0` 在 `HostPort::is_loopback()` 眼里不是回环写法（过得了
    /// 校验），而内核会把「连到 INADDR_ANY」落到本机上，于是字节实际走的
    /// 就是回环。实测取到的服务端 accept 到的对端地址是 `127.0.0.1:…`，
    /// 见 [`non_loopback_self_ip`] 的文档。暴露面整个消失，别的一个字没改。
    pub async fn start() -> Self {
        Self::start_at(IpAddr::V4(Ipv4Addr::LOCALHOST)).await
    }

    async fn start_at(ip: IpAddr) -> Self {
        // host key 走跟 `Identity` 同一条路。**不要**用
        // `PrivateKey::random(&mut rand::rngs::OsRng, ...)`：`ssh-key`
        // 那个 `random` 要 `rand_core` 0.10 的 `CryptoRng`，本 workspace
        // 的 `rand` 是 0.8（rand_core 0.6），版本对不上，编不过。
        let seed: [u8; 32] = rand::random();
        let kp = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
        let host_key = russh::keys::PrivateKey::from(kp);
        // 借用坑（GLOBAL 教训第 6 条）：`public_key()` 返回的是拥有值，
        // 一行链下去会 E0716，先 `let` 住。
        let pk = host_key.public_key();
        let blob = {
            use russh::keys::PublicKeyBase64;
            pk.public_key_bytes()
        };
        let fingerprint = rmc_core::knownhosts::fingerprint_of(&blob)
            .as_str()
            .to_string();

        let cfg = Arc::new(russh::server::Config {
            keys: vec![host_key],
            methods: russh::MethodSet::from(&[russh::MethodKind::Password][..]),
            inactivity_timeout: None,
            nodelay: true,
            ..Default::default()
        });
        let listener = tokio::net::TcpListener::bind((ip, 0))
            .await
            .unwrap_or_else(|e| panic!("假一体机绑 {ip}:0 失败：{e}"));
        let addr = listener.local_addr().expect("刚绑上的监听地址");
        let (stop, mut stop_rx) = watch::channel(false);
        let accept_task = tokio::spawn(async move {
            let mut conns = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    accepted = listener.accept() => match accepted {
                        Ok((sock, _peer)) => {
                            let cfg = cfg.clone();
                            conns.spawn(async move {
                                if let Ok(running) =
                                    russh::server::run_stream(cfg, sock, ApplianceHandler).await
                                {
                                    let _ = running.await;
                                }
                            });
                        }
                        Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
                    },
                    Some(_) = conns.join_next(), if !conns.is_empty() => {}
                }
            }
            conns.abort_all();
            // `listener` 在这里随作用域丢弃，端口才真的释放——`stop()`
            // 等的就是这一刻。
        });
        Self {
            addr,
            fingerprint,
            stop,
            accept_task,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// OpenSSH 风格的 `SHA256:…`，跟 `rmc_core::preflight` 第二步
    /// （"一体机 host key 指纹"）的 detail 逐字符可比。
    pub fn fingerprint_sha256(&self) -> String {
        self.fingerprint.clone()
    }

    /// 拆掉监听，用来模拟"一体机不可达"。
    ///
    /// **偏离 brief 字面**：brief 把它写成同步的 `stop(self)`。这里是
    /// `async`，而且**等 accept 任务真的退出**才返回——只发一个 watch
    /// 信号就返回的话，`listener` 还没被丢弃、端口还听着，紧接着的
    /// "现在它不可达了"那条断言就会在一个竞态窗口上跑，偶发地验反。
    pub async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.accept_task.await;
    }
}

// ---------------------------------------------------------- engineer_exec

/// 假工程师：对着运维服务器的**反向端口**（明文 TCP，不是 TLS——TLS 只
/// 在现场客户端拨进来的那一跳上）建一条 SSH 连接，登录假一体机，跑一条
/// `exec`，把输出收回来。
///
/// 返回 `Err` 的每一条都带上下文，因为这个函数的失败在端到端用例里是
/// 主要的诊断来源：一条只说 "failed" 的错误会让"到底断在哪一跳"要靠猜。
pub async fn engineer_exec(
    ip: IpAddr,
    port: u16,
    password: &str,
    cmd: &str,
) -> Result<String, String> {
    struct AnyHostKey;
    impl russh::client::Handler for AnyHostKey {
        type Error = russh::Error;
        async fn check_server_key(
            &mut self,
            _k: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            // 工程师这一跳不在本项目的指纹钉扣范围内（钉扣管的是现场
            // 客户端 → 运维服务器那一跳）。这里只要能握上手。
            Ok(true)
        }
    }

    let cfg = Arc::new(russh::client::Config {
        inactivity_timeout: None,
        ..Default::default()
    });
    let mut session = russh::client::connect(cfg, (ip, port), AnyHostKey)
        .await
        .map_err(|e| format!("连不上反向端口 {ip}:{port}：{e}"))?;
    let ok = session
        .authenticate_password(APPLIANCE_USER, password)
        .await
        .map_err(|e| format!("对假一体机认证出错：{e}"))?;
    if !ok.success() {
        return Err("假一体机拒绝了这个口令".to_string());
    }
    let mut ch = session
        .channel_open_session()
        .await
        .map_err(|e| format!("开 session 通道失败：{e}"))?;
    ch.exec(true, cmd)
        .await
        .map_err(|e| format!("exec {cmd:?} 失败：{e}"))?;
    let mut out: Vec<u8> = Vec::new();
    while let Some(msg) = ch.wait().await {
        match msg {
            russh::ChannelMsg::Data { data } => out.extend_from_slice(&data),
            russh::ChannelMsg::ExitStatus { .. }
            | russh::ChannelMsg::Eof
            | russh::ChannelMsg::Close => break,
            _ => {}
        }
    }
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await;
    String::from_utf8(out).map_err(|e| format!("一体机回的不是 UTF-8：{e}"))
}

// ------------------------------------------------- 非回环的本机可达地址

/// 一个**在 `HostPort::is_loopback()` 眼里不是回环写法、但拨过去真的能打到
/// 本机回环监听**的地址。今天它就是 `0.0.0.0`，而且是探测核实过的那一个。
///
/// # 为什么需要这么一个别扭的东西
///
/// `rmc_core::config::validate_addresses` 拒绝"一体机地址指向本机回环"
/// （方案 §3.1：一体机在客户内网、运维服务器在公网，两者永不重合），
/// 而它是公开的 `Command::Start` 的必经之路——`ValidatedAddresses::for_test`
/// 那条旁路是 `#[cfg(test)] pub(crate)`，`tests/e2e.rs` 是外部 crate，
/// 看不见它。于是走 `Supervisor` 的那两条端到端用例没法把一体机地址**写成**
/// `127.0.0.1`。（不走 supervisor 的用例直接调 `SshTunnelFactory`，不经过
/// 这道校验，照常用 `127.0.0.1`。）
///
/// # 字节其实走的是回环——这里绕开的只是那道**输入校验**
///
/// 修复轮 1/5（复审 R12-4）订正了上一版的做法。要分清两件事：
///
/// - **`0.0.0.0` 只是写给 `ValidatedAddresses::validate` 看的那个字符串。**
///   `Ipv4Addr::UNSPECIFIED.to_canonical().is_loopback()` 是 `false`，所以
///   它过得了那道「一体机不能是本机回环」的校验。这道校验防的是"把隧道接回
///   客户端自己身上"这类**配置错误**，它看的是地址的**书写形式**
///   （`is_loopback` 的文档自己写明了这一点：纯字符串/数值判断，不做解析）。
/// - **真正的数据路径仍然是回环。** [`FakeAppliance`] 只绑 `127.0.0.1`；
///   内核把"连到 INADDR_ANY"落到本机，连接就打在那个回环监听上。
///   实测（探针原文记在 task-12-fix-1-report.md）：拨 `0.0.0.0:56642`，
///   只绑 `127.0.0.1` 的那个监听 accept 到的对端是 `127.0.0.1:56643`。
///
/// 所以这里**没有**把任何东西暴露到局域网上。上一版是真暴露过——它让假
/// 一体机自己去绑 `0.0.0.0`，那台认 `root`/`appliance-pw`、任何 `exec`
/// 都照回 `ok:<命令>` 的 SSH 服务端在测试期间对整个局域网可见。
///
/// # 为什么是"探测 + 核实"，不是直接写死一个地址
///
/// 探测本身就是证据，不需要相信任何一条关于"这台机器的网络长什么样"的假设。
/// 这不是洁癖：第一版打算用"UDP socket connect 到一个外部地址、读回本地
/// IP"这个常见技巧当候选，**在开发这台机器上当场被证伪**——它返回
/// `198.18.0.1`（一条 VPN 的 utun 地址），bind 上去成功、connect 却永远挂着。
///
/// # 为什么候选只剩一个（复审 R12-4 的第二半，如实订正）
///
/// 复审要求把"第二候选（UDP 探出的网卡地址）是 Windows 兜底、在这台机器上
/// 从没被验证过"写进文档。照做的时候发现一件更要紧的事：**换成"监听只绑
/// 回环"之后，那个候选在任何平台上都不可能成立**，不只是"Linux/macOS 上
/// 执行不到"。理由是纯粹的：监听只在 `127.0.0.1` 上，拨网卡地址的包不会
/// 落到它身上，连接必然被拒——跟操作系统无关。实测也是这个结果（拨
/// `198.18.0.1:<回环监听的端口>` 挂死，30 秒 alarm 杀掉）。
///
/// 留着一个**注定过不了自己那道核实**的候选，只会让读代码的人以为
/// Windows 上有兜底。所以删掉了，并把话说清楚：
///
/// **如果哪天 Windows 上 `0.0.0.0` 这个候选真的探不通**，这个函数会
/// panic，panic 文案里写明了该怎么办。不要退回"让假一体机去绑网卡地址"
/// ——那是把 R12-4 修掉的暴露面又加回来。
///
/// 一个候选都不通时 **panic，不是静默跳过**：一条"环境不满足就悄悄不验"
/// 的测试，跟一条假绿的区别只在措辞上。
pub async fn non_loopback_self_ip() -> IpAddr {
    let candidate = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    if reaches_a_loopback_listener(candidate).await {
        return candidate;
    }
    panic!(
        "拨 {candidate} 打不到一个只绑 127.0.0.1 的监听，这台机器上没有可用的\
         「不是回环写法、又真的能连到本机」的地址。走 Supervisor 的那两条端到端\
         用例需要它，因为 Command::Start 会拒绝写成回环的一体机地址。\n\
         要修的话：给这台机器的 hosts 加一个解析到 127.0.0.1 的名字（`is_loopback`\
         只特判字面量 `localhost`），或者在 rmc-core 里给测试开一条受控的旁路。\n\
         **不要**改成让 FakeAppliance 去绑网卡地址——那会把一台认得出口令的\
         SSH 服务端暴露到局域网上，正是修复轮 1/5 的 R12-4 刚拆掉的东西。"
    );
}

/// 绑一个**只在回环上**的监听，从 `via` 这个地址拨过去，确认连得上而且
/// 服务端真的 accept 到了。两头都确认，少一头都可能是假信号。
async fn reaches_a_loopback_listener(via: IpAddr) -> bool {
    let Ok(listener) = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await else {
        return false;
    };
    let Ok(local) = listener.local_addr() else {
        return false;
    };
    let target = SocketAddr::new(via, local.port());
    let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
    let connected = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(target),
    )
    .await
    .is_ok_and(|r| r.is_ok());
    let accepted = tokio::time::timeout(Duration::from_secs(3), accept)
        .await
        .is_ok_and(|j| matches!(j, Ok(Ok(()))));
    connected && accepted
}
