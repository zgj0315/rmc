//! 进程内端到端：真客户端内核（rmc-core）↔ 真运维服务器（rmc-gateway）
//! ↔ 假一体机 ↔ 假工程师。替掉 `gateway/test-env` 那套 docker 夹具。
//!
//! # 这份文件里每一条都要能回答「它绿的时候，真的有字节流动过吗」
//!
//! 端到端测试最容易出的假绿是「测试自己没连上，但断言写成了 `is_err()`」。
//! 这里的做法是：**每一条否定断言都配一个同场的肯定对照**，或者建立在一次
//! 已经成功的连接之上。具体到每条用例：
//!
//! - 第 2 条（错指纹）不只断言 `is_err()`，还断言错误**恰好是**
//!   `TlsPinMismatch`（不是"连不上"那一类），并且在同一个夹具上用**对的**
//!   指纹再连一次、确认那次成功——错指纹那次的失败才有意义。
//! - 第 3 条（错口令）同样断言错误恰好是 `AuthRejected`，并且审计日志里
//!   真的多了一行 `auth_fail`。
//! - 第 9 条（一体机不可达）在同一条**仍然活着**的隧道上，先验证不可达
//!   会报 `ApplianceDialFailed`，再验证隧道本身还在（服务端隧道表里还有
//!   它、还能再接一个工程师）。
//! - 其余各条都以 `establish()` 返回 `Ok` 为前提——那意味着 TCP、TLS 1.3
//!   指纹钉扣、SSH KEX、host key 比对、argon2 口令认证、`tcpip-forward`
//!   端口回填这一整串真的逐一走完了。
//!
//! # 超时
//!
//! 这台机器没有 `timeout` 命令，CI 上卡死的代价是干等到 job 级超时。
//! 每一次可能挂住的 `.await` 都过 [`within`]，到点 panic 并说清是哪一步。

use rmc_core::addr::HostPort;
use rmc_core::backoff::{FixedJitter, Jitter};
use rmc_core::code::{AccountName, ConnectionCode, ServerFingerprint};
use rmc_core::error::{Error, ErrorClass};
use rmc_core::platform::{NoProxy, NoProxyAuth, NoSystemEvents};
use rmc_core::preflight::{self, StepOutcome, TransportPreflight, ALL_STEPS};
use rmc_core::ssh::SshTunnelFactory;
use rmc_core::state::{Command, State, TunnelEvent};
use rmc_core::supervisor::{Deps, Supervisor};
use rmc_core::transport::Transport;
use rmc_core::tunnel::{TunnelFactory, TunnelHandle, TunnelMsg, TunnelParams};
use rmc_gateway::testing::{
    engineer_exec, non_loopback_self_ip, FakeAppliance, TestGateway, APPLIANCE_PASSWORD,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::{broadcast, mpsc};
use zeroize::Zeroizing;

// ------------------------------------------------------------------ 夹具

const STEP_TIMEOUT: Duration = Duration::from_secs(30);

async fn within<T>(what: &str, f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(STEP_TIMEOUT, f)
        .await
        .unwrap_or_else(|_| panic!("{what} 超过 {STEP_TIMEOUT:?} 没有结果"))
}

fn transport() -> Arc<Transport> {
    Arc::new(Transport::new(Arc::new(NoProxy), Arc::new(NoProxyAuth)))
}

fn factory() -> SshTunnelFactory {
    SshTunnelFactory::new(transport())
}

fn params(code: &ConnectionCode, password: &str, appliance: SocketAddr) -> TunnelParams {
    TunnelParams {
        username: code.account().to_string(),
        password: Zeroizing::new(password.to_string()),
        gateway: code.server(),
        appliance: hostport(appliance),
        fingerprint: *code.fingerprint(),
    }
}

fn hostport(addr: SocketAddr) -> HostPort {
    HostPort::new(&addr.ip().to_string(), addr.port()).expect("真实监听地址必定合法")
}

/// 同一台服务器、同一个账号，但把连接码里的指纹换成另一把钥匙的。
/// 用在"指纹不符"那两条上——除了指纹，其它一切都是对的，所以失败只可能
/// 来自指纹比对本身。
fn with_other_fingerprint(code: &ConnectionCode) -> ConnectionCode {
    let other = ServerFingerprint::of_ed25519_public(&[7u8; 32]);
    assert_ne!(
        &other,
        code.fingerprint(),
        "夹具自检：换上的指纹必须真的跟服务器的不一样"
    );
    ConnectionCode::new(
        AccountName::parse(code.account().as_str()).expect("账号名来自一条合法连接码"),
        code.server().host().parse().expect("连接码里只放 IP"),
        code.server().port(),
        other,
    )
    .expect("端口来自一条合法连接码，不可能是 0")
}

/// `Box<dyn TunnelHandle>` 没有 `Debug`，`Result::expect_err` 用不了。
/// 顺手把「本该失败却连上了」这句话说清楚——一条端到端用例里，这正是
/// 最需要一眼看懂的那种失败。
fn expect_err(what: &str, r: rmc_core::error::Result<Box<dyn TunnelHandle>>) -> Error {
    match r {
        Ok(_) => panic!("{what}：本该连不上，却连上了"),
        Err(e) => e,
    }
}

async fn next_msg(rx: &mut mpsc::Receiver<TunnelMsg>) -> TunnelMsg {
    within("等下一条隧道消息", rx.recv())
        .await
        .expect("隧道消息通道提前关闭了——隧道已经没了")
}

/// 一直收，直到 `pred` 命中；把路上看到的全部返回（含命中的那一条）。
async fn msgs_until(
    rx: &mut mpsc::Receiver<TunnelMsg>,
    what: &str,
    pred: impl Fn(&TunnelMsg) -> bool,
) -> Vec<TunnelMsg> {
    let mut seen = Vec::new();
    within(what, async {
        loop {
            let m = rx
                .recv()
                .await
                .unwrap_or_else(|| panic!("等 {what} 的时候隧道消息通道关了，已经看到：{seen:?}"));
            let hit = pred(&m);
            seen.push(m);
            if hit {
                return;
            }
        }
    })
    .await;
    seen
}

async fn wait_state(
    rx: &mut broadcast::Receiver<TunnelEvent>,
    what: &str,
    pred: impl Fn(&State) -> bool,
) -> State {
    let mut seen: Vec<State> = Vec::new();
    within(what, async {
        loop {
            match rx.recv().await {
                Ok(TunnelEvent::State(s)) => {
                    if pred(&s) {
                        return s;
                    }
                    seen.push(s);
                }
                Ok(_) => {}
                Err(e) => panic!("等 {what} 时事件通道出错：{e}，路上看到：{seen:?}"),
            }
        }
    })
    .await
}

/// 一个"确实没人监听"的本机端口：绑一个、记下号、放掉，再回连一次确认
/// 真的被拒。不确认的话，这个号理论上会被别的并发测试立刻复用，"一体机
/// 不可达"那条就会在一台其实连得上的机器上跑，验的东西跟名字对不上。
async fn dead_port() -> SocketAddr {
    for _ in 0..10 {
        let Ok(l) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            continue;
        };
        let Ok(addr) = l.local_addr() else { continue };
        drop(l);
        let refused =
            tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr))
                .await
                .is_ok_and(|r| r.is_err());
        if refused {
            return addr;
        }
    }
    panic!("10 次都没找到一个确认拒绝连接的死端口");
}

fn no_jitter() -> Box<dyn Jitter> {
    Box::new(FixedJitter(1.0))
}

/// Supervisor 那两条用的 `Deps`：全部是真零件（真 SSH 工厂、真
/// `TransportPreflight`），只有系统事件与抖动换成确定性的占位实现。
///
/// **不声称这条链路验了 `Deps.events`**：`wiring.rs:1018` 附近记着一次
/// 真实事故——`events` 被换成一个新造的 `NoSystemEvents` 而 600 条测试
/// 全绿。这里用的就是 `NoSystemEvents`，它本来就什么都不产出，这两条
/// 用例对它没有任何观察能力。
fn real_deps() -> Deps {
    let transport = transport();
    Deps {
        factory: Arc::new(SshTunnelFactory::new(Arc::clone(&transport))),
        preflight: Arc::new(TransportPreflight::new(Arc::clone(&transport))),
        transport,
        events: Arc::new(NoSystemEvents::default()),
        jitter: no_jitter,
    }
}

fn supervisor_config(log_dir: &tempfile::TempDir) -> rmc_core::config::Config {
    rmc_core::config::Config {
        log_dir: log_dir.path().to_path_buf(),
        ..Default::default()
    }
}

// -------------------------------------------------------------- 0. 自证

/// Ruling R7 要求的第一步：`tests/` 这个独立 crate 真的链接得到
/// `rmc_gateway::testing`，而且**命令行上没有 `--features testing`**
/// （`Cargo.toml` 的 dev-dependency 自引用把它点亮了）。这条流水线最该
/// 防的形态就是「CI 里某一批测试静默不跑」——如果自引用那行被删掉，
/// 整个文件编译不过，不会是"安静地少跑十四条"。
///
/// 改红（实测过）：把 `crates/rmc-gateway/Cargo.toml` 里
/// `rmc-gateway = { path = ".", features = ["testing"] }` 注释掉：
/// ```text
/// error[E0432]: unresolved import `rmc_gateway::testing`
/// error: could not compile `rmc-gateway` (test "e2e") due to 1 previous error
/// ```
/// 这一枪顺带证明了后半句——`testing` 这个 feature **只**由这条
/// dev-dependency 点亮，没有别的地方开着它，所以不解析 dev-dependencies 的
/// `cargo build --release` 拿不到这个模块。
#[test]
fn the_testing_fixtures_are_linked_without_a_feature_flag_on_the_command_line() {
    assert_eq!(APPLIANCE_PASSWORD, "appliance-pw");
}

// ------------------------------------------------------------ 1. 建隧道

/// 改红（实测过）：`crates/rmc-gateway/src/server.rs` 的 `tcpip_forward`
/// 里 `        *port = u32::from(account_port);` 换成 `        *port = 0;`
/// （不回填）：
/// ```text
/// test establishes_reports_the_verified_fingerprint_and_the_server_assigned_port ... FAILED
/// panicked at crates/rmc-gateway/tests/e2e.rs
/// ```
/// ——客户端 `establish_over` 看到回填端口是 0 就直接失败，红在
/// `.expect("建隧道")` 上。
#[tokio::test]
async fn establishes_reports_the_verified_fingerprint_and_the_server_assigned_port() {
    let gw = TestGateway::start().await;
    let app = FakeAppliance::start().await;
    let (code, pw) = gw.add_account("zhang");
    let account_port = gw.account_port("zhang");

    let (tx, mut rx) = mpsc::channel(32);
    let handle = within(
        "建隧道",
        factory().establish(params(&code, &pw, app.addr()), tx),
    )
    .await
    .expect("建隧道");

    assert_eq!(
        next_msg(&mut rx).await,
        TunnelMsg::Authenticated {
            fingerprint: gw.fingerprint()
        },
        "第一条消息应该是「host key 与连接码里的指纹核对一致」"
    );
    assert_eq!(
        next_msg(&mut rx).await,
        TunnelMsg::ForwardRegistered { port: account_port },
        "反向端口必须是服务端按账号回填的那一个，客户端申请的是 0"
    );

    handle.shutdown().await;
    app.stop().await;
    gw.shutdown().await;
}

// --------------------------------------------------------- 2. 指纹不符

/// 连接码里那**一个**指纹同时钉 TLS 与 SSH host key，而 TLS 先握手——
/// 所以换错指纹时拿到的是 `TlsPinMismatch`，不是 `HostKeyMismatch`。
///
/// 口令根本没有机会被发出去：TLS 握手就没过，SSH 层压根没开始。服务端
/// 审计日志里因此既没有 `auth_ok` 也没有 `auth_fail`。
///
/// **这条否定断言不是空的**：同一台服务器上紧接着用**对的**指纹连一次，
/// 确认那次会留下 `auth_ok`——上面那条"没有 auth_ok"于是被证明是因为
/// 口令真的没送出去，而不是因为审计日志压根没在工作。
///
/// 改红（实测过）：`crates/rmc-core/src/transport/tls.rs` 里
/// `        if ServerFingerprint::of_ed25519_public(&pk) != self.want {`
/// 换成 `        if false {`（TLS 那一层不再核对指纹）：
/// ```text
/// panicked at crates/rmc-gateway/tests/e2e.rs:
/// 同一个指纹钉 TLS 与 SSH 两层，TLS 先握手，所以这里应该是 TlsPinMismatch，
/// 实际 HostKeyMismatch { expected: "S7Bvjk46...", actual: "hZdvtnpV..." }
/// ```
/// 这一枪顺带**实测证明了"TLS 先握手"这句话本身**：只要 TLS 那一层放行，
/// 握手就能推进到 SSH 层，错指纹才会以 `HostKeyMismatch` 的形态出现。
/// 两层都在核对同一个指纹，但顺序决定了工程师看到的是哪一条。
#[tokio::test]
async fn a_wrong_fingerprint_is_fatal_and_no_password_leaves_the_client() {
    let gw = TestGateway::start().await;
    let app = FakeAppliance::start().await;
    let (code, pw) = gw.add_account("zhang");

    let bad = with_other_fingerprint(&code);
    let (tx, _rx) = mpsc::channel(32);
    let err = expect_err(
        "指纹不符",
        within(
            "用错指纹建隧道",
            factory().establish(params(&bad, &pw, app.addr()), tx),
        )
        .await,
    );
    assert!(
        matches!(err, Error::TlsPinMismatch(_)),
        "同一个指纹钉 TLS 与 SSH 两层，TLS 先握手，所以这里应该是 TlsPinMismatch，实际 {err:?}"
    );
    assert_eq!(err.class(), ErrorClass::Fatal);

    let audit = gw.audit_text();
    assert!(
        audit.contains("server_start"),
        "夹具自检：审计日志得是活的，否则下面两条「没有」是空话。实际内容：{audit:?}"
    );
    assert!(
        !audit.contains("auth_ok"),
        "TLS 没握上，口令不可能送到服务端，实际：{audit}"
    );
    assert!(
        !audit.contains("auth_fail"),
        "TLS 没握上，服务端不该记录任何一次认证尝试，实际：{audit}"
    );

    // 肯定对照：同一台服务器、同一个账号、**对的**指纹——这次必须连上，
    // 并且必须留下 auth_ok。上面那两条「没有」由此才有意义。
    let (tx, _rx) = mpsc::channel(32);
    let handle = within(
        "用对的指纹建隧道",
        factory().establish(params(&code, &pw, app.addr()), tx),
    )
    .await
    .expect("对的指纹必须连得上");
    assert!(
        gw.audit_text().contains("auth_ok"),
        "对照组连上了，审计日志里就该有 auth_ok——没有说明这份日志根本没在记认证"
    );

    handle.shutdown().await;
    app.stop().await;
    gw.shutdown().await;
}

// --------------------------------------------------------- 3. 口令不对

/// 改红（实测过）：`crates/rmc-gateway/src/accounts.rs` 的
/// `pub fn verify_hash(pw: &str, phc: &str) -> bool {` 下面插进
/// `return true;`（口令一律算对）：
/// ```text
/// panicked at crates/rmc-gateway/tests/e2e.rs:
/// 口令不对：本该连不上，却连上了
/// ```
/// （第一版试的是"把 `server.rs` 里 `Verify::Rejected` 那一支改成
/// `Auth::Accept`"——那是个跨多行的 `match` 分支，单行注入改不动它而且
/// 会让大括号失配、编译不过。改钉 `verify_hash` 是同一条判定链上更靠内
/// 的一环，效果一样而且是干净的单行注入。）
#[tokio::test]
async fn a_wrong_password_is_auth_class_and_the_server_logs_auth_fail() {
    let gw = TestGateway::start().await;
    let app = FakeAppliance::start().await;
    let (code, _pw) = gw.add_account("zhang");

    const WRONG: &str = "definitely-not-the-generated-one";
    let (tx, _rx) = mpsc::channel(32);
    let err = expect_err(
        "口令不对",
        within(
            "用错口令建隧道",
            factory().establish(params(&code, WRONG, app.addr()), tx),
        )
        .await,
    );
    assert!(
        matches!(err, Error::AuthRejected),
        "错口令应该是 AuthRejected，实际 {err:?}"
    );
    assert_eq!(err.class(), ErrorClass::Auth);

    let audit = gw.audit_text();
    assert!(
        audit.contains("auth_fail"),
        "服务端必须记下这次认证失败，实际：{audit}"
    );
    assert!(
        !audit.contains(WRONG),
        "审计日志里绝不能出现口令，实际：{audit}"
    );

    app.stop().await;
    gw.shutdown().await;
}

// ------------------------------------------------ 4. 同账号第二条隧道

/// 改红（实测过）：`crates/rmc-gateway/src/server.rs` 的 `tcpip_forward`
/// 里 `            if t.contains_key(&account) {` 换成
/// `            if false {`（不再拦同账号的第二条）：
/// ```text
/// panicked at crates/rmc-gateway/tests/e2e.rs:
/// 同一账号的第二条隧道：本该连不上，却连上了
/// ```
/// 实测的连锁反应值得记一笔：第二次 `insert` **覆盖**了隧道表里第一条的
/// `TunnelInfo`，旧的 `watch::Sender` 随之被丢弃，第一条的
/// `reverse_accept_loop` 的 `stop.changed()` 分支立刻完成、退出循环、
/// 放掉监听——于是第二条那段"bind 短重试"顺利绑上了同一个端口。也就是
/// 说这道 `contains_key` 不只是"早一点拒绝"的优化，它是唯一挡住
/// **第二条隧道把第一条挤下线**的东西。
#[tokio::test]
async fn a_second_tunnel_for_the_same_account_is_port_busy() {
    let gw = TestGateway::start().await;
    let app = FakeAppliance::start().await;
    let (code, pw) = gw.add_account("zhang");

    let (tx, mut rx) = mpsc::channel(32);
    let first = within(
        "建第一条隧道",
        factory().establish(params(&code, &pw, app.addr()), tx),
    )
    .await
    .expect("第一条必须连上");
    // 等回填确认第一条真的把端口占住了，再去建第二条——否则第二条可能
    // 赶在第一条注册之前跑完，验的就不是"端口已被占"。
    msgs_until(&mut rx, "第一条隧道注册反向端口", |m| {
        matches!(m, TunnelMsg::ForwardRegistered { .. })
    })
    .await;

    let (tx2, _rx2) = mpsc::channel(32);
    let err = expect_err(
        "同一账号的第二条隧道",
        within(
            "建第二条隧道",
            factory().establish(params(&code, &pw, app.addr()), tx2),
        )
        .await,
    );
    assert!(
        matches!(err, Error::ForwardPortBusy),
        "应该是 ForwardPortBusy，实际 {err:?}"
    );
    assert_eq!(err.class(), ErrorClass::PortBusy);

    first.shutdown().await;
    app.stop().await;
    gw.shutdown().await;
}

// ------------------------------------------------------ 5. 工程师打通

/// 这是整条链路唯一不可伪造的证据：`ok:uptime\n` 这七个字节是假一体机
/// 造的，工程师从运维服务器的反向端口读到了它，说明字节真的走完了
/// 工程师 → 运维服务器 → 现场客户端 → 一体机 → 原路返回。
///
/// 改红（实测过）：`crates/rmc-gateway/src/server.rs` 的
/// `reverse_accept_loop` 里把
/// `let r = tokio::io::copy_bidirectional(&mut sock, &mut st).await;`
/// 换成 `let r = tokio::io::copy(&mut sock, &mut st).await.map(|n| (n, 0u64));`
/// （只转发工程师→客户端一个方向）：
/// ```text
/// panicked at crates/rmc-gateway/tests/e2e.rs:
/// 工程师 exec 超过 30s 没有结果
/// ```
/// 一体机的回包到不了工程师，`engineer_exec` 挂在 `ch.wait()` 上——正是
/// [`within`] 存在的理由：卡死时说清是哪一步，而不是干等 job 级超时。
#[tokio::test]
async fn engineer_command_reaches_the_appliance_through_the_reverse_port() {
    let gw = TestGateway::start().await;
    let app = FakeAppliance::start().await;
    let (code, pw) = gw.add_account("zhang");

    let (tx, mut rx) = mpsc::channel(32);
    let handle = within(
        "建隧道",
        factory().establish(params(&code, &pw, app.addr()), tx),
    )
    .await
    .expect("建隧道");
    let port = forwarded_port(&mut rx).await;

    let out = within(
        "工程师 exec",
        engineer_exec(gw.addr().ip(), port, APPLIANCE_PASSWORD, "uptime"),
    )
    .await
    .expect("工程师应当能经反向端口登录假一体机并执行命令");
    assert_eq!(out, "ok:uptime\n");

    handle.shutdown().await;
    app.stop().await;
    gw.shutdown().await;
}

async fn forwarded_port(rx: &mut mpsc::Receiver<TunnelMsg>) -> u16 {
    let seen = msgs_until(rx, "反向端口注册", |m| {
        matches!(m, TunnelMsg::ForwardRegistered { .. })
    })
    .await;
    match seen.last() {
        Some(TunnelMsg::ForwardRegistered { port }) => *port,
        other => panic!("等到的不是 ForwardRegistered：{other:?}"),
    }
}

// ------------------------------------------------ 6. 会话开/流量/关闭

/// 改红（实测过）：`crates/rmc-core/src/ssh/pump.rs` 里结束前那次补报的
/// `            to_appliance: to_appliance.load(Ordering::Relaxed),`
/// 换成 `            to_appliance: 0,`（一个方向的账记丢了）：
/// ```text
/// panicked at crates/rmc-gateway/tests/e2e.rs:
/// 没有一条两个方向都 > 0 的流量上报：[RemoteSessionOpened { id: 1 },
/// RemoteSessionBytes { id: 1, to_appliance: 0, from_appliance: 2546 },
/// RemoteSessionClosed { id: 1 }]
/// ```
/// 这条实测同时说明了为什么断言要卡"**两个方向都** > 0"而不是"收到过
/// 一条 `RemoteSessionBytes`"：后者对这次注入是绿的。另外也印证了那次
/// 补报本身是必需的——`engineer_exec` 全程不到 2 秒，周期上报
/// （`BYTES_REPORT_INTERVAL` = 2 秒）一次都轮不到。
#[tokio::test]
async fn reports_session_open_bytes_and_close() {
    let gw = TestGateway::start().await;
    let app = FakeAppliance::start().await;
    let (code, pw) = gw.add_account("zhang");

    let (tx, mut rx) = mpsc::channel(32);
    let handle = within(
        "建隧道",
        factory().establish(params(&code, &pw, app.addr()), tx),
    )
    .await
    .expect("建隧道");
    let port = forwarded_port(&mut rx).await;

    let out = within(
        "工程师 exec",
        engineer_exec(gw.addr().ip(), port, APPLIANCE_PASSWORD, "uptime"),
    )
    .await
    .expect("工程师 exec");
    assert_eq!(out, "ok:uptime\n");

    let seen = msgs_until(&mut rx, "远程会话关闭", |m| {
        matches!(m, TunnelMsg::RemoteSessionClosed { .. })
    })
    .await;

    let opened = seen
        .iter()
        .position(|m| matches!(m, TunnelMsg::RemoteSessionOpened { .. }))
        .expect("必须先报会话开启");
    let closed = seen.len() - 1;
    let bytes_at = seen
        .iter()
        .position(|m| {
            matches!(
                m,
                TunnelMsg::RemoteSessionBytes {
                    to_appliance,
                    from_appliance,
                    ..
                } if *to_appliance > 0 && *from_appliance > 0
            )
        })
        .unwrap_or_else(|| panic!("没有一条两个方向都 > 0 的流量上报：{seen:?}"));
    assert!(
        opened < bytes_at && bytes_at < closed,
        "顺序必须是 开启 → 流量 → 关闭，实际：{seen:?}"
    );

    handle.shutdown().await;
    app.stop().await;
    gw.shutdown().await;
}

// ------------------------------------------------------ 7. 两个工程师

/// 改红（实测过）：`crates/rmc-core/src/ssh/handler.rs` 的
/// `alloc_session_id` 里 `        self.next_session_id.fetch_add(1, Ordering::Relaxed)`
/// 换成 `        self.next_session_id.load(Ordering::Relaxed)`（不再递增，
/// 每条会话都拿 1）：
/// ```text
/// panicked at crates/rmc-gateway/tests/e2e.rs:
/// assertion `left != right` failed: 还没读完 banner 连接就断了：[]
/// ```
/// **红的位置跟原先的预测不一样，这里如实记下**：预测是红在
/// `assert_ne!(ids[0], ids[1])` 上，实测红得更早——第二条会话用同一个 id
/// 插进 `SharedChannels` 账本时**覆盖**了第一条的 `Closer`，旧 `Closer`
/// 一被丢弃，第一条的 pump 立刻收到关闭信号退出，工程师那一侧的 banner
/// 还没读完连接就断了。也就是说 id 唯一性不只是"界面上好看"，它是账本
/// 这条不变式的前提。注释按实测改了，测试本身没动。
#[tokio::test]
async fn two_concurrent_engineers_get_distinct_ids() {
    let gw = TestGateway::start().await;
    let app = FakeAppliance::start().await;
    let (code, pw) = gw.add_account("zhang");

    let (tx, mut rx) = mpsc::channel(64);
    let handle = within(
        "建隧道",
        factory().establish(params(&code, &pw, app.addr()), tx),
    )
    .await
    .expect("建隧道");
    let port = forwarded_port(&mut rx).await;

    // 两条**同时开着**的工程师连接：不能用 exec（跑完就断），否则第二条
    // 开的时候第一条可能已经关了，拿到同一个 id 也不奇怪。
    let a = engineer_socket(gw.addr().ip(), port).await;
    let b = engineer_socket(gw.addr().ip(), port).await;

    let mut ids = Vec::new();
    while ids.len() < 2 {
        if let TunnelMsg::RemoteSessionOpened { id } = next_msg(&mut rx).await {
            ids.push(id);
        }
    }
    assert_ne!(ids[0], ids[1], "两条同时打开的远程会话必须拿到不同的 id");

    drop(a);
    drop(b);
    handle.shutdown().await;
    app.stop().await;
    gw.shutdown().await;
}

/// 开一条工程师连接并**读完假一体机那一整行 SSH banner** 才返回。
///
/// 读到 banner 才证明这一跳真的打通到一体机了——仅仅"TCP 连上了反向
/// 端口"是不够的（反向端口在服务端一侧是无条件 accept 的，拨一体机失败
/// 也要等一会儿才会体现成 EOF）。
///
/// **必须读到行尾，不能只读前四个字节**：第一版只 `read_exact` 了
/// `"SSH-"`，剩下十几个字节还留在内核缓冲区里，于是后面那条"会话被关掉
/// 之后工程师侧读到 EOF"的断言读回来的是这些残留字节而不是 EOF——实测
/// 红在 `left: 18, right: 0`。把 banner 整行吃干净，两侧的后续读才都是
/// 对"通路状态"的观察，而不是对"缓冲区剩多少"的观察。
async fn engineer_socket(ip: std::net::IpAddr, port: u16) -> tokio::net::TcpStream {
    let mut s = within(
        "工程师连反向端口",
        tokio::net::TcpStream::connect((ip, port)),
    )
    .await
    .expect("连反向端口");
    let mut line = Vec::new();
    within("读一体机 SSH banner", async {
        let mut b = [0u8; 1];
        loop {
            let n = s.read(&mut b).await.expect("读 banner");
            assert_ne!(n, 0, "还没读完 banner 连接就断了：{line:?}");
            line.push(b[0]);
            if b[0] == b'\n' {
                return;
            }
        }
    })
    .await;
    assert!(
        line.starts_with(b"SSH-"),
        "反向端口后面应当是假一体机的 SSH banner，实际 {:?}",
        String::from_utf8_lossy(&line)
    );
    s
}

// ------------------------------------------------ 8. 只断开指定的会话

/// 改红（实测过）：`crates/rmc-core/src/ssh/mod.rs` 的
/// `close_remote_session` 在 `        match self.channels.lock().unwrap().remove(&id) {`
/// 之前插一段"把账本里**其它**会话也一并 `close()`"的代码：
/// ```text
/// panicked at crates/rmc-gateway/tests/e2e.rs:
/// 只有被点名的那条该关，实际：[RemoteSessionBytes { id: 2, .. },
/// RemoteSessionClosed { id: 2 }, RemoteSessionBytes { id: 1, .. },
/// RemoteSessionClosed { id: 1 }]
/// ```
/// （第一版注入写的是 `drain()` 全清，那样连被点名的那条也从账本里没了，
/// 函数会返回 `Err(UnknownSessionId)` 而编译不过原来的 `match` 形状——
/// 换成"只多关别人、被点名那条仍走原路"是更干净的对照。）
#[tokio::test]
async fn close_remote_session_drops_only_that_session() {
    let gw = TestGateway::start().await;
    let app = FakeAppliance::start().await;
    let (code, pw) = gw.add_account("zhang");

    let (tx, mut rx) = mpsc::channel(64);
    let handle = within(
        "建隧道",
        factory().establish(params(&code, &pw, app.addr()), tx),
    )
    .await
    .expect("建隧道");
    let port = forwarded_port(&mut rx).await;

    let mut first = engineer_socket(gw.addr().ip(), port).await;
    let mut second = engineer_socket(gw.addr().ip(), port).await;

    let mut ids = Vec::new();
    while ids.len() < 2 {
        if let TunnelMsg::RemoteSessionOpened { id } = next_msg(&mut rx).await {
            ids.push(id);
        }
    }
    // 两条连接开的顺序就是两个 id 分配的顺序（`alloc_session_id` 是
    // `fetch_add`），但这里不依赖那个顺序：挑较小的那个关掉，另一条
    // 用它自己的 id 认。
    let (victim, survivor_socket, victim_socket) = if ids[0] < ids[1] {
        (ids[0], &mut second, &mut first)
    } else {
        (ids[1], &mut first, &mut second)
    };

    within("关掉一条远程会话", handle.close_remote_session(victim))
        .await
        .expect("这条会话此刻是开着的");

    let closed = msgs_until(
        &mut rx,
        "被关掉那条的收尾",
        |m| matches!(m, TunnelMsg::RemoteSessionClosed { id } if *id == victim),
    )
    .await;
    assert!(
        !closed
            .iter()
            .any(|m| matches!(m, TunnelMsg::RemoteSessionClosed { id } if *id != victim)),
        "只有被点名的那条该关，实际：{closed:?}"
    );

    // 被关掉的那一条：banner 已经读干净了，所以这次读到的只能是"通路
    // 没了"——EOF，或者连接被重置。
    let mut buf = [0u8; 64];
    let dead = within("被关掉那条读到 EOF", victim_socket.read(&mut buf)).await;
    assert!(
        matches!(dead, Ok(0) | Err(_)),
        "被关掉的会话，工程师侧应当读到 EOF（或连接重置），实际 {dead:?}"
    );

    // 活着的那一条：banner 同样已经读干净，所以它此刻应当**既没有新
    // 数据、也没有断**——读会一直挂着直到超时。如果 `close_remote_session`
    // 连带关掉了它，这次读会立刻返回 `Ok(0)`，`is_err()` 就是 false。
    assert!(
        tokio::time::timeout(Duration::from_millis(300), survivor_socket.read(&mut buf))
            .await
            .is_err(),
        "另一条会话不该被连带关掉——它此刻应当只是没有新数据，而不是 EOF"
    );

    handle.shutdown().await;
    app.stop().await;
    gw.shutdown().await;
}

// ------------------------------------------------------ 9. 一体机不可达

/// 改红（实测过）：`crates/rmc-core/src/ssh/pump.rs` 里拨号失败那一支的
/// `            let _ = tx` 换成
/// `            let _ = tokio::sync::mpsc::channel::<TunnelMsg>(1).0`
/// ——这条 `ApplianceDialFailed` 被发进一个没有接收端的新通道，等于没发：
/// ```text
/// panicked at crates/rmc-gateway/tests/e2e.rs:
/// 一体机拨号失败上报 超过 30s 没有结果
/// ```
#[tokio::test]
async fn unreachable_appliance_reports_dial_failure_and_keeps_the_tunnel() {
    let gw = TestGateway::start().await;
    let nowhere = dead_port().await;
    let (code, pw) = gw.add_account("zhang");

    let (tx, mut rx) = mpsc::channel(32);
    let handle = within(
        "建隧道",
        factory().establish(params(&code, &pw, nowhere), tx),
    )
    .await
    .expect("一体机不可达不影响隧道本身能不能建起来");
    let port = forwarded_port(&mut rx).await;

    let _sock = within(
        "工程师连反向端口",
        tokio::net::TcpStream::connect((gw.addr().ip(), port)),
    )
    .await
    .expect("反向端口本身是通的");
    let seen = msgs_until(&mut rx, "一体机拨号失败上报", |m| {
        matches!(m, TunnelMsg::ApplianceDialFailed { .. })
    })
    .await;
    assert!(
        !seen
            .iter()
            .any(|m| matches!(m, TunnelMsg::RemoteSessionOpened { .. })),
        "拨号都没成，不该报会话开启：{seen:?}"
    );

    // 隧道本身还活着：服务端的隧道表里还有它，而且还能再接一个工程师
    // （再报一次拨号失败——这比只看表更硬，它要求整条反向通路仍然在跑）。
    let tunnels = gw.running().tunnels_snapshot();
    assert_eq!(tunnels.len(), 1, "隧道不该因为一体机连不上而被拆掉");
    assert_eq!(tunnels[0].1, port);

    let _sock2 = within(
        "第二个工程师连反向端口",
        tokio::net::TcpStream::connect((gw.addr().ip(), port)),
    )
    .await
    .expect("隧道还在，反向端口该继续接受连接");
    msgs_until(&mut rx, "第二次一体机拨号失败上报", |m| {
        matches!(m, TunnelMsg::ApplianceDialFailed { .. })
    })
    .await;

    handle.shutdown().await;
    gw.shutdown().await;
}

// ------------------------------------------------------------ 10/11. 预检

/// 四步全过，而且第二步的 detail 跟假一体机自己算出来的 host key 指纹
/// 逐字符相等（不是"长得像一个指纹"）。
///
/// 改红（实测过）：`crates/rmc-core/src/preflight.rs` 里第二步的
/// `            Ok(fp) => StepOutcome::Pass { detail: fp },` 换成
/// `            Ok(fp) => StepOutcome::Pass { detail: { let _ = fp; "ok".to_string() } },`：
/// ```text
/// panicked at crates/rmc-gateway/tests/e2e.rs:
/// assertion `left == right` failed: 第二步的 detail 必须就是假一体机那把 host key 的指纹
///   left: "ok"
/// ```
/// 注意这一枪打不红 `report.passed()`——四步仍然全 `Pass`。这正是要拿
/// **逐字符相等**去对指纹、而不是只看"这一步过了"的理由。
#[tokio::test]
async fn preflight_passes_all_four_steps_against_the_real_server() {
    let gw = TestGateway::start().await;
    let app = FakeAppliance::start().await;
    let (code, _pw) = gw.add_account("zhang");

    let t = transport();
    let report = within(
        "预检",
        preflight::run(
            &t,
            &code.server(),
            code.fingerprint(),
            &hostport(app.addr()),
        ),
    )
    .await;

    assert_eq!(
        report.steps.len(),
        ALL_STEPS.len(),
        "四步都该有结果：{report:?}"
    );
    assert!(report.passed(), "四步都该过，实际：{report:?}");
    assert_eq!(
        detail_of(&report, ALL_STEPS[1]),
        app.fingerprint_sha256(),
        "第二步的 detail 必须就是假一体机那把 host key 的指纹"
    );
    assert!(
        detail_of(&report, ALL_STEPS[3]).contains("指纹与连接码一致"),
        "第四步应当说清 TLS 指纹跟连接码对上了，实际 {:?}",
        detail_of(&report, ALL_STEPS[3])
    );

    app.stop().await;
    gw.shutdown().await;
}

/// 指纹换错一把：前三步跟对的时候一模一样（一体机那两步压根不看这个
/// 指纹，运维服务器的 TCP 连通也不看），只有第四步 TLS 钉扣会垮。
///
/// 改红（实测过，与上面第 2 条同一枪）：`crates/rmc-core/src/transport/tls.rs`
/// 里 `        if ServerFingerprint::of_ed25519_public(&pk) != self.want {`
/// 换成 `        if false {`：
/// ```text
/// panicked at crates/rmc-gateway/tests/e2e.rs:
/// 第四步应当 Fail 且是 Fatal，实际 Pass { detail: "TLS 1.3 · 指纹与连接码一致" }
/// ```
#[tokio::test]
async fn preflight_with_a_wrong_fingerprint_fails_only_the_fourth_step() {
    let gw = TestGateway::start().await;
    let app = FakeAppliance::start().await;
    let (code, _pw) = gw.add_account("zhang");
    let bad = with_other_fingerprint(&code);

    let t = transport();
    let report = within(
        "错指纹预检",
        preflight::run(&t, &code.server(), bad.fingerprint(), &hostport(app.addr())),
    )
    .await;

    for name in &ALL_STEPS[..3] {
        assert!(
            matches!(outcome_of(&report, name), StepOutcome::Pass { .. }),
            "第 {name} 步不该受指纹影响，实际：{:?}",
            outcome_of(&report, name)
        );
    }
    match outcome_of(&report, ALL_STEPS[3]) {
        StepOutcome::Fail { class, .. } => assert_eq!(*class, ErrorClass::Fatal),
        other => panic!("第四步应当 Fail 且是 Fatal，实际 {other:?}"),
    }

    app.stop().await;
    gw.shutdown().await;
}

fn outcome_of<'a>(r: &'a preflight::PreflightReport, name: &str) -> &'a StepOutcome {
    &r.steps
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("报告里没有 {name} 这一步：{r:?}"))
        .outcome
}

fn detail_of(r: &preflight::PreflightReport, name: &str) -> String {
    match outcome_of(r, name) {
        StepOutcome::Pass { detail }
        | StepOutcome::Fail { detail, .. }
        | StepOutcome::Skipped { detail } => detail.clone(),
    }
}

// --------------------------------------------------------------- 12. 吊销

/// `Timings::fast()` 的 `sweep` 是 200ms，所以一个扫描周期之内就该被踢掉。
///
/// 改红（实测过）：`crates/rmc-gateway/src/server.rs` 的
/// `revocation_sweep` 里 `                for (name, handle, port) in doomed {`
/// 换成 `                for (name, handle, port) in doomed.into_iter().take(0) {`
/// ——扫描照跑、名单照算，就是一个都不踢：
/// ```text
/// panicked at crates/rmc-gateway/tests/e2e.rs:
/// 吊销之后一个扫描周期内（这里放宽到 1 秒）必须收到 Disconnected
/// ```
/// （用 `.take(0)` 而不是逐字删掉那句 `handle.disconnect(...)`：后者跨
/// 三行，单行注入改不动；`.take(0)` 是同一个效果的干净单行注入。）
#[tokio::test]
async fn a_revoked_account_is_disconnected_within_one_sweep() {
    let gw = TestGateway::start().await;
    let app = FakeAppliance::start().await;
    let (code, pw) = gw.add_account("zhang");

    let (tx, mut rx) = mpsc::channel(32);
    let handle = within(
        "建隧道",
        factory().establish(params(&code, &pw, app.addr()), tx),
    )
    .await
    .expect("建隧道");
    forwarded_port(&mut rx).await;

    gw.revoke("zhang");

    let disconnected = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let TunnelMsg::Disconnected { reason } = next_msg(&mut rx).await {
                return reason;
            }
        }
    })
    .await;
    assert!(
        disconnected.is_ok(),
        "吊销之后一个扫描周期内（这里放宽到 1 秒）必须收到 Disconnected"
    );

    handle.shutdown().await;
    app.stop().await;
    gw.shutdown().await;
}

// -------------------------------------------- 13/14. Supervisor 全链路

/// Supervisor 在服务端重启之后，用它一直留着的那份凭据自己重连上——
/// 界面**没有**再输入一次口令，测试也只发过一条 `Command::Start`。
///
/// 数据目录必须复用：凭据里是连接码，连接码里钉着指纹，指纹从数据目录
/// 里那把 ed25519 种子派生。所以 `shutdown()` 把 `TempDir` 还出来，
/// `start_on` 再把它收回去——见 `testing.rs` 上 `TestGateway` 的说明。
///
/// # 改红：打了两枪，第一枪的结果跟 brief 的预测不一样，如实记下
///
/// **第一枪（brief 字面指定的那一枪）**：把下面
/// `    let gw2 = TestGateway::start_on(gw_addr, dir).await;` 换成
/// `    let gw2 = TestGateway::start_on(gw_addr, tempfile::tempdir().unwrap()).await;`。
/// 实测**是红的，但不是 brief 说的那个原因**：
/// ```text
/// panicked at crates/rmc-gateway/src/testing.rs:
/// 重启到的数据目录里应该已经有 config.toml——它是上一次 start 写的:
/// Config("读不到 /var/folders/.../config.toml：No such file or directory；先运行 init")
/// ```
/// 一个全新的空 `TempDir` 里既没有 `config.toml` 也没有身份密钥，
/// `start_on` 在 `GatewayConfig::load` 那一步就停住了——客户端**根本没有
/// 机会**看到一个不一样的指纹。也就是说这一枪证明的是"夹具拦得住"，
/// 不是"指纹钉扣拦得住"。
///
/// **第二枪（真正打到 brief 想证的那件事上）**：在
/// `crates/rmc-gateway/src/testing.rs` 的 `start_on` 里、
/// `        let cfg = GatewayConfig::load(&data)` 之前插一行
/// `{ let _ = std::fs::remove_file(data.identity_key()); Identity::create_in(&data).unwrap(); }`
/// ——同一个数据目录、同一份账号表与端口，**只换掉身份密钥**，服务端照常
/// 起来：
/// ```text
/// panicked at crates/rmc-gateway/tests/e2e.rs:
/// 重启之后重新连上 超过 30s 没有结果
/// ```
/// 新身份 = 新指纹，客户端手里那份凭据的指纹对不上，永远回不到
/// `Connected`。这才是这条测试真正钉住的东西。
#[tokio::test]
async fn the_supervisor_reconnects_after_the_server_restarts_with_the_credentials_it_kept() {
    let logs = tempfile::tempdir().unwrap();
    let gw = TestGateway::start().await;
    // 一体机地址不能是回环写法：`Command::Start` 会调
    // `ValidatedAddresses::validate`，它拒绝回环的一体机。
    let app = FakeAppliance::start_at(non_loopback_self_ip().await).await;
    let (code, pw) = gw.add_account("zhang");
    let gw_addr = gw.addr();

    let (cmd, mut ev) = Supervisor::spawn(supervisor_config(&logs), real_deps());
    cmd.send(Command::Start {
        code,
        password: Zeroizing::new(pw.to_string()),
        appliance: hostport(app.addr()),
    })
    .await
    .expect("Supervisor 还活着");

    wait_state(&mut ev, "首次连上", |s| {
        matches!(s, State::Connected { .. })
    })
    .await;

    let dir = gw.shutdown().await;
    wait_state(&mut ev, "断线后进退避", |s| {
        matches!(s, State::Backoff { .. })
    })
    .await;

    let gw2 = TestGateway::start_on(gw_addr, dir).await;
    assert_eq!(gw2.addr(), gw_addr, "重启必须回到同一个地址");

    // 没有第二条 Command::Start——Supervisor 自己拿留着的凭据重连。
    wait_state(&mut ev, "重启之后重新连上", |s| {
        matches!(s, State::Connected { .. })
    })
    .await;

    let _ = cmd.send(Command::Stop).await;
    app.stop().await;
    gw2.shutdown().await;
}

/// `Stop` 之后：客户端回 `Idle`，**而且服务端那一侧的隧道真的被释放了**
/// ——`status.json` 里隧道表空了。前面先断言它非空，否则"空了"这件事
/// 在一条压根没连上的链路上也恒成立。
///
/// 改红（实测过）：`crates/rmc-core/src/ssh/mod.rs` 的
/// `async fn disconnect_session(...) {` 下面插进 `if true { return; }`
/// ——`SshTunnel::shutdown()` 与 `impl Drop for SshTunnel` 那条兜底**共用
/// 这一个函数**，所以一行就把两条路一起堵上（这也是它值得被抽成一个函数
/// 的原因：不会出现"补了一条、漏了另一条"）：
/// ```text
/// panicked at crates/rmc-gateway/tests/e2e.rs:
/// 等服务端释放隧道 超过 30s 没有结果
/// ```
/// 服务端收不到 disconnect，隧道要等心跳超时才掉，`status.json` 在整个
/// 30 秒窗口里一直非空。
#[tokio::test]
async fn the_supervisor_stops_cleanly_and_the_server_frees_the_port() {
    let logs = tempfile::tempdir().unwrap();
    let gw = TestGateway::start().await;
    let app = FakeAppliance::start_at(non_loopback_self_ip().await).await;
    let (code, pw) = gw.add_account("zhang");

    let (cmd, mut ev) = Supervisor::spawn(supervisor_config(&logs), real_deps());
    cmd.send(Command::Start {
        code,
        password: Zeroizing::new(pw.to_string()),
        appliance: hostport(app.addr()),
    })
    .await
    .expect("Supervisor 还活着");
    wait_state(&mut ev, "连上", |s| matches!(s, State::Connected { .. })).await;

    // 肯定对照：这一刻服务端确实记着一条隧道。
    let before = rmc_gateway::status::read(gw.data_dir())
        .expect("读 status.json")
        .expect("serve 起来就会写一份");
    assert_eq!(
        before.tunnels.len(),
        1,
        "连上之后 status.json 里该有一条隧道：{before:?}"
    );

    cmd.send(Command::Stop).await.expect("Supervisor 还活着");
    wait_state(&mut ev, "停止后回 Idle", |s| matches!(s, State::Idle)).await;

    let freed = within("等服务端释放隧道", async {
        loop {
            let st = rmc_gateway::status::read(gw.data_dir())
                .expect("读 status.json")
                .expect("serve 还在跑");
            if st.tunnels.is_empty() {
                return st;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(freed.tunnels.is_empty());

    app.stop().await;
    gw.shutdown().await;
}
