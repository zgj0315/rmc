//! 真实链路测试，需要 gateway/test-env 在运行。
//! 运行前先执行 crates/rmc-core/tests/fetch-harness-cert.sh。
//!
//! 宿主要能把 "gateway.test" 解析到 127.0.0.1——方案约定是在 /etc/hosts
//! 里加一行 `127.0.0.1 gateway.test`（CI 由工作流写入），跟
//! tests/transport.rs 里 `#[ignore]` 的 `connect_wraps_tls_and_delivers_the_ssh_banner`
//! 依赖的是同一个前提，不是本文件新引入的要求。
//!
//! `--test-threads=1` 是必须的：`establishes_and_reports_first_seen_host_key`
//! 与 `second_tunnel_on_the_same_port_is_port_busy` 都会真的把 22001 绑起来，
//! 多个用例并发跑会互相抢这个端口。

use rmc_core::addr::HostPort;
use rmc_core::error::{Error, ErrorClass};
use rmc_core::knownhosts::{Fingerprint, KnownHosts};
use rmc_core::platform::{NoProxy, NoProxyAuth};
use rmc_core::ssh::SshTunnelFactory;
use rmc_core::transport::tls::TlsRoots;
use rmc_core::transport::Transport;
use rmc_core::tunnel::{TunnelFactory, TunnelMsg, TunnelParams};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

const TUNNEL_USER: &str = "tunnel-zhang";
const TUNNEL_PW: &str = "tunnel-init-pw";
const REVERSE_PORT: u16 = 22001;

fn tmp_known_hosts() -> KnownHosts {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    KnownHosts::open(std::env::temp_dir().join(format!("rmc-kh-{n}/known_hosts")))
}

fn gateway() -> HostPort {
    "gateway.test:8443".parse().unwrap()
}

fn appliance() -> HostPort {
    // 一体机在测试环境里对宿主发布为 127.0.0.1:2322，但转发目标由
    // 客户端自己拨号，所以这里用宿主可达的地址。
    "127.0.0.1:2322".parse().unwrap()
}

fn factory(known_hosts: KnownHosts) -> SshTunnelFactory {
    let mut roots = TlsRoots::webpki();
    roots
        .with_extra_pem(
            &std::fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/harness-ca.pem"
            ))
            .expect("先运行 tests/fetch-harness-cert.sh"),
        )
        .unwrap();
    let transport = Arc::new(Transport::new(
        Arc::new(NoProxy),
        Arc::new(NoProxyAuth),
        roots,
    ));
    SshTunnelFactory::new(transport, Arc::new(known_hosts), gateway())
}

fn params(password: &str, port: u16) -> TunnelParams {
    TunnelParams {
        username: TUNNEL_USER.into(),
        password: Zeroizing::new(password.to_string()),
        reverse_port: port,
        appliance: appliance(),
    }
}

/// `Box<dyn TunnelHandle>` 上没有 `Debug`（`TunnelHandle` trait 本身没有
/// 也不该有这个约束），`Result::unwrap_err` 要求 `Ok` 分支实现 `Debug`，
/// 直接 `unwrap_err()` 编译不过——跟 tests/transport.rs 里 `expect_err`
/// 是同一个原因，用一次 `match` 换掉它。
fn expect_err(r: Result<Box<dyn rmc_core::tunnel::TunnelHandle>, Error>) -> Error {
    match r {
        Ok(_) => panic!("期望建立隧道失败，实际却成功了"),
        Err(e) => e,
    }
}

async fn next_msg(rx: &mut mpsc::Receiver<TunnelMsg>) -> TunnelMsg {
    tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .expect("等待隧道消息超时")
        .expect("隧道消息通道已关闭")
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn establishes_and_reports_first_seen_host_key() {
    let (tx, mut rx) = mpsc::channel(32);
    let handle = factory(tmp_known_hosts())
        .establish(params(TUNNEL_PW, REVERSE_PORT), tx)
        .await
        .unwrap();

    match next_msg(&mut rx).await {
        TunnelMsg::Authenticated {
            host_key_fp,
            first_seen,
        } => {
            assert!(host_key_fp.starts_with("SHA256:"), "{host_key_fp}");
            assert!(first_seen, "首次连接应报 first_seen");
        }
        other => panic!("第一条消息应为 Authenticated，实际 {other:?}"),
    }
    match next_msg(&mut rx).await {
        TunnelMsg::ForwardRegistered { port } => assert_eq!(port, REVERSE_PORT),
        other => panic!("第二条消息应为 ForwardRegistered，实际 {other:?}"),
    }

    // 只证明 establish() 返回成功、且发过 ForwardRegistered，证明不了
    // Gateway 真的把反向端口接进了这条 SSH 会话——tcpip_forward 本身确实
    // 是一次真实的协议往返（见 ssh/mod.rs 上 map_tcpip_forward_error 的
    // 文档注释），但通道能不能真正转发，还要看
    // ClientHandler::server_channel_open_forwarded_tcpip 有没有真的调用
    // `reply.accept()`——如果代码把 `reply` 命名成 `_reply` 直接丢弃，
    // establish() 前面的每一步都不受影响，照样能连上、认证、注册端口，
    // 这里断言的 Authenticated/ForwardRegistered 两条消息也照样会来。
    //
    // 所以这里再往前走一步：真的从宿主拨一个原始 TCP 连接到 22001，
    // 观察它的行为。sshd 收到反向端口上的连接后，会先 accept() 这个
    // TCP 连接，再通过 SSH 会话发 forwarded-tcpip 请求给客户端；
    // - 如果 `reply.accept()` 真的被调用，这条 TCP 连接会保持打开——
    //   Task 8 还没实现字节转发，读不到任何字节，也读不到 EOF，
    //   读操作应该超时。
    // - 如果 `reply` 被悄悄丢弃（等效于自动拒绝），sshd 会在通道被拒绝后
    //   立刻把这条已经 accept 过的 TCP 连接关掉，读操作会几乎立即返回
    //   `Ok(0)`（EOF），而不是超时。
    //
    // 会让这部分变红的改法：把 handler.rs 里 `reply.accept().await;`
    // 删掉或者换成 drop(reply)（等效于把参数命名成 `_reply`）。
    let mut probe = tokio::net::TcpStream::connect(("127.0.0.1", REVERSE_PORT))
        .await
        .expect("连接反向端口失败");
    let mut buf = [0u8; 1];
    let read_result = tokio::time::timeout(Duration::from_secs(3), probe.read(&mut buf)).await;
    assert!(
        read_result.is_err(),
        "期待读超时（forwarded-tcpip 通道被 accept、保持打开），\
         实际 {read_result:?}——说明通道被悄悄拒绝了"
    );

    handle.shutdown().await;
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn second_connection_matches_the_recorded_host_key() {
    let kh_path = tmp_known_hosts().path().to_path_buf();

    for expect_first_seen in [true, false] {
        let (tx, mut rx) = mpsc::channel(32);
        let handle = factory(KnownHosts::open(kh_path.clone()))
            .establish(params(TUNNEL_PW, REVERSE_PORT), tx)
            .await
            .unwrap();
        match next_msg(&mut rx).await {
            TunnelMsg::Authenticated { first_seen, .. } => {
                assert_eq!(first_seen, expect_first_seen);
            }
            other => panic!("{other:?}"),
        }
        handle.shutdown().await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn recorded_but_changed_host_key_is_fatal() {
    let kh = tmp_known_hosts();
    // 先写一条不同的指纹，模拟 Gateway 被冒充。
    //
    // R——预扫描已发现：knownhosts::KnownHosts::check 收的是 `&Fingerprint`
    // 不是裸 `&str`（Task 4 的 R28 裁决），brief 原文这里直接传字符串字面量
    // 编译不过，必须先过 `Fingerprint::new` 的形状校验。
    kh.check(
        &gateway(),
        &Fingerprint::new("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
    )
    .unwrap();

    let (tx, _rx) = mpsc::channel(32);
    let err = expect_err(
        factory(kh)
            .establish(params(TUNNEL_PW, REVERSE_PORT), tx)
            .await,
    );
    // 只断言 class() == Fatal 还不够：Auth/Config/TlsInvalidCert 等好几个
    // 变体都落在 Fatal 类下，一个只对着 class() 断言的测试测不出这里
    // 返回的到底是不是 HostKeyMismatch——例如把 check_server_key 里的
    // 错误路径误改成返回 Error::Config(...)（同样 Fatal），这条测试不会
    // 变红。额外 matches! 一次具体变体，把这个缺口堵上。
    assert!(
        matches!(err, Error::HostKeyMismatch { .. }),
        "应为 HostKeyMismatch，实际 {err:?}"
    );
    assert_eq!(err.class(), ErrorClass::Fatal);
    assert!(err.to_string().contains("host key"), "{err}");
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn wrong_password_is_auth_class_and_not_network() {
    let (tx, _rx) = mpsc::channel(32);
    let err = expect_err(
        factory(tmp_known_hosts())
            .establish(params("definitely-wrong", REVERSE_PORT), tx)
            .await,
    );
    assert!(matches!(err, Error::AuthRejected), "实际 {err:?}");
    assert_eq!(err.class(), ErrorClass::Auth);
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn port_outside_permitlisten_is_port_busy_class() {
    // 22007 未在 Gateway 的 PermitListen 中放行，tcpip-forward 会被拒。
    //
    // R9：这条测试和下面的 second_tunnel_on_the_same_port_is_port_busy
    // 在 SSH 协议层面是不可分辨的——sshd 对"端口不在 PermitListen 里"和
    // "端口已经被同账号另一条会话占用"都回同一个
    // SSH_MSG_REQUEST_FAILURE，客户端拿到的都是 russh::Error::RequestDenied，
    // 协议本身没有携带"为什么拒绝"的原因字符串（不同于 channel-open-failure
    // 那种带 reason code + description 的拒绝）。所以这两条测试没法靠
    // "观察到不同的失败原因"来互相区分，只能确认"两种真实场景都确实
    // 被服务端拒绝、且都落 PortBusy"——真正验证"不是所有 tcpip_forward
    // 失败都被划成 PortBusy"这件事的，是
    // `ssh::tests::request_denied_is_port_busy_but_disconnect_and_send_error_are_network`
    // 这条不需要 docker、任何 `cargo test` 都会跑到的单元测试：它直接对
    // `map_tcpip_forward_error` 喂 `Disconnect`/`SendError`，断言二者绝不会
    // 被判成 PortBusy——这是本轮 R9 真正修的漏洞（旧版把 tcpip_forward
    // 的一切失败都当端口占用，会话中途断线也会被套上"固定 5 秒重试"）。
    //
    // 这里额外 matches! 一次端口号，至少确认返回的 PortBusy 错误携带的
    // 是这次请求的端口（22007），不是巧合命中其他分支。
    let (tx, _rx) = mpsc::channel(32);
    let err = expect_err(
        factory(tmp_known_hosts())
            .establish(params(TUNNEL_PW, 22007), tx)
            .await,
    );
    assert!(matches!(err, Error::ForwardPortBusy(22007)), "实际 {err:?}");
    assert_eq!(err.class(), ErrorClass::PortBusy);
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn second_tunnel_on_the_same_port_is_port_busy() {
    let (tx1, mut rx1) = mpsc::channel(32);
    let first = factory(tmp_known_hosts())
        .establish(params(TUNNEL_PW, REVERSE_PORT), tx1)
        .await
        .unwrap();
    // 等注册完成
    while !matches!(
        next_msg(&mut rx1).await,
        TunnelMsg::ForwardRegistered { .. }
    ) {}

    let (tx2, _rx2) = mpsc::channel(32);
    let err = expect_err(
        factory(tmp_known_hosts())
            .establish(params(TUNNEL_PW, REVERSE_PORT), tx2)
            .await,
    );
    assert!(
        matches!(err, Error::ForwardPortBusy(REVERSE_PORT)),
        "实际 {err:?}"
    );
    assert_eq!(err.class(), ErrorClass::PortBusy);

    first.shutdown().await;
}

#[tokio::test]
async fn password_never_appears_in_debug_output() {
    // R——预扫描已发现：这条是"口令绝不出现在 Debug 输出"这条全局约束
    // 唯一的断言，brief 原文标了 `#[ignore]` 却没给理由，导致正常一次
    // `cargo test` 永远跑不到它。这条不需要 docker 环境（只是构造一个
    // `TunnelParams` 然后 format!("{:?}")），没有理由 ignore，去掉属性。
    let p = params("super-secret-pw", REVERSE_PORT);
    let printed = format!("{p:?}");
    assert!(!printed.contains("super-secret-pw"), "{printed}");
}
