//! 真实链路测试，需要 gateway/test-env 在运行。
//! 运行前先执行 crates/rmc-core/tests/fetch-harness-cert.sh。
//!
//! 宿主要能把 "gateway.test" 解析到 127.0.0.1——方案约定是在 /etc/hosts
//! 里加一行 `127.0.0.1 gateway.test`，跟 tests/transport.rs 里
//! `#[ignore]` 的 `connect_wraps_tls_and_delivers_the_ssh_banner` 依赖的是
//! 同一个前提，不是本文件新引入的要求。
//!
//! R46（第二轮评审发现）：上一版这里写"CI 由工作流写入"，不是事实——
//! `.github/workflows/gateway.yml` 只在 `paths: ["gateway/**", ...]`
//! 变化时触发，`crates/**` 底下的改动不会触发任何工作流；这个仓库目前
//! 没有任何工作流会跑 `cargo build`/`cargo test`，自然也没有一步写
//! `/etc/hosts`。这意味着本文件下面十条 `#[ignore]` 用例（连同
//! tests/transport.rs 的那四条）事实上从未被任何自动化跑过，只能靠人
//! 手动在配好 /etc/hosts、起好 gateway/test-env 的机器上跑
//! `-- --ignored` 才会执行——在这一天到来之前，如实说：这些用例哪里都
//! 不会跑。协议级别的等价行为改由 `crate::ssh::test_support` 里那个
//! 进程内 russh 服务端跑在每一次普通 `cargo test` 里（见 R40），不依赖
//! docker/DNS/hosts，是当前唯一真正被跑到的证据来源。
//!
//! `--test-threads=1` 是必须的：`establishes_and_reports_first_seen_host_key`
//! 与 `second_tunnel_on_the_same_port_is_port_busy` 都会真的把 22001 绑起来，
//! 多个用例并发跑会互相抢这个端口。

use rmc_core::error::{Error, ErrorClass};
use rmc_core::knownhosts::{Fingerprint, KnownHosts};
use rmc_core::tunnel::{TunnelFactory, TunnelMsg};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

mod common;
use common::*;

/// `Box<dyn TunnelHandle>` 上没有 `Debug`（`TunnelHandle` trait 本身没有
/// 也不该有这个约束），`Result::unwrap_err` 要求 `Ok` 分支实现 `Debug`，
/// 直接 `unwrap_err()` 编译不过——跟 tests/transport.rs 里 `expect_err`
/// 是同一个原因，用一次 `match` 换掉它。
///
/// 这个辅助只有这个文件需要（`forwarding.rs` 里没有一条测试断言
/// `establish()` 本身失败），所以留在本地，不搬进 `tests/common`——搬过去
/// 会在 `forwarding.rs` 那个二进制里变成没人调用的 dead_code。
fn expect_err(r: Result<Box<dyn rmc_core::tunnel::TunnelHandle>, Error>) -> Error {
    match r {
        Ok(_) => panic!("期望建立隧道失败，实际却成功了"),
        Err(e) => e,
    }
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
    //   一体机自己的 sshd 会立刻发一句 SSH banner，字节转发（Task 8，
    //   `ssh::pump`）会把它原样转发过来，读操作会在超时前拿到非零
    //   字节。
    // - 如果 `reply` 被悄悄丢弃（等效于自动拒绝），sshd 会在通道被拒绝后
    //   立刻把这条已经 accept 过的 TCP 连接关掉，读操作会几乎立即返回
    //   `Ok(0)`（EOF）。
    //
    // R——Task 12 首次让这条 `#[ignore]` 用例真的在 CI 里跑起来时抓到：
    // brief 原文这里断言"应该超时"，写这句话的时候字节转发还没接上
    // （模块顶部第二段的历史注释）；转发接上之后，一体机的 SSH banner
    // 会在 3 秒超时之前就到，`read_result` 变成 `Ok(Ok(1))`，原来那句
    // `assert!(read_result.is_err(), ...)` 反倒会把"转发工作正常"这个
    // 好结果误判成失败——这条 `#[ignore]` 从未被自动化跑过，这个假阳性
    // 一直没被发现。真正该守住的性质是"没有读到 EOF"（`Ok(Ok(0))` 才
    // 是通道被悄悄拒绝的信号），超时（尚未转发任何字节）与读到非零字节
    // （转发已经在正常工作）都是"通道确实被 accept 了"的证据，两者都
    // 该算通过。
    //
    // 会让这条测试变红的实现改法：把 handler.rs 里
    // `reply.accept().await;` 删掉或者换成 `drop(reply)`（等效于把参数
    // 命名成 `_reply`）——sshd 会立刻把探测连接关掉，下面的读操作会
    // 几乎立即返回 `Ok(Ok(0))`。
    let mut probe = tokio::net::TcpStream::connect(("127.0.0.1", REVERSE_PORT))
        .await
        .expect("连接反向端口失败");
    let mut buf = [0u8; 1];
    let read_result = tokio::time::timeout(Duration::from_secs(3), probe.read(&mut buf)).await;
    match read_result {
        Err(_) => {} // 超时：通道被 accept，还没有字节流过。
        Ok(Ok(n)) => assert_ne!(n, 0, "读到 EOF——说明通道被悄悄拒绝了"),
        Ok(Err(e)) => panic!("读取探测连接失败：{e}"),
    }

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
