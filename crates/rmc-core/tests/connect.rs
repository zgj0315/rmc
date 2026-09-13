//! HTTP CONNECT 的协议流程，用本地假代理驱动。

use rmc_core::addr::HostPort;
use rmc_core::error::{Error, ErrorClass};
use rmc_core::platform::{NoProxyAuth, ProxyAuthenticator};
use rmc_core::transport::connect::http_connect;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 起一个假代理，按 `replies` 顺序逐轮应答，收集收到的请求头。
async fn fake_proxy(replies: Vec<&'static str>) -> (u16, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut seen = Vec::new();
        for reply in replies {
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            seen.push(String::from_utf8_lossy(&buf[..n]).to_string());
            sock.write_all(reply.as_bytes()).await.unwrap();
        }
        // 隧道建立后回一个 SSH banner，供调用方确认字节直通。
        let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.2p1\r\n").await;
        seen
    });
    (port, handle)
}

fn target() -> HostPort {
    "gateway.company.com:443".parse().unwrap()
}

#[tokio::test]
async fn sends_connect_request_and_accepts_200() {
    let (port, srv) = fake_proxy(vec!["HTTP/1.1 200 Connection established\r\n\r\n"]).await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    http_connect(&mut s, &target(), &NoProxyAuth).await.unwrap();

    let seen = srv.await.unwrap();
    assert!(
        seen[0].starts_with("CONNECT gateway.company.com:443 HTTP/1.1\r\n"),
        "{}",
        seen[0]
    );
    assert!(
        seen[0].contains("Host: gateway.company.com:443\r\n"),
        "{}",
        seen[0]
    );
    assert!(seen[0].ends_with("\r\n\r\n"));

    let mut banner = [0u8; 8];
    s.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"SSH-2.0-");
}

#[tokio::test]
async fn accepts_200_with_headers_before_body() {
    let (port, _srv) = fake_proxy(vec![
        "HTTP/1.1 200 OK\r\nProxy-Agent: corp\r\nX-Trace: abc\r\n\r\n",
    ])
    .await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    assert!(http_connect(&mut s, &target(), &NoProxyAuth).await.is_ok());

    // 光看 `is_ok()` 不够：如果实现只读到第一个 `\r\n` 就把 200 当成
    // 头部结束（漏读了 `Proxy-Agent`/`X-Trace` 这两行），这里也会
    // 返回 Ok——`Response.status` 已经是 200 了，剩下没读的两行头部
    // 会原样留在 socket 里，紧跟着假代理随后发的 SSH banner 之前，
    // 隧道打通后调用方第一口读到的就不是干净的 banner，而是残留的
    // 头部字节。手动验证过这条断言补上之前，这个 mutation
    // （`buf.ends_with(b"\r\n\r\n")` 松成 `buf.ends_with(b"\r\n")`）
    // 不会让本测试变红。
    let mut banner = [0u8; 8];
    s.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"SSH-2.0-");
}

#[tokio::test]
async fn without_authenticator_407_is_fatal_and_names_the_scheme() {
    let (port, _srv) = fake_proxy(vec![
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\n\r\n",
    ])
    .await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let err = http_connect(&mut s, &target(), &NoProxyAuth)
        .await
        .unwrap_err();
    assert_eq!(err.class(), ErrorClass::Fatal);
    assert!(err.to_string().contains("Negotiate"), "{err}");
}

/// 两轮 Negotiate 协商，第二轮带上服务端的 challenge。
struct TwoLegNegotiate {
    seen_challenges: Arc<std::sync::Mutex<Vec<Option<String>>>>,
}

#[async_trait::async_trait]
impl ProxyAuthenticator for TwoLegNegotiate {
    async fn next_token(&self, scheme: &str, challenge: Option<&str>) -> Option<String> {
        assert_eq!(scheme, "Negotiate");
        let mut seen = self.seen_challenges.lock().unwrap();
        seen.push(challenge.map(str::to_string));
        match seen.len() {
            1 => Some("TlRMTVNTUAAB".into()),
            2 => Some("TlRMTVNTUAAD".into()),
            _ => None,
        }
    }
}

#[tokio::test]
async fn completes_a_two_leg_negotiate_handshake_on_one_connection() {
    let (port, srv) = fake_proxy(vec![
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\n\r\n",
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate TlRMTVNTUAAC\r\n\r\n",
        "HTTP/1.1 200 Connection established\r\n\r\n",
    ])
    .await;
    let seen_challenges = Arc::new(std::sync::Mutex::new(Vec::new()));
    let auth = TwoLegNegotiate {
        seen_challenges: seen_challenges.clone(),
    };

    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    http_connect(&mut s, &target(), &auth).await.unwrap();

    let seen = srv.await.unwrap();
    assert_eq!(seen.len(), 3);
    assert!(!seen[0].contains("Proxy-Authorization"));
    assert!(
        seen[1].contains("Proxy-Authorization: Negotiate TlRMTVNTUAAB"),
        "{}",
        seen[1]
    );
    assert!(
        seen[2].contains("Proxy-Authorization: Negotiate TlRMTVNTUAAD"),
        "{}",
        seen[2]
    );

    let challenges = seen_challenges.lock().unwrap().clone();
    assert_eq!(challenges, vec![None, Some("TlRMTVNTUAAC".to_string())]);
}

/// R8：proxy 的 407 挑战几乎总带 base64 padding（NTLM Type-2 消息尤其
/// 如此），本任务的 brief 原始测试用的 `TlRMTVNTUAAC` 恰好不带
/// padding，凑巧掩盖了一处会把带 `=` 的挑战整个丢弃的 bug——把它
/// 错当成了 `realm="corp"` 这类逗号分隔的 auth-param 列表。这里专门
/// 用一个带 `=` padding 的、更接近真实 NTLM Type-2 消息的 token 验证
/// 挑战原样传到了 authenticator 手上。
///
/// 会让这条测试变红的改法：把挑战解析里的判别式从"结构上是不是
/// token68"换回"字符串里含不含 `='"（brief 原文写法），这个 token
/// 会被整个丢弃，`seen` 永远是 `None`。
struct RecordsChallenge {
    seen: Arc<std::sync::Mutex<Option<String>>>,
}

#[async_trait::async_trait]
impl ProxyAuthenticator for RecordsChallenge {
    async fn next_token(&self, scheme: &str, challenge: Option<&str>) -> Option<String> {
        assert_eq!(scheme, "Negotiate");
        if let Some(c) = challenge {
            *self.seen.lock().unwrap() = Some(c.to_string());
        }
        Some("TlRMTVNTUAAD".into())
    }
}

#[tokio::test]
async fn proxy_authenticate_challenge_with_base64_padding_reaches_the_authenticator() {
    let (port, srv) = fake_proxy(vec![
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\n\r\n",
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate TlRMTVNTUAACAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n",
        "HTTP/1.1 200 Connection established\r\n\r\n",
    ])
    .await;
    let seen = Arc::new(std::sync::Mutex::new(None));
    let auth = RecordsChallenge { seen: seen.clone() };

    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    http_connect(&mut s, &target(), &auth).await.unwrap();
    srv.await.unwrap();

    assert_eq!(
        seen.lock().unwrap().as_deref(),
        Some("TlRMTVNTUAACAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    );
}

#[tokio::test]
async fn gives_up_when_authenticator_returns_none() {
    let (port, _srv) = fake_proxy(vec![
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\n",
    ])
    .await;
    struct Refuses;
    #[async_trait::async_trait]
    impl ProxyAuthenticator for Refuses {
        async fn next_token(&self, _: &str, _: Option<&str>) -> Option<String> {
            None
        }
    }
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let err = http_connect(&mut s, &target(), &Refuses).await.unwrap_err();
    assert_eq!(err.class(), ErrorClass::Fatal);
    assert!(matches!(err, Error::ProxyAuthFailed(_)));
}

/// R36：brief 原文只断言了"报的是 ProxyAuthFailed"，从不 join 假代理的
/// handle、从不看它实际应了几轮——`MAX_ROUNDS` 改成 1 之后这条测试原样全绿
/// （第一轮就被拒、协商器的 token 从没被接受，同样是 ProxyAuthFailed），
/// 名字里写的 five 从来没被真正钉住。改成 1000 才会红，但红的原因是假代理
/// 那 8 条脚本回复用光、socket 被关闭，读到的是 Tcp/Network 错误，不是
/// "存在上限"本身的证据。
///
/// 这里改成断言假代理实际看到的轮数（`seen.len()`）恰好等于 5：假代理只
/// 准备 5 条应答（不多不少），并在拿到 `http_connect` 的错误之后立刻
/// `drop` 客户端这一侧的 socket——这样无论真实上限被改成几，都不会卡死：
/// - 上限被收紧（比如改成 2）：客户端只发 2 轮就放弃，`drop(s)`
///   之后假代理的第 3 次 `read` 收到 EOF 提前退出循环，`seen.len() == 2`，
///   跟这里断言的 5 对不上，变红。
/// - 上限被放宽（比如改成 1000）：假代理的 5 条脚本回复用完之后
///   自然退出循环并返回，连接随之关闭；客户端发第 6 轮请求时读不到响应，
///   拿到的是 `Error::Tcp`，不是 `Error::ProxyAuthFailed`，
///   `assert!(matches!(err, Error::ProxyAuthFailed(_)))` 这一行先变红。
/// - 上限恰好是 5：5 条应答自然发完，`seen.len() == 5`，两条断言都过。
#[tokio::test]
async fn stops_after_five_rounds() {
    let replies = vec![
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\n\r\n";
        5
    ];
    struct Endless;
    #[async_trait::async_trait]
    impl ProxyAuthenticator for Endless {
        async fn next_token(&self, _: &str, _: Option<&str>) -> Option<String> {
            Some("AAAA".into())
        }
    }
    let (port, srv) = fake_proxy(replies).await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let err = http_connect(&mut s, &target(), &Endless).await.unwrap_err();
    assert!(matches!(err, Error::ProxyAuthFailed(_)), "{err}");
    drop(s);

    let seen = srv.await.unwrap();
    assert_eq!(
        seen.len(),
        5,
        "假代理实际看到的轮数应恰好等于上限 5；如果这个数字对不上，\
         要么上限被悄悄改动了，要么根本没有生效"
    );
}

#[tokio::test]
async fn other_status_codes_are_network_errors() {
    let (port, _srv) = fake_proxy(vec!["HTTP/1.1 502 Bad Gateway\r\n\r\n"]).await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let err = http_connect(&mut s, &target(), &NoProxyAuth)
        .await
        .unwrap_err();
    assert_eq!(err.class(), ErrorClass::Network);
    assert!(err.to_string().contains("502"), "{err}");
}

#[tokio::test]
async fn truncated_response_is_a_network_error() {
    let (port, _srv) = fake_proxy(vec!["HTTP/1.1 200 OK\r\n"]).await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    // 代理在 banner 之后关闭，头部始终不完整
    let err = http_connect(&mut s, &target(), &NoProxyAuth)
        .await
        .unwrap_err();
    assert_eq!(err.class(), ErrorClass::Network);
}
