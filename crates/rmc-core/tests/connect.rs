//! HTTP CONNECT 的协议流程，用本地假代理驱动。

use rmc_core::addr::HostPort;
use rmc_core::error::{Error, ErrorClass};
use rmc_core::platform::{NoProxyAuth, ProxyAuthenticator};
use rmc_core::transport::connect::http_connect;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

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
    async fn begin_connection(&self) {}

    async fn next_token(&self, scheme: &str, challenge: Option<&str>) -> Option<Zeroizing<String>> {
        assert_eq!(scheme, "Negotiate");
        let mut seen = self.seen_challenges.lock().unwrap();
        seen.push(challenge.map(str::to_string));
        match seen.len() {
            1 => Some(Zeroizing::new("TlRMTVNTUAAB".into())),
            2 => Some(Zeroizing::new("TlRMTVNTUAAD".into())),
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
    async fn begin_connection(&self) {}

    async fn next_token(&self, scheme: &str, challenge: Option<&str>) -> Option<Zeroizing<String>> {
        assert_eq!(scheme, "Negotiate");
        if let Some(c) = challenge {
            *self.seen.lock().unwrap() = Some(c.to_string());
        }
        Some(Zeroizing::new("TlRMTVNTUAAD".into()))
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
        async fn begin_connection(&self) {}

        async fn next_token(&self, _: &str, _: Option<&str>) -> Option<Zeroizing<String>> {
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
        async fn begin_connection(&self) {}

        async fn next_token(&self, _: &str, _: Option<&str>) -> Option<Zeroizing<String>> {
            Some(Zeroizing::new("AAAA".into()))
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

/// 记下协商器被问到的 scheme，永远给同一个 token。
struct RecordsScheme {
    seen: Arc<std::sync::Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl ProxyAuthenticator for RecordsScheme {
    async fn begin_connection(&self) {}

    async fn next_token(&self, scheme: &str, _: Option<&str>) -> Option<Zeroizing<String>> {
        self.seen.lock().unwrap().push(scheme.to_string());
        Some(Zeroizing::new("TlRMTVNTUAAB".into()))
    }
}

/// ★ W35。企业代理同时通告 Basic / NTLM / Negotiate 是常态，而且很可能
/// 把 Basic 排在最前面（顺序不由我们控制）。只取第一条
/// `Proxy-Authenticate` 会把整个 SSPI 能力旁路掉：协商器被问的是
/// `Basic`，它只能返回 None，`http_connect` 报 ProxyAuthFailed——而这台
/// 机器明明能做 Negotiate。
///
/// 会让这条测试变红的改法：`read_response` 里恢复 `auth_scheme.is_none()`
/// 那道"只收第一条"的守卫，或者把 `select_challenge` 换成
/// `challenges.first()`——协商器会被问 `Basic`。
#[tokio::test]
async fn negotiate_is_picked_even_when_the_proxy_lists_basic_first() {
    let (port, srv) = fake_proxy(vec![
        "HTTP/1.1 407 Proxy Authentication Required\r\n\
         Proxy-Authenticate: Basic realm=\"corp\"\r\n\
         Proxy-Authenticate: NTLM\r\n\
         Proxy-Authenticate: Negotiate\r\n\r\n",
        "HTTP/1.1 200 Connection established\r\n\r\n",
    ])
    .await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let auth = RecordsScheme { seen: seen.clone() };

    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    http_connect(&mut s, &target(), &auth).await.unwrap();

    assert_eq!(seen.lock().unwrap().clone(), vec!["Negotiate".to_string()]);
    let sent = srv.await.unwrap();
    assert!(
        sent[1].contains("Proxy-Authorization: Negotiate TlRMTVNTUAAB"),
        "{}",
        sent[1]
    );
}

/// 同一件事的另一种写法：三个 scheme 挤在一行里用逗号分隔。
#[tokio::test]
async fn negotiate_is_picked_out_of_one_comma_separated_header_line() {
    let (port, _srv) = fake_proxy(vec![
        "HTTP/1.1 407 Proxy Authentication Required\r\n\
         Proxy-Authenticate: Basic realm=\"corp\", NTLM, Negotiate\r\n\r\n",
        "HTTP/1.1 200 Connection established\r\n\r\n",
    ])
    .await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let auth = RecordsScheme { seen: seen.clone() };

    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    http_connect(&mut s, &target(), &auth).await.unwrap();
    assert_eq!(seen.lock().unwrap().clone(), vec!["Negotiate".to_string()]);
}

/// 代理回 407 却一个 `Proxy-Authenticate` 都没给。
///
/// 旧实现在这里 `unwrap_or_else(|| "Basic".into())`，于是错误文案与诊断
/// 页会说"代理要求 Basic 认证"——代理从没说过这句话，现场工程师会照着
/// 去查一个不存在的 Basic 配置。
///
/// 会让这条测试变红的改法：把那句 `unwrap_or_else(|| "Basic")` 加回来
/// ——协商器会被叫醒（`seen` 不再为空），错误文案里会出现 "Basic"。
#[tokio::test]
async fn a_407_without_any_scheme_is_not_reported_as_basic() {
    let (port, _srv) = fake_proxy(vec![
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Agent: corp\r\n\r\n",
    ])
    .await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let auth = RecordsScheme { seen: seen.clone() };

    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let err = http_connect(&mut s, &target(), &auth).await.unwrap_err();
    assert!(matches!(err, Error::ProxyAuthFailed(_)), "{err}");
    let text = err.to_string();
    assert!(
        !text.contains("Basic"),
        "不能编一个代理没说过的 scheme：{text}"
    );
    assert!(text.contains("Proxy-Authenticate"), "{text}");
    assert!(
        seen.lock().unwrap().is_empty(),
        "没有 scheme 时不该去叫醒协商器"
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

/// 按发生的先后记下协商器被调用的每一件事。
struct RecordsCalls {
    calls: Arc<std::sync::Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl ProxyAuthenticator for RecordsCalls {
    async fn begin_connection(&self) {
        self.calls.lock().unwrap().push("begin_connection".into());
    }

    async fn next_token(&self, scheme: &str, _: Option<&str>) -> Option<Zeroizing<String>> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("next_token:{scheme}"));
        Some(Zeroizing::new("TlRMTVNTUAAB".into()))
    }
}

/// ★ W45。`http_connect` 每被调用一次就是一条**新的** TCP 连接上的一次
/// CONNECT 尝试，而 Negotiate/NTLM 是连接绑定的认证——协商器必须在这里
/// 被告知连接边界，否则它只能从"这个 407 带不带 token68"去猜，而那个
/// 信号在现实里承担了两个互斥的含义（见
/// `ProxyAuthenticator::begin_connection` 的文档）。
///
/// 三件事一起钉住，缺一条这个保证就不成立：
/// 1. **调到了**——把 `auth.begin_connection().await;` 那一行删掉就红；
/// 2. **排在第一次 `next_token` 之前**——挪到循环里面（或循环之后）就红；
/// 3. **一条连接只调一次**——挪进 `for` 循环体就红（这里是三轮协商，
///    会看到三次 `begin_connection`）。
#[tokio::test]
async fn http_connect_marks_the_connection_boundary_once_before_any_token() {
    let (port, srv) = fake_proxy(vec![
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\n\r\n",
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate TlRMTVNTUAAC\r\n\r\n",
        "HTTP/1.1 200 Connection established\r\n\r\n",
    ])
    .await;
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let auth = RecordsCalls {
        calls: Arc::clone(&calls),
    };

    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    http_connect(&mut s, &target(), &auth).await.unwrap();
    drop(s);
    let _ = srv.await;

    assert_eq!(
        calls.lock().unwrap().clone(),
        vec![
            "begin_connection".to_string(),
            "next_token:Negotiate".to_string(),
            "next_token:Negotiate".to_string(),
        ]
    );
}

/// 上一条的另一半：**两次** `http_connect` 就是两条连接，边界要划两次。
/// 这正是 Supervisor 重连时的形状——协商器凭这一条才知道该把上一条连接
/// 的安全上下文丢掉。
#[tokio::test]
async fn every_connect_attempt_gets_its_own_boundary() {
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    for _ in 0..2 {
        let (port, srv) = fake_proxy(vec![
            "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\n\r\n",
            "HTTP/1.1 200 Connection established\r\n\r\n",
        ])
        .await;
        let auth = RecordsCalls {
            calls: Arc::clone(&calls),
        };
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        http_connect(&mut s, &target(), &auth).await.unwrap();
        drop(s);
        let _ = srv.await;
    }

    assert_eq!(
        calls.lock().unwrap().clone(),
        vec![
            "begin_connection".to_string(),
            "next_token:Negotiate".to_string(),
            "begin_connection".to_string(),
            "next_token:Negotiate".to_string(),
        ]
    );
}
