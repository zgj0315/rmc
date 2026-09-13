//! Transport 的组装：DNS、TCP、可选代理、TLS。
//! TLS 用例对着 Gateway 计划的 docker 环境跑，需要 127.0.0.1:8443 在监听。
//!
//! R11/F13（brief 自身的缺陷，开工前预扫描已发现）：brief 原文让
//! `harness_ca_pem()` 用 `.expect(...)` 在文件不存在时直接 panic，而 brief
//! 给的 Step 4 命令顺序恰好是先跑非 ignored 测试、后起 docker、后跑
//! fetch-harness-cert.sh——四条不带 `#[ignore]` 的用例
//! （`resolve_dns_*`/`probe_tcp_*`）根本不需要真的建 TLS 连接，却全部经共享
//! 夹具 `transport_trusting_harness()` 间接调用 `harness_ca_pem()`，在证书
//! 文件还不存在时统统 panic。采用 Task 9 (`preflight.rs`) 已经在用的形状：
//! `if let Ok(pem) = ...`，读不到就跳过"追加信任根"这一步，不 panic——这四条
//! 用例本就不依赖那个根，跳过对它们没有任何影响。
//!
//! 两条真正需要 docker 环境的用例仍然标 `#[ignore]`：这是 Rust 测试里"跳过"
//! 的标准机制，`cargo test` 的汇总行会打印 `N ignored`，不会悄悄消失在
//! "全绿"里；而且这两条用例内部不做"文件缺失就提前 return"式的静默跳过——
//! 一旦有人真的传了 `--ignored` 却没有先起环境，会得到一次响亮的失败
//! （TLS 握手因为只信任 webpki 根而被拒绝，或者 TCP 连接失败），而不是一个
//! 假的绿色通过。`transport_trusting_harness()` 额外在证书文件缺失时打印一行
//! 原因到 stderr，方便这种情况被诊断，而不是让人误以为是网络抖动。

use rmc_core::addr::HostPort;
use rmc_core::error::{Error, ErrorClass};
use rmc_core::platform::{Conn, NoProxy, NoProxyAuth};
use rmc_core::transport::tls::TlsRoots;
use rmc_core::transport::Transport;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// `Conn = Box<dyn Io>` 没有实现 `Debug`（也不该为了这一件事去实现——`dyn Io`
/// 上没有任何有意义的调试信息可打，装一个只会打印类型名的 `Debug` 纯粹是为了
/// 让 `unwrap_err()` 能编译，属于给错误信息掺水）。`Result::unwrap_err` 要求
/// `Ok` 分支的类型实现 `Debug`，brief 原文直接在 `Result<Conn, Error>` 上调用
/// `unwrap_err()`，编译不过。用一次 `match` 换掉它。
fn expect_err(r: Result<Conn, Error>) -> Error {
    match r {
        Ok(_) => panic!("期望连接失败，实际却成功建立了连接"),
        Err(e) => e,
    }
}

fn harness_ca_path() -> std::path::PathBuf {
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/harness-ca.pem").into()
}

fn transport_trusting_harness() -> Transport {
    let mut roots = TlsRoots::webpki();
    match std::fs::read(harness_ca_path()) {
        Ok(pem) => roots.with_extra_pem(&pem).unwrap(),
        Err(e) => eprintln!(
            "跳过信任 harness 自签证书这一步（{e}）：{} 不存在。\
             需要 docker 环境的用例标了 #[ignore]，会照常运行、照常失败，\
             不会假装通过。先 `docker compose -f gateway/test-env/docker-compose.yml up -d --build` \
             再跑 `crates/rmc-core/tests/fetch-harness-cert.sh` 可以让它们跑起来。",
            harness_ca_path().display()
        ),
    }
    Transport::new(Arc::new(NoProxy), Arc::new(NoProxyAuth), roots)
}

fn gateway_tls() -> HostPort {
    "gateway.test:8443".parse().unwrap()
}

/// 一个在任何网络环境下都解析不出来的主机名。
///
/// brief 原文用 `"no-such-host.invalid"`——`.invalid` 是 RFC 2606 保留给
/// "肯定解析不出来"这种用途的 TLD，但这只是一个**约定**，靠的是 DNS
/// 解析器"老实"地在查不到时回 NXDOMAIN。现实里有相当一部分网络环境不老实：
/// 会把 NXDOMAIN 劫持成一个"提示页"IP（国内相当一部分 ISP 的 DNS 默认行为，
/// 也正是这台开发机所在网络的行为）。实测过：这台机器上
/// `no-such-host.invalid` 无论问哪个上游（系统默认的 114.114.114.114、还是
/// 直接问 8.8.8.8/1.1.1.1）都会被劫持成 198.18.0.4——用它的话，
/// `resolve_dns` 会"成功"返回这个劫持地址，测试断言的是"解析失败"这个分支，
/// 在这台机器上永远走不到，是假阳性风险，不是我们想验证的行为。
///
/// 换成一个单个 label 超过 63 字节的主机名：这是 RFC 1035 §3.1
/// 的硬性语法限制，glibc/BSD 的 resolver 库在真正发出网络请求之前，
/// 本地校验阶段就会直接拒绝——不摸网络，因此不受任何 DNS 劫持影响，在任何
/// 环境下都能确定性地走到"解析失败"这条分支。这个改动只影响测试用的
/// 主机名字符串，不影响 `resolve_dns` 本身的实现。
fn always_unresolvable_host() -> String {
    format!("{}.invalid", "a".repeat(64))
}

#[tokio::test]
async fn resolve_dns_returns_addresses_for_localhost() {
    let t = transport_trusting_harness();
    let addrs = t.resolve_dns("localhost").await.unwrap();
    assert!(!addrs.is_empty());
}

#[tokio::test]
async fn resolve_dns_failure_is_network_class() {
    let t = transport_trusting_harness();
    let err = t
        .resolve_dns(&always_unresolvable_host())
        .await
        .unwrap_err();
    assert_eq!(err.class(), ErrorClass::Network);
}

#[tokio::test]
async fn probe_tcp_reports_rtt_for_an_open_port() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    let t = transport_trusting_harness();
    let target: HostPort = format!("127.0.0.1:{port}").parse().unwrap();
    let rtt = t.probe_tcp(&target, Duration::from_secs(5)).await.unwrap();
    assert!(rtt < Duration::from_secs(5));
}

#[tokio::test]
async fn probe_tcp_on_closed_port_is_network_class() {
    let t = transport_trusting_harness();
    let target: HostPort = "127.0.0.1:1".parse().unwrap();
    let err = t
        .probe_tcp(&target, Duration::from_secs(3))
        .await
        .unwrap_err();
    assert_eq!(err.class(), ErrorClass::Network);
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn connect_wraps_tls_and_delivers_the_ssh_banner() {
    let t = transport_trusting_harness();
    let mut conn = t.connect(&gateway_tls()).await.unwrap();
    let mut banner = [0u8; 8];
    conn.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"SSH-2.0-");
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn untrusted_certificate_is_fatal_not_network() {
    // 只信任 webpki 根时，自签证书必须被判为致命错误。
    let t = Transport::new(Arc::new(NoProxy), Arc::new(NoProxyAuth), TlsRoots::webpki());
    let err = expect_err(t.connect(&gateway_tls()).await);
    assert_eq!(err.class(), ErrorClass::Fatal);
    assert!(err.to_string().contains("证书"), "{err}");
}

// --- 以下两条不经过 `Transport::connect`，直接调 `tls::wrap_tls`，按 IP
// 拨号、只把 "gateway.test" 当 SNI/证书校验名传进去，不依赖宿主把
// gateway.test 解析到 127.0.0.1（也就不需要改 /etc/hosts、不需要 root）。
// 它们跟上面两条 `#[ignore]` 用例验证的是同一件事——证书校验是不是真的在
// 起作用——只是换了个不需要改宿主配置的路径，专门用来在没有权限写
// /etc/hosts 的环境里（比如本任务开发时用的这台机器）也能把这件事跑通、
// 看到真实结果，而不是只能读代码猜。

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn wrap_tls_accepts_the_harness_cert_when_the_extra_root_is_trusted() {
    let pem = std::fs::read(harness_ca_path()).expect("先运行 fetch-harness-cert.sh");
    let mut roots = TlsRoots::webpki();
    roots.with_extra_pem(&pem).unwrap();

    let stream = tokio::net::TcpStream::connect("127.0.0.1:8443")
        .await
        .unwrap();
    let mut tls = rmc_core::transport::tls::wrap_tls(stream, "gateway.test", &roots)
        .await
        .unwrap();
    let mut banner = [0u8; 8];
    tls.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"SSH-2.0-");
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn wrap_tls_rejects_the_harness_cert_without_the_extra_root() {
    let roots = TlsRoots::webpki();
    let stream = tokio::net::TcpStream::connect("127.0.0.1:8443")
        .await
        .unwrap();
    let err = rmc_core::transport::tls::wrap_tls(stream, "gateway.test", &roots)
        .await
        .unwrap_err();
    assert_eq!(err.class(), ErrorClass::Fatal);
    assert!(err.to_string().contains("证书"), "{err}");
}
