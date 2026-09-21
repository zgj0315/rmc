//! Transport 的组装：DNS、TCP、可选代理。
//!
//! Task 9 订正：TLS 不再校验一份可复用的信任根（`TlsRoots` 整个被删掉），
//! 核对的是连接码里的指纹，每次 `wrap_tls`/`connect` 单独传入——本文件
//! 原来对着 docker harness 跑的 TLS 用例（`connect_wraps_tls_and_
//! delivers_the_ssh_banner`、`untrusted_certificate_is_fatal_not_network`、
//! `wrap_tls_accepts_the_harness_cert_when_the_extra_root_is_trusted`、
//! `wrap_tls_rejects_the_harness_cert_without_the_extra_root`）连同
//! `transport_trusting_harness()`/`harness_ca_path()`/`gateway_tls()`
//! 这几个只为它们存在的夹具已经删掉——它们的等价覆盖、而且更强（不用
//! docker，进程内起一个真正的 rustls TLS 服务端）已经搬进
//! `crates/rmc-core/src/transport/tls.rs` 的单元测试
//! （`wrap_tls_accepts_the_server_whose_key_matches_the_pin`/
//! `wrap_tls_rejects_a_server_whose_key_does_not_match_as_fatal`）。
//!
//! 下面四条跟 TLS 无关，不依赖 docker，本来就不用 harness 的信任根，
//! 原样保留。

use rmc_core::addr::HostPort;
use rmc_core::error::ErrorClass;
use rmc_core::platform::{NoProxy, NoProxyAuth};
use rmc_core::transport::Transport;
use std::sync::Arc;
use std::time::Duration;

fn transport() -> Transport {
    Transport::new(Arc::new(NoProxy), Arc::new(NoProxyAuth))
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
    let t = transport();
    let addrs = t.resolve_dns("localhost").await.unwrap();
    assert!(!addrs.is_empty());
}

#[tokio::test]
async fn resolve_dns_failure_is_network_class() {
    let t = transport();
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
    let t = transport();
    let target: HostPort = format!("127.0.0.1:{port}").parse().unwrap();
    let rtt = t.probe_tcp(&target, Duration::from_secs(5)).await.unwrap();
    assert!(rtt < Duration::from_secs(5));
}

#[tokio::test]
async fn probe_tcp_on_closed_port_is_network_class() {
    let t = transport();
    let target: HostPort = "127.0.0.1:1".parse().unwrap();
    let err = t
        .probe_tcp(&target, Duration::from_secs(3))
        .await
        .unwrap_err();
    assert_eq!(err.class(), ErrorClass::Network);
}
