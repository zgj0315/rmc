//! 预检四步的黑盒行为：见方案 3.4，`rmc_core::preflight`。
//!
//! 不需要 docker 的用例（没有 `#[ignore]` 的那几条）刻意不摸任何真实
//! 外部地址：
//!
//! - Gateway 地址要么用 `always_unresolvable_host()`（单个 label 超过 63
//!   字节，RFC 1035 §3.1 的硬性语法限制，resolver 本地校验阶段直接拒绝，
//!   不发网络请求），要么用 `localhost`（走 loopback，不查外部 DNS）——
//!   不用 `no-such-host.invalid`/`gateway.test` 这类名字，本机网络会把
//!   NXDOMAIN 劫持成一个"提示页" IP（8.8.8.8、1.1.1.1 都一样，Task 6 已经
//!   踩过），会让"预期 DNS 失败"的测试在这台机器上假阳性地走错分支。
//! - 一体机地址要么绑一个端口立刻释放（保证空置，不依赖某个固定端口号
//!   "大概率没人监听"——`ssh::pump` 里同名的进程内测试就是这么干的，见
//!   R53），要么绑一个真的在监听、但故意不说 SSH 的端口，专门用来验证
//!   `STEP_APPLIANCE_TCP` 真的在看 banner 内容，不是只看"连不连得上"。
//!
//! 每个用例都套了一层外层超时（`preflight_within`），不是可选项——这个
//! crate 已经被"失败路径报不出错、只会一直挂着"坑过不止一次（见
//! `ssh::test_support` 模块文档、Task 7 报告）。
//!
//! 需要 docker 环境的三条仍然标 `#[ignore]`，与 `tests/transport.rs`/
//! `tests/ssh_tunnel.rs` 现有的十几条是同一个历史遗留限制（R40/R46）：
//! 这台开发机没有 `/etc/hosts` 的 sudo 权限，`gateway.test` 解析不到
//! docker 环境里的 Gateway，见 `tests/transport.rs` 顶部的说明。
//! `appliance_hostkey_step_reports_a_sha256_fingerprint` 是例外——它只
//! 检查一体机那一步，一体机地址是 docker 直接发布到宿主的
//! `127.0.0.1:2322`（不涉及任何主机名解析），本任务开发时真的起过一次
//! `gateway/test-env` 的 `appliance` 服务验证过这一条，见任务报告。

use rmc_core::addr::HostPort;
use rmc_core::error::ErrorClass;
use rmc_core::platform::{NoProxy, NoProxyAuth};
use rmc_core::preflight::{
    self, StepOutcome, STEP_APPLIANCE_HOSTKEY, STEP_APPLIANCE_TCP, STEP_GATEWAY_DNS,
    STEP_GATEWAY_TLS,
};
use rmc_core::transport::tls::TlsRoots;
use rmc_core::transport::Transport;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

fn transport() -> Transport {
    let mut roots = TlsRoots::webpki();
    if let Ok(pem) = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/harness-ca.pem"
    )) {
        roots.with_extra_pem(&pem).unwrap();
    }
    Transport::new(Arc::new(NoProxy), Arc::new(NoProxyAuth), roots)
}

/// 单个 label 超过 63 字节：RFC 1035 §3.1 的硬性语法限制，resolver 在
/// 真正发出网络请求之前、本地校验阶段就会直接拒绝——不摸网络，因此不
/// 受 DNS 劫持影响，在任何环境下都能确定性地走到"解析失败"这条分支。
/// 与 `tests/transport.rs` 里的同名帮助函数逻辑一致（各测试二进制独立
/// 编译，不共享源码，见该文件顶部关于 `tests/common` 取舍的说明）。
fn always_unresolvable_host() -> String {
    format!("{}.invalid", "a".repeat(64))
}

fn unresolvable_gateway() -> HostPort {
    format!("{}:443", always_unresolvable_host())
        .parse()
        .unwrap()
}

/// 绑一个端口立刻释放：地址合法、端口号本身刚刚还真的没人监听，比"挑一个
/// 固定端口号，赌它大概率空闲"更可靠——同一个手法见
/// `crates/rmc-core/src/ssh/pump.rs` 里
/// `unreachable_appliance_reports_dial_failure_and_keeps_the_session_handler_alive`
/// （R53）。
async fn dead_appliance() -> HostPort {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    HostPort::new("127.0.0.1", addr.port()).unwrap()
}

/// 给预检测试套一层外层超时：真出问题应该在几秒内报错，不是让 `cargo
/// test` 无限期挂起——这个 crate 已经被这类死锁坑过不止一次。
async fn preflight_within<F: Future>(what: &str, fut: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(20), fut)
        .await
        .unwrap_or_else(|_| panic!("等待「{what}」超过 20 秒仍未完成，判定为死锁"))
}

#[tokio::test]
async fn report_lists_four_steps_in_fixed_order() {
    let appliance = dead_appliance().await;
    let r = preflight_within(
        "四步固定顺序",
        preflight::run(&transport(), &unresolvable_gateway(), &appliance),
    )
    .await;
    let names: Vec<_> = r.steps.iter().map(|s| s.name).collect();
    assert_eq!(
        names,
        vec![
            STEP_APPLIANCE_TCP,
            STEP_APPLIANCE_HOSTKEY,
            STEP_GATEWAY_DNS,
            STEP_GATEWAY_TLS
        ]
    );
}

// 会让这条测试变红的实现改法：把 `run()` 里"一体机 TCP 失败就把 host key
// 步骤标成 Skipped"的分支删掉、改成不管三七二十一都去跑
// `appliance_host_key`——那样 `steps[1]` 会变成一次新的、针对同一个不可达
// 地址的 `Fail`，不是 `Skipped`，这里的 `matches!` 断言会先叫出来。
#[tokio::test]
async fn unreachable_appliance_fails_first_step_and_skips_hostkey() {
    let appliance = dead_appliance().await;
    let r = preflight_within(
        "一体机不可达",
        preflight::run(&transport(), &unresolvable_gateway(), &appliance),
    )
    .await;
    assert!(!r.passed());
    let first = r.first_failure().unwrap();
    assert_eq!(first.name, STEP_APPLIANCE_TCP);
    // 不止"是不是 Fail"，连分类都要对：一体机不可达必须落
    // `ApplianceUnreachable`（转 degraded、周期探测），不能落一般的
    // `Network`（无限退避重连）——两者对 Task 10 的重连行为是不同的处置。
    match &first.outcome {
        StepOutcome::Fail { class, .. } => {
            assert_eq!(*class, ErrorClass::ApplianceUnreachable)
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(r.steps[1].outcome, StepOutcome::Skipped { .. }));
}

// 会让这条测试变红的实现改法：把 DNS 失败时"TLS 步骤标成 Skipped"的分支
// 删掉，改成不管 DNS 是否成功都去跑 `transport.connect`——那样 `steps[3]`
// 会变成对着一个从没解析出地址的 host 发起连接产生的某种 `Fail`，不是
// `Skipped`。
#[tokio::test]
async fn bad_gateway_name_fails_dns_and_skips_tls() {
    let appliance = dead_appliance().await;
    let r = preflight_within(
        "Gateway 域名解析失败",
        preflight::run(&transport(), &unresolvable_gateway(), &appliance),
    )
    .await;
    let dns = r.steps.iter().find(|s| s.name == STEP_GATEWAY_DNS).unwrap();
    match &dns.outcome {
        StepOutcome::Fail { class, .. } => assert_eq!(*class, ErrorClass::Network),
        other => panic!("{other:?}"),
    }
    assert!(matches!(r.steps[3].outcome, StepOutcome::Skipped { .. }));
}

// 这条不在 brief 原始草稿里：给 `STEP_APPLIANCE_TCP` 补一条"结果真的被
// 采纳"的证据——一个真的在监听、真的能三次握手成功的端口，只要它不说
// SSH，这一步也必须失败，而不是把"连得上 socket"直接当成"这一步通过"。
// 会让这条测试变红的实现改法：`appliance_banner` 里删掉
// `banner.starts_with("SSH-2.0-")` 这个检查，只要连上了就报 Pass。
#[tokio::test]
async fn appliance_tcp_step_fails_when_the_port_answers_but_is_not_ssh() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let _ = sock.write_all(b"NOT-AN-SSH-BANNER\r\n").await;
            // 稍微留一会儿再关闭，确保对端的 read 拿到的是这几个字节，
            // 而不是巧合地直接读到 EOF（0 字节）。
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    let appliance = HostPort::new("127.0.0.1", port).unwrap();

    let r = preflight_within(
        "一体机端口不说 SSH",
        preflight::run(&transport(), &unresolvable_gateway(), &appliance),
    )
    .await;

    let tcp = r
        .steps
        .iter()
        .find(|s| s.name == STEP_APPLIANCE_TCP)
        .unwrap();
    match &tcp.outcome {
        StepOutcome::Fail { class, detail } => {
            assert_eq!(*class, ErrorClass::ApplianceUnreachable);
            assert!(detail.contains("SSH banner"), "{detail}");
        }
        other => panic!("端口能连上但不说 SSH，这一步不该是 {other:?}"),
    }
    assert!(matches!(r.steps[1].outcome, StepOutcome::Skipped { .. }));
}

// 这条也不在 brief 原始草稿里：`bad_gateway_name_fails_dns_and_skips_tls`
// 只证明了"DNS 失败 ⇒ TLS 步骤被跳过"，没有反向证据——如果实现把 TLS 步骤
// 写死成"DNS 一失败就 Skip，DNS 一成功也 Skip"（也就是压根没真的调用
// `transport.connect`），前一条测试照样会通过。这里用 `localhost`（保证
// DNS 成功，不查外部网络）加一个真的在监听、但完全不说 TLS 的端口，证明
// TLS 步骤在 DNS 成功之后真的会运行、真的会把连接结果当回事——它必须是
// `Fail`，不是 `Skipped`，也不是巧合的 `Pass`。
// 会让这条测试变红的实现改法：把 `if dns_ok { ... } else { Skipped }`
// 里的 `if` 条件永远走 `else` 分支（不管 DNS 是否成功都报 Skipped）。
#[tokio::test]
async fn gateway_tls_step_runs_and_fails_when_dns_succeeds_but_peer_is_not_tls() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        // 接受连接后什么都不做就关掉——TLS 客户端等不到合法的 ServerHello。
        let _ = listener.accept().await;
    });
    let gateway: HostPort = format!("localhost:{port}").parse().unwrap();
    let appliance = dead_appliance().await;

    let r = preflight_within(
        "Gateway 端口不说 TLS",
        preflight::run(&transport(), &gateway, &appliance),
    )
    .await;

    let dns = r.steps.iter().find(|s| s.name == STEP_GATEWAY_DNS).unwrap();
    assert!(
        matches!(dns.outcome, StepOutcome::Pass { .. }),
        "localhost 应该总能解析成功：{:?}",
        dns.outcome
    );

    let tls = r.steps.iter().find(|s| s.name == STEP_GATEWAY_TLS).unwrap();
    match &tls.outcome {
        StepOutcome::Fail { class, .. } => {
            assert_eq!(
                *class,
                ErrorClass::Network,
                "链路问题应归 Network，不是 Fatal"
            )
        }
        other => panic!("DNS 已经成功，TLS 步骤不该是 {other:?}"),
    }
}

fn gateway_tls() -> HostPort {
    "gateway.test:8443".parse().unwrap()
}

fn appliance_ssh() -> HostPort {
    "127.0.0.1:2322".parse().unwrap()
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行，且 gateway.test 能解析（这台机器没有 /etc/hosts 的 sudo 权限，见 tests/transport.rs 顶部说明）"]
async fn all_four_steps_pass_against_the_harness() {
    let r = preflight::run(&transport(), &gateway_tls(), &appliance_ssh()).await;
    assert!(r.passed(), "{:#?}", r.steps);
}

// 与其他两条 `#[ignore]` 用例不同：这一条只依赖 docker 发布到宿主的
// `127.0.0.1:2322`（一体机 SSH，容器内部端口是方案 §3.8 要求的
// 61001），不涉及任何主机名解析——`gateway` 参数在这条用例里从头到尾
// 只影响 DNS/TLS 那两步，不影响这里断言的一体机步骤。本任务开发时真的
// 起过一次 `gateway/test-env` 的 `appliance` 服务验证过，见任务报告。
#[tokio::test]
#[ignore = "需要 gateway/test-env 的 appliance 服务在运行"]
async fn appliance_hostkey_step_reports_a_sha256_fingerprint() {
    let r = preflight::run(&transport(), &unresolvable_gateway(), &appliance_ssh()).await;
    let step = r
        .steps
        .iter()
        .find(|s| s.name == STEP_APPLIANCE_HOSTKEY)
        .unwrap();
    match &step.outcome {
        StepOutcome::Pass { detail } => assert!(detail.contains("SHA256:"), "{detail}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行，且 gateway.test 能解析"]
async fn untrusted_gateway_cert_fails_tls_step_as_fatal() {
    let t = Transport::new(Arc::new(NoProxy), Arc::new(NoProxyAuth), TlsRoots::webpki());
    let r = preflight::run(&t, &gateway_tls(), &appliance_ssh()).await;
    let tls = r.steps.iter().find(|s| s.name == STEP_GATEWAY_TLS).unwrap();
    match &tls.outcome {
        StepOutcome::Fail { class, detail } => {
            assert_eq!(*class, ErrorClass::Fatal);
            assert!(detail.contains("证书"), "{detail}");
        }
        other => panic!("{other:?}"),
    }
}
