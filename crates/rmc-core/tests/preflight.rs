//! 预检四步的黑盒行为：见方案 3.4，`rmc_core::preflight`。
//!
//! 不需要 docker 的用例（没有 `#[ignore]` 的那几条）刻意不摸任何真实
//! 外部地址：
//!
//! - Gateway 地址要么用 `undialable_gateway()`/`unresolvable_gateway()`
//!   （分别是"绑一个端口立刻释放"与"单个 label 超过 63 字节，RFC 1035
//!   §3.1 的硬性语法限制，resolver 本地校验阶段直接拒绝，不发网络
//!   请求"两种确定性失败），要么用 `localhost`（走 loopback，不查外部
//!   DNS）——不用 `no-such-host.invalid`/`gateway.test` 这类名字，本机
//!   网络会把 NXDOMAIN 劫持成一个"提示页" IP（8.8.8.8、1.1.1.1 都一样，
//!   Task 6 已经踩过），会让"预期连不上"的测试在这台机器上假阳性地走
//!   错分支。
//! - 一体机地址要么绑一个端口立刻释放（保证空置，不依赖某个固定端口号
//!   "大概率没人监听"——`ssh::pump` 里同名的进程内测试就是这么干的，见
//!   R53），要么绑一个真的在监听、但故意不说 SSH 的端口，专门用来验证
//!   `STEP_APPLIANCE_TCP` 真的在看 banner 内容，不是只看"连不连得上"。
//!
//! 每个用例都套了一层外层超时（`preflight_within`），不是可选项——这个
//! crate 已经被"失败路径报不出错、只会一直挂着"坑过不止一次（见
//! `ssh::test_support` 模块文档、Task 7 报告）。
//!
//! # Task 9 订正：DNS 那一步已经不存在，Gateway TLS 换成核对指纹
//!
//! 连接码里的服务器地址只能是 IP（spec §4.2「只用 IP，不接受域名」），
//! `preflight::run` 因此不再单独探一次域名解析——原来的
//! `STEP_GATEWAY_DNS` 与 `STEP_GATEWAY_TLS` 两步合并改造成
//! `STEP_GATEWAY_REACH`（TCP 拨号，经代理时含 CONNECT）与
//! `STEP_GATEWAY_TLS`（核对连接码里的指纹，不再信任任何公共 CA 或额外
//! 信任根）。这份文件里原来靠 `TlsRoots::with_extra_pem` 信任 docker
//! harness 自签证书的两条 `#[ignore]` 用例（`all_four_steps_pass_
//! against_the_harness`、`untrusted_gateway_cert_fails_tls_step_as_
//! fatal`）已经删掉——`TlsRoots` 这个类型本身不存在了，它们的等价覆盖、
//! 而且更强（指纹一正一反成对验证，不用 docker）已经搬进
//! `crates/rmc-core/src/preflight.rs` 内部的
//! `all_four_steps_pass_when_the_fingerprint_matches`/
//! `gateway_tls_step_fails_as_fatal_when_the_fingerprint_does_not_match_
//! while_reach_still_passes`。
//!
//! 需要 docker 环境的场景因此已经清零，本文件不再有 `#[ignore]` 用例。
//!
//! R56（第二轮评审）：原来这里还有第三条 ignored 用例
//! `appliance_hostkey_step_reports_a_sha256_fingerprint`，只检查一体机
//! 那一步、只依赖 docker 发布的 `127.0.0.1:2322`，根本不需要
//! `/etc/hosts` 这道限制——继续把它挂在"需要 docker"这个理由下没有道理：
//! `appliance_host_key` 需要的只是"TCP 那一头有个会做 SSH 握手的服务
//! 端"，不需要真的是 OpenSSH。已删掉，改成
//! `rmc_core::preflight::tests::appliance_tcp_and_hostkey_steps_pass_over_a_real_tcp_socket`
//! （`src/preflight.rs` 内部单测）：用 `russh::server::run_stream` 直接
//! 喂一个真实的 `tokio::net::TcpStream`，在进程内把"服务端"这一半也用
//! russh 实现，覆盖范围比原来那条更宽（原来只测 host key 这一步，这条
//! 连 TCP／banner 这一步也一起覆盖了），而且默认就跑，不再计入本 crate
//! 的 ignored 总数。

use rmc_core::addr::HostPort;
use rmc_core::code::ServerFingerprint;
use rmc_core::error::ErrorClass;
use rmc_core::platform::{NoProxy, NoProxyAuth};
use rmc_core::preflight::{
    self, StepOutcome, STEP_APPLIANCE_HOSTKEY, STEP_APPLIANCE_TCP, STEP_GATEWAY_REACH,
    STEP_GATEWAY_TLS,
};
use rmc_core::transport::Transport;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

fn transport() -> Transport {
    Transport::new(Arc::new(NoProxy), Arc::new(NoProxyAuth))
}

/// 占位指纹：只在"运维服务器根本连不上/不说 TLS"这类用例里用，反正
/// TLS 步骤会在核对指纹之前就已经因为别的原因失败或被跳过，传哪个值
/// 都不影响这些用例要断言的东西。
fn placeholder_pin() -> ServerFingerprint {
    ServerFingerprint::of_ed25519_public(&[0u8; 32])
}

/// 单个 label 超过 63 字节：RFC 1035 §3.1 的硬性语法限制，resolver 在
/// 真正发出网络请求之前、本地校验阶段就会直接拒绝——不摸网络，因此不
/// 受 DNS 劫持影响，在任何环境下都能确定性地走到"连不上"这条分支。
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

/// 同上，给运维服务器用：一个刚刚还真的没人监听的端口，TCP 连接会被
/// 瞬间拒绝——不需要 docker，也不需要 DNS。
async fn undialable_gateway() -> HostPort {
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
    let pin = placeholder_pin();
    let r = preflight_within(
        "四步固定顺序",
        preflight::run(&transport(), &unresolvable_gateway(), &pin, &appliance),
    )
    .await;
    let names: Vec<_> = r.steps.iter().map(|s| s.name).collect();
    assert_eq!(
        names,
        vec![
            STEP_APPLIANCE_TCP,
            STEP_APPLIANCE_HOSTKEY,
            STEP_GATEWAY_REACH,
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
    let pin = placeholder_pin();
    let r = preflight_within(
        "一体机不可达",
        preflight::run(&transport(), &unresolvable_gateway(), &pin, &appliance),
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

/// Task 9 改名（原 `bad_gateway_name_fails_dns_and_skips_tls`）：DNS 那
/// 一步已经不存在，夹具从"解析不了的域名"换成"一个没人监听的 127.0.0.1
/// 端口"——不需要 docker，也不需要 DNS。
///
/// 变异三枪之一（brief Step 6）：把 `run()` 里"运维服务器连不上就把
/// TLS 步骤标成 Skipped"的分支删掉（四步变三步）——`r.steps[3]` 的
/// 索引会直接越界 panic，这条当场红，比"内容错了"更响亮。
#[tokio::test]
async fn an_unreachable_server_fails_the_reach_step_and_skips_tls() {
    let appliance = dead_appliance().await;
    let gateway = undialable_gateway().await;
    let pin = placeholder_pin();
    let r = preflight_within(
        "运维服务器连不上",
        preflight::run(&transport(), &gateway, &pin, &appliance),
    )
    .await;
    let reach = r
        .steps
        .iter()
        .find(|s| s.name == STEP_GATEWAY_REACH)
        .unwrap();
    match &reach.outcome {
        StepOutcome::Fail { class, .. } => assert_eq!(*class, ErrorClass::Network),
        other => panic!("{other:?}"),
    }
    assert!(matches!(r.steps[3].outcome, StepOutcome::Skipped { .. }));
}

// R54（第二轮评审，HIGH）：`STEP_APPLIANCE_TCP` 的 Pass 方向之前一个字
// 都没有测试守着——本文件原有用例只覆盖 Fail/Skipped 两个方向（下面的
// `appliance_tcp_step_fails_when_the_port_answers_but_is_not_ssh` 是
// Fail 方向），评审把 `appliance_banner` 的 `Ok(banner)` 分支改成恒定
// `Err`，全套 `cargo test` 依旧全绿，因为 Pass 方向唯一的把关者是
// `#[ignore]` 的 `all_four_steps_pass_against_the_harness`，本仓没有
// 任何 CI 会跑它。这条补上 Pass 方向：一个真的说 SSH 的端口，这一步
// 必须是 `Pass`，且 detail 里必须包含真实读到的 banner 文本（不是巧合
// 命中"SSH banner"这几个字——banner 内容本身带一段不会出现在错误信息
// 里的独有字符串）。
// 会让这条测试变红的实现改法：把 `appliance_banner` 的 `Ok(banner)`
// 分支改成恒定 `Err(...)`（哪怕真的读到了合法的 SSH banner）——本地
// 验证过：改完之后这条测试立刻在 `match` 的 `other` 分支上 panic。
#[tokio::test]
async fn appliance_tcp_step_passes_and_reports_the_real_banner() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let _ = sock.write_all(b"SSH-2.0-TestApplianceD-8f2c1a\r\n").await;
            // 稍微留一会儿再关闭，确保对端的 read 拿到的是这几个字节。
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    let appliance = HostPort::new("127.0.0.1", port).unwrap();
    let pin = placeholder_pin();

    let r = preflight_within(
        "一体机端口真的说 SSH",
        preflight::run(&transport(), &unresolvable_gateway(), &pin, &appliance),
    )
    .await;

    let tcp = r
        .steps
        .iter()
        .find(|s| s.name == STEP_APPLIANCE_TCP)
        .unwrap();
    match &tcp.outcome {
        StepOutcome::Pass { detail } => {
            assert!(detail.contains("SSH-2.0-TestApplianceD-8f2c1a"), "{detail}");
        }
        other => panic!("端口真的说 SSH，这一步不该是 {other:?}"),
    }
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
    let pin = placeholder_pin();

    let r = preflight_within(
        "一体机端口不说 SSH",
        preflight::run(&transport(), &unresolvable_gateway(), &pin, &appliance),
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

// Task 9 改名（原 `gateway_tls_step_runs_and_fails_when_dns_succeeds_
// but_peer_is_not_tls`）：这条不在 brief 原始草稿里，是给"运维服务器
// 连通"与"运维服务器 TLS"两步补的一条反向证据——只证明"连不上 ⇒ TLS
// 步骤被跳过"（上面 `an_unreachable_server_fails_the_reach_step_and_
// skips_tls` 那条）不够，如果实现把 TLS 步骤写死成"连通失败就 Skip，
// 连通成功也 Skip"（也就是压根没真的调用 `wrap_tls`），前一条测试照样
// 会通过。这里用一个真的在监听、但完全不说 TLS 的端口，证明 TLS 步骤
// 在连通成功之后真的会运行、真的会把握手结果当回事——它必须是 `Fail`，
// 不是 `Skipped`，也不是巧合的 `Pass`。
// 会让这条测试变红的实现改法：把 `if let Ok(stream) = dial { ... } else
// { Skipped }` 里的分支永远走 `Err` 那一半（不管连通是否成功都报
// Skipped）。
#[tokio::test]
async fn gateway_tls_step_runs_and_fails_when_reach_succeeds_but_peer_is_not_tls() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        // 接受连接后什么都不做就关掉——TLS 客户端等不到合法的 ServerHello。
        let _ = listener.accept().await;
    });
    let gateway = HostPort::new("127.0.0.1", port).unwrap();
    let appliance = dead_appliance().await;
    let pin = placeholder_pin();

    let r = preflight_within(
        "运维服务器端口不说 TLS",
        preflight::run(&transport(), &gateway, &pin, &appliance),
    )
    .await;

    let reach = r
        .steps
        .iter()
        .find(|s| s.name == STEP_GATEWAY_REACH)
        .unwrap();
    assert!(
        matches!(reach.outcome, StepOutcome::Pass { .. }),
        "监听端口应该总能连上：{:?}",
        reach.outcome
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
        other => panic!("连通已经成功，TLS 步骤不该是 {other:?}"),
    }
}
