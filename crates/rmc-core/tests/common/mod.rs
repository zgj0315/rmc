//! `tests/ssh_tunnel.rs` 与 `tests/forwarding.rs` 共用的夹具，跑在
//! gateway/test-env 上，两边都用 `mod common; use common::*;` 引入。
//!
//! 每个集成测试文件（`tests/*.rs`）各自编译成一个独立的二进制，`mod
//! common;` 会把这份源码分别编进每一个二进制——里面的每一项如果在**那
//! 个**二进制里没被用到，就是货真价实的 `dead_code`，`pub` 关键字管不了
//! 这件事（它只影响跨 crate 可见性，这里两个二进制本来就是各自独立的
//! crate，`pub` 顶多让 crate 内部的兄弟模块能看见它，堵不住 "整个 crate
//! 里没人用" 这条 lint）。`cargo clippy -p rmc-core --all-targets
//! -- -D warnings` 因此会因为跟被测代码毫无关系的告警而失败——这不是假设
//! 的风险，gateway 那条分支上真的因为同一个形状栽过一次。
//!
//! 所以这里只放 `ssh_tunnel.rs` 与 `forwarding.rs` **两边都用得上**的东西：
//! 六个函数、三个常量，跟 Task 8 brief 列的清单一一对应。任何只有一边
//! 需要的辅助（比如 `forwarding.rs` 用 `SSH_ASKPASS` 直连一体机需要的
//! 脚本生成函数）都留在各自的文件里，不搬进来——挪进来就会在没用到它的
//! 那个二进制里变成 dead_code。
//!
//! 验证方式见 task-8-report.md："tests/common 的 dead_code 问题" 一节：
//! `cargo clippy -p rmc-core --all-targets -- -D warnings` 全绿，且对着
//! 这份文件里的每一项手动追了一遍调用链——`gateway`/`appliance` 没有被
//! 两个文件直接调用，但分别被本文件内的 `factory`/`params` 调用，属于
//! "对当前 crate（某个测试二进制）可达"，不会被判 dead_code。

use rmc_core::addr::HostPort;
use rmc_core::code::ServerFingerprint;
use rmc_core::knownhosts::KnownHosts;
use rmc_core::platform::{NoProxy, NoProxyAuth};
use rmc_core::ssh::SshTunnelFactory;
use rmc_core::transport::Transport;
use rmc_core::tunnel::{TunnelMsg, TunnelParams};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

pub const TUNNEL_USER: &str = "tunnel-zhang";
pub const TUNNEL_PW: &str = "tunnel-init-pw";
pub const REVERSE_PORT: u16 = 22001;

/// 每次都要一个全新、保证互不冲突的路径。
///
/// R96（最终复审发现）：这里原来用纳秒时间戳拼路径，跟
/// `src/ssh/test_support.rs::tmp_known_hosts` 当初那一版一模一样——而
/// 那一版已经因为一个**实测踩到过的真故障**被换掉了：
/// `wrong_password_is_auth_rejected` 跟另一条测试撞了同一个纳秒、共用
/// 同一份 `known_hosts` 文件，读到别的用例写进去的指纹，报出一个不相关
/// 的 `HostKeyMismatch` 而不是预期的 `AuthRejected`（详见
/// `test_support.rs` 上同名函数的文档注释）。
///
/// CI 的 integration job 靠 `--test-threads=1` 兜住了这个形状；但本机
/// 直接 `cargo test -p rmc-core -- --ignored`（不带 `--test-threads=1`）
/// 就原样暴露在同一个已被证实过的故障里，而且现场看起来像是被测代码
/// 的 host key 校验出了问题，不像夹具自己撞了路径。纳秒这个粒度靠不住
/// 不是推测：把这段路径生成逻辑原样抄出来，8 个线程各调 2000 次，本机
/// 实测 16000 个路径里只有 2400~4500 个是唯一的，撞车率 72%~85%。
///
/// **修好这一条不等于并发跑就绿了**，别据此去掉 `--test-threads=1`：
/// `ssh_tunnel.rs`/`forwarding.rs` 里有几条用例会真的把反向端口 22001
/// 绑起来，并发跑必然互相抢占（实测失败是 `ForwardPortBusy(22001)`）。
/// 那是一个独立的、结构性的理由，本函数管不着。这一条修的是另一半：
/// 并发跑失败时，失败原因应当是那个真实存在的端口争用，而不是夹具自己
/// 撞路径伪装成的 `HostKeyMismatch`。
///
/// `tempfile::tempdir()` 用的是操作系统级别的唯一名字生成，不会有这个
/// 问题——拿到路径之后立刻让 `TempDir` guard 被丢弃也没关系：
/// `KnownHosts::append()` 自己会在第一次写入时用 `create_dir_all` 补上
/// 目录，路径本身的唯一性才是这里真正依赖的性质。
pub fn tmp_known_hosts() -> KnownHosts {
    let dir = tempfile::tempdir().expect("创建临时目录失败");
    KnownHosts::open(dir.path().join("known_hosts"))
}

pub fn gateway() -> HostPort {
    "gateway.test:8443".parse().unwrap()
}

pub fn appliance() -> HostPort {
    // 一体机在测试环境里对宿主发布为 127.0.0.1:2322，但转发目标由
    // 客户端自己拨号，所以这里用宿主可达的地址。
    "127.0.0.1:2322".parse().unwrap()
}

/// Task 9 订正：TLS 不再信任任何"根"，核对的是连接码里的指纹——
/// `TlsRoots`/`with_extra_pem` 那条路已经被整个删掉。这两份 docker 集成
/// 测试文件（`ssh_tunnel.rs`/`forwarding.rs`）连同 `tests/common/`、
/// `tests/data/`、`tests/fetch-harness-cert.sh` 按计划要在 Task 10 随
/// SSH 侧的 host key 校验一起整份删掉重写（那时会换成真实的 harness
/// 指纹）；这里只做了保持编译通过的最小改动，不改变这几个文件的测试
/// 语义或删除范围——它们本来就全部标了 `#[ignore]`，本仓没有 CI 会跑
/// 它们，`params()` 里那个占位指纹因此不会被任何断言用到。
pub fn factory(known_hosts: KnownHosts) -> SshTunnelFactory {
    let transport = Arc::new(Transport::new(Arc::new(NoProxy), Arc::new(NoProxyAuth)));
    SshTunnelFactory::new(transport, Arc::new(known_hosts))
}

pub fn params(password: &str, port: u16) -> TunnelParams {
    TunnelParams {
        username: TUNNEL_USER.into(),
        password: Zeroizing::new(password.to_string()),
        reverse_port: port,
        // R96：Gateway 地址从工厂的构造参数搬到了这里——现在
        // `establish()` 拨的、host key 比对的，都是这个值。见
        // `rmc_core::tunnel::TunnelParams` 上的说明。
        gateway: gateway(),
        appliance: appliance(),
        // Task 8：指纹已经接线到 TunnelParams，但这一层集成测试跑的是
        // Task 9 之前的中间态——TLS 仍然只走公共 CA，没有人核对这个值，
        // 随便给一个固定的即可。
        fingerprint: ServerFingerprint::of_ed25519_public(&[9u8; 32]),
    }
}

pub async fn next_msg(rx: &mut mpsc::Receiver<TunnelMsg>) -> TunnelMsg {
    tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .expect("等待隧道消息超时")
        .expect("隧道消息通道已关闭")
}
