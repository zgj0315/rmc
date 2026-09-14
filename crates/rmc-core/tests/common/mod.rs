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
use rmc_core::knownhosts::KnownHosts;
use rmc_core::platform::{NoProxy, NoProxyAuth};
use rmc_core::ssh::SshTunnelFactory;
use rmc_core::transport::tls::TlsRoots;
use rmc_core::transport::Transport;
use rmc_core::tunnel::{TunnelMsg, TunnelParams};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

pub const TUNNEL_USER: &str = "tunnel-zhang";
pub const TUNNEL_PW: &str = "tunnel-init-pw";
pub const REVERSE_PORT: u16 = 22001;

pub fn tmp_known_hosts() -> KnownHosts {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    KnownHosts::open(std::env::temp_dir().join(format!("rmc-kh-{n}/known_hosts")))
}

pub fn gateway() -> HostPort {
    "gateway.test:8443".parse().unwrap()
}

pub fn appliance() -> HostPort {
    // 一体机在测试环境里对宿主发布为 127.0.0.1:2322，但转发目标由
    // 客户端自己拨号，所以这里用宿主可达的地址。
    "127.0.0.1:2322".parse().unwrap()
}

pub fn factory(known_hosts: KnownHosts) -> SshTunnelFactory {
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
    }
}

pub async fn next_msg(rx: &mut mpsc::Receiver<TunnelMsg>) -> TunnelMsg {
    tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .expect("等待隧道消息超时")
        .expect("隧道消息通道已关闭")
}
