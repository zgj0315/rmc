# 客户端核心 rmc-core 实施计划（续）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 接着 `2026-09-13-rmc-core.md` 的 Task 6，完成 SSH 隧道、转发、预检、状态机、审计与 CI。

**Architecture:** 隧道建立抽成 `TunnelFactory` trait，真实实现用 russh，测试实现用脚本化的假隧道，于是状态机可以纯单元测试，真实链路另有集成测试对着 `gateway/test-env` 跑。

**Tech Stack:** 同前半，另加 russh

**Spec:** `docs/方案设计.md` 第 3.4 到 3.8、第 8 章 rmc-core 用例

**Global Constraints:** 与 `2026-09-13-rmc-core.md` 的同名小节完全一致，此处不重复，每个任务的要求都隐含包含它。

**russh 版本提醒：** 本计划的代码按 russh 0.54 的 `client::Handler` 形状写。执行 Task 7 第一步时先 `cargo add russh` 看解析到哪个版本，然后 `cargo doc -p russh --open` 核对 `Handler::check_server_key`、`server_channel_open_forwarded_tcpip` 与 `client::Session::tcpip_forward` 三处签名。若签名不同，保持本计划的 `TunnelMsg` 与 `TunnelHandle` 接口不变，只调整 russh 的调用形状，并把实际版本写进 `Cargo.toml` 的注释。

---

### Task 7: SSH 握手、host key、口令认证与反向端口注册

**Files:**
- Create: `crates/rmc-core/src/ssh/mod.rs`
- Create: `crates/rmc-core/src/ssh/handler.rs`
- Create: `crates/rmc-core/src/tunnel.rs`
- Modify: `crates/rmc-core/src/lib.rs`
- Test: `crates/rmc-core/tests/ssh_tunnel.rs`

**Interfaces:**
- Consumes: `Conn`（Task 5）、`Transport`（Task 6）、`KnownHosts`（Task 4）、`Error`（Task 1）
- Produces:
  - `pub struct TunnelParams { pub username: String, pub password: Zeroizing<String>, pub reverse_port: u16, pub appliance: HostPort }`
  - `pub enum TunnelMsg { Authenticated { host_key_fp: String, first_seen: bool }, ForwardRegistered { port: u16 }, RemoteSessionOpened { id: u64 }, RemoteSessionBytes { id: u64, to_appliance: u64, from_appliance: u64 }, RemoteSessionClosed { id: u64 }, ApplianceDialFailed { id: u64, reason: String }, Disconnected { reason: String } }`
  - `#[async_trait] pub trait TunnelFactory: Send + Sync { async fn establish(&self, params: TunnelParams, tx: mpsc::Sender<TunnelMsg>) -> Result<Box<dyn TunnelHandle>> }`
  - `#[async_trait] pub trait TunnelHandle: Send + Sync { async fn close_remote_session(&self, id: u64) -> Result<()>; async fn shutdown(self: Box<Self>) }`
  - `pub struct SshTunnelFactory { transport: Arc<Transport>, known_hosts: Arc<KnownHosts>, gateway: HostPort }`，实现 `TunnelFactory`

- [ ] **Step 1: 写下失败的测试**

创建 `crates/rmc-core/tests/ssh_tunnel.rs`：

```rust
//! 真实链路测试，需要 gateway/test-env 在运行。
//! 运行前先执行 crates/rmc-core/tests/fetch-harness-cert.sh。

use rmc_core::addr::HostPort;
use rmc_core::error::ErrorClass;
use rmc_core::knownhosts::KnownHosts;
use rmc_core::platform::{NoProxy, NoProxyAuth};
use rmc_core::ssh::SshTunnelFactory;
use rmc_core::transport::tls::TlsRoots;
use rmc_core::transport::Transport;
use rmc_core::tunnel::{TunnelFactory, TunnelMsg, TunnelParams};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

const TUNNEL_USER: &str = "tunnel-zhang";
const TUNNEL_PW: &str = "tunnel-init-pw";
const REVERSE_PORT: u16 = 22001;

fn tmp_known_hosts() -> KnownHosts {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
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
            &std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/harness-ca.pem"))
                .expect("先运行 tests/fetch-harness-cert.sh"),
        )
        .unwrap();
    let transport = Arc::new(Transport::new(Arc::new(NoProxy), Arc::new(NoProxyAuth), roots));
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
        TunnelMsg::Authenticated { host_key_fp, first_seen } => {
            assert!(host_key_fp.starts_with("SHA256:"), "{host_key_fp}");
            assert!(first_seen, "首次连接应报 first_seen");
        }
        other => panic!("第一条消息应为 Authenticated，实际 {other:?}"),
    }
    match next_msg(&mut rx).await {
        TunnelMsg::ForwardRegistered { port } => assert_eq!(port, REVERSE_PORT),
        other => panic!("第二条消息应为 ForwardRegistered，实际 {other:?}"),
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
    kh.check(&gateway(), "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .unwrap();

    let (tx, _rx) = mpsc::channel(32);
    let err = factory(kh)
        .establish(params(TUNNEL_PW, REVERSE_PORT), tx)
        .await
        .unwrap_err();
    assert_eq!(err.class(), ErrorClass::Fatal);
    assert!(err.to_string().contains("host key"), "{err}");
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn wrong_password_is_auth_class_and_not_network() {
    let (tx, _rx) = mpsc::channel(32);
    let err = factory(tmp_known_hosts())
        .establish(params("definitely-wrong", REVERSE_PORT), tx)
        .await
        .unwrap_err();
    assert_eq!(err.class(), ErrorClass::Auth);
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn port_outside_permitlisten_is_port_busy_class() {
    // 22007 未在 Gateway 的 PermitListen 中放行，tcpip-forward 会被拒。
    let (tx, _rx) = mpsc::channel(32);
    let err = factory(tmp_known_hosts())
        .establish(params(TUNNEL_PW, 22007), tx)
        .await
        .unwrap_err();
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
    while !matches!(next_msg(&mut rx1).await, TunnelMsg::ForwardRegistered { .. }) {}

    let (tx2, _rx2) = mpsc::channel(32);
    let err = factory(tmp_known_hosts())
        .establish(params(TUNNEL_PW, REVERSE_PORT), tx2)
        .await
        .unwrap_err();
    assert_eq!(err.class(), ErrorClass::PortBusy);

    first.shutdown().await;
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn password_never_appears_in_debug_output() {
    let p = params("super-secret-pw", REVERSE_PORT);
    let printed = format!("{p:?}");
    assert!(!printed.contains("super-secret-pw"), "{printed}");
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-core --test ssh_tunnel
```

预期：编译失败，`unresolved import rmc_core::ssh`。

- [ ] **Step 3: 写最小实现**

先确认 russh 版本：

```bash
cargo add russh -p rmc-core
cargo add zeroize -p rmc-core --features std
cargo doc -p russh --open   # 核对三处签名
```

创建 `crates/rmc-core/src/tunnel.rs`：

```rust
//! 隧道的抽象接口。Supervisor 只依赖这里，因此状态机可以用假隧道测试。

use crate::addr::HostPort;
use crate::error::Result;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

/// 建立一条隧道所需的全部输入。口令用 Zeroizing 承载，Debug 时被遮蔽。
pub struct TunnelParams {
    pub username: String,
    pub password: Zeroizing<String>,
    pub reverse_port: u16,
    pub appliance: HostPort,
}

impl std::fmt::Debug for TunnelParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelParams")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("reverse_port", &self.reverse_port)
            .field("appliance", &self.appliance)
            .finish()
    }
}

/// 隧道运行期间向 Supervisor 上报的事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelMsg {
    Authenticated { host_key_fp: String, first_seen: bool },
    ForwardRegistered { port: u16 },
    RemoteSessionOpened { id: u64 },
    RemoteSessionBytes { id: u64, to_appliance: u64, from_appliance: u64 },
    RemoteSessionClosed { id: u64 },
    ApplianceDialFailed { id: u64, reason: String },
    Disconnected { reason: String },
}

#[async_trait::async_trait]
pub trait TunnelFactory: Send + Sync {
    /// 成功返回时认证与反向端口注册均已完成，后续事件从 tx 送出。
    async fn establish(
        &self,
        params: TunnelParams,
        tx: mpsc::Sender<TunnelMsg>,
    ) -> Result<Box<dyn TunnelHandle>>;
}

#[async_trait::async_trait]
pub trait TunnelHandle: Send + Sync {
    /// 断开某一条远程会话，隧道本身保持。
    async fn close_remote_session(&self, id: u64) -> Result<()>;
    async fn shutdown(self: Box<Self>);
}
```

创建 `crates/rmc-core/src/ssh/handler.rs`：

```rust
//! russh 客户端回调。host key 校验与 forwarded-tcpip 通道的接收都在这里。

use crate::addr::HostPort;
use crate::error::Error;
use crate::knownhosts::{fingerprint_sha256, KnownHosts, Verdict};
use crate::tunnel::TunnelMsg;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct ClientHandler {
    pub gateway: HostPort,
    pub known_hosts: Arc<KnownHosts>,
    pub appliance: HostPort,
    pub reverse_port: u16,
    pub tx: mpsc::Sender<TunnelMsg>,
    pub next_session_id: Arc<AtomicU64>,
    /// host key 校验结果，establish 在认证后读取。
    pub verdict: Arc<std::sync::Mutex<Option<(String, bool)>>>,
}

impl ClientHandler {
    pub fn alloc_session_id(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }
}

#[async_trait::async_trait]
impl russh::client::Handler for ClientHandler {
    type Error = Error;

    /// 首次连接记录指纹，之后变更即拒绝。拒绝时返回 Err，握手随即失败。
    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let fp = fingerprint_sha256(&russh::keys::PublicKeyBase64::public_key_bytes(
            server_public_key,
        ));
        match self.known_hosts.check(&self.gateway, &fp)? {
            Verdict::FirstSeen => {
                *self.verdict.lock().unwrap() = Some((fp, true));
                Ok(true)
            }
            Verdict::Matched => {
                *self.verdict.lock().unwrap() = Some((fp, false));
                Ok(true)
            }
        }
    }

    /// Gateway 上有人连到反向端口时触发。把通道接到一体机。
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        // 只接受自己注册过的端口，防止服务端把别处的通道塞进来。
        if connected_port as u16 != self.reverse_port || connected_address != "127.0.0.1" {
            tracing::warn!(
                connected_address,
                connected_port,
                "拒绝未注册的 forwarded-tcpip 通道"
            );
            return Ok(());
        }

        let id = self.alloc_session_id();
        let appliance = self.appliance.clone();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            super::pump::run(id, channel, appliance, tx).await;
        });
        Ok(())
    }
}
```

创建 `crates/rmc-core/src/ssh/mod.rs`：

```rust
//! russh 实现的隧道。

pub mod handler;
pub mod pump;

use crate::addr::HostPort;
use crate::error::{Error, Result};
use crate::knownhosts::KnownHosts;
use crate::transport::Transport;
use crate::tunnel::{TunnelFactory, TunnelHandle, TunnelMsg, TunnelParams};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub struct SshTunnelFactory {
    transport: Arc<Transport>,
    known_hosts: Arc<KnownHosts>,
    gateway: HostPort,
}

impl SshTunnelFactory {
    pub fn new(
        transport: Arc<Transport>,
        known_hosts: Arc<KnownHosts>,
        gateway: HostPort,
    ) -> Self {
        Self { transport, known_hosts, gateway }
    }
}

pub struct SshTunnel {
    session: russh::client::Handle<handler::ClientHandler>,
    channels: Arc<tokio::sync::Mutex<std::collections::HashMap<u64, pump::Closer>>>,
}

#[async_trait::async_trait]
impl TunnelFactory for SshTunnelFactory {
    async fn establish(
        &self,
        params: TunnelParams,
        tx: mpsc::Sender<TunnelMsg>,
    ) -> Result<Box<dyn TunnelHandle>> {
        let conn = self.transport.connect(&self.gateway).await?;

        let config = Arc::new(russh::client::Config {
            keepalive_interval: Some(Duration::from_secs(10)),
            keepalive_max: 3,
            inactivity_timeout: None,
            ..Default::default()
        });

        let verdict = Arc::new(std::sync::Mutex::new(None));
        let handler = handler::ClientHandler {
            gateway: self.gateway.clone(),
            known_hosts: self.known_hosts.clone(),
            appliance: params.appliance.clone(),
            reverse_port: params.reverse_port,
            tx: tx.clone(),
            next_session_id: Arc::new(AtomicU64::new(1)),
            verdict: verdict.clone(),
        };

        let mut session = russh::client::connect_stream(config, conn, handler)
            .await
            .map_err(map_russh_error)?;

        let ok = session
            .authenticate_password(&params.username, params.password.as_str())
            .await
            .map_err(map_russh_error)?;
        if !ok.success() {
            return Err(Error::AuthRejected);
        }

        let (fp, first_seen) = verdict
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| Error::SshTransport("握手未产生 host key 校验结果".into()))?;
        let _ = tx.send(TunnelMsg::Authenticated { host_key_fp: fp, first_seen }).await;

        // tcpip-forward 被拒时统一按端口占用处理：现场唯一可行的动作是等待重试。
        session
            .tcpip_forward("127.0.0.1", params.reverse_port as u32)
            .await
            .map_err(|_| Error::ForwardPortBusy(params.reverse_port))?;
        let _ = tx
            .send(TunnelMsg::ForwardRegistered { port: params.reverse_port })
            .await;

        Ok(Box::new(SshTunnel {
            session,
            channels: Arc::new(tokio::sync::Mutex::new(Default::default())),
        }))
    }
}

#[async_trait::async_trait]
impl TunnelHandle for SshTunnel {
    async fn close_remote_session(&self, id: u64) -> Result<()> {
        if let Some(closer) = self.channels.lock().await.remove(&id) {
            closer.close();
        }
        Ok(())
    }

    async fn shutdown(self: Box<Self>) {
        let _ = self
            .session
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await;
    }
}

/// russh 的错误统一归到网络类，host key 与认证在各自分支已提前返回。
fn map_russh_error(e: russh::Error) -> Error {
    match e {
        russh::Error::Keys(_) | russh::Error::NoAuthMethod => Error::AuthRejected,
        other => Error::SshTransport(other.to_string()),
    }
}
```

暂时创建 `crates/rmc-core/src/ssh/pump.rs` 的占位，Task 8 填实：

```rust
//! forwarded-tcpip 通道到一体机的双向转发。

use crate::addr::HostPort;
use crate::tunnel::TunnelMsg;
use tokio::sync::mpsc;

/// 关闭某条远程会话的句柄。
pub struct Closer(tokio::sync::oneshot::Sender<()>);

impl Closer {
    pub fn close(self) {
        let _ = self.0.send(());
    }
}

pub async fn run(
    _id: u64,
    _channel: russh::Channel<russh::client::Msg>,
    _appliance: HostPort,
    _tx: mpsc::Sender<TunnelMsg>,
) {
    // Task 8 实现
}
```

在 `lib.rs` 加 `pub mod ssh;` 与 `pub mod tunnel;`。

- [ ] **Step 4: 运行测试确认通过**

```bash
cd gateway/test-env && docker compose up -d && cd ../..
./crates/rmc-core/tests/fetch-harness-cert.sh
cargo test -p rmc-core --test ssh_tunnel -- --ignored --test-threads=1
cargo test -p rmc-core --test ssh_tunnel   # 非 ignored 的口令遮蔽用例
```

预期：7 passed。`--test-threads=1` 是必须的，多个用例会争抢同一个反向端口。

- [ ] **Step 5: 提交**

```bash
git add crates/rmc-core/src/ssh crates/rmc-core/src/tunnel.rs crates/rmc-core/src/lib.rs \
        crates/rmc-core/Cargo.toml crates/rmc-core/tests/ssh_tunnel.rs
git commit -m "feat(core): SSH 握手、口令认证与反向端口注册"
```

---

### Task 8: 通道转发到一体机与逐会话账目

**Files:**
- Modify: `crates/rmc-core/src/ssh/pump.rs`
- Modify: `crates/rmc-core/src/ssh/mod.rs`
- Test: `crates/rmc-core/tests/forwarding.rs`

**Interfaces:**
- Consumes: Task 7 的 `TunnelMsg`、`Closer`
- Produces:
  - `pump::run(id, channel, appliance, tx)`：拨号一体机、双向转发、周期上报流量、结束时上报关闭
  - `pump::spawn(id, channel, appliance, tx) -> Closer`：供 handler 调用并把 `Closer` 登记到 `SshTunnel::channels`
  - 流量上报周期常量 `pub const BYTES_REPORT_INTERVAL: Duration = Duration::from_secs(2)`

- [ ] **Step 1: 写下失败的测试**

创建 `crates/rmc-core/tests/forwarding.rs`：

```rust
//! 端到端转发：工程师经 Gateway 连到反向端口，字节必须到达一体机。
//! 需要 gateway/test-env 在运行。

use rmc_core::tunnel::{TunnelFactory, TunnelMsg};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::mpsc;

mod common;
use common::{appliance, factory, next_msg, params, tmp_known_hosts, REVERSE_PORT, TUNNEL_PW};

/// 以工程师身份经 Gateway 跳到反向端口，在一体机上执行一条命令。
async fn engineer_runs(cmd: &str) -> std::process::Output {
    let key = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../gateway/test-env/engineer-keys/eng_ed25519"
    );
    Command::new("sshpass")
        .args(["-p", "appliance-dynamic-pw", "ssh"])
        .args(["-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .args(["-o", "PreferredAuthentications=password"])
        .args([
            "-o",
            &format!(
                "ProxyCommand=ssh -i {key} -o StrictHostKeyChecking=no \
                 -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
                 -W %h:%p -p 2022 eng@127.0.0.1"
            ),
        ])
        .args(["-p", &REVERSE_PORT.to_string(), "root@127.0.0.1", cmd])
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn engineer_command_reaches_the_appliance() {
    let (tx, mut rx) = mpsc::channel(64);
    let handle = factory(tmp_known_hosts())
        .establish(params(TUNNEL_PW, REVERSE_PORT), tx)
        .await
        .unwrap();
    while !matches!(next_msg(&mut rx).await, TunnelMsg::ForwardRegistered { .. }) {}

    let out = engineer_runs("cat /etc/appliance-id").await;
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "c0001-a1");

    handle.shutdown().await;
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn reports_session_open_bytes_and_close() {
    let (tx, mut rx) = mpsc::channel(64);
    let handle = factory(tmp_known_hosts())
        .establish(params(TUNNEL_PW, REVERSE_PORT), tx)
        .await
        .unwrap();
    while !matches!(next_msg(&mut rx).await, TunnelMsg::ForwardRegistered { .. }) {}

    // 传一段可观测大小的数据，确保两个方向的计数都非零。
    let out = engineer_runs("head -c 65536 /dev/zero | base64 | wc -c").await;
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let mut opened = None;
    let mut bytes = None;
    let mut closed = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline && closed.is_none() {
        match next_msg(&mut rx).await {
            TunnelMsg::RemoteSessionOpened { id } => opened = Some(id),
            TunnelMsg::RemoteSessionBytes { id, to_appliance, from_appliance } => {
                bytes = Some((id, to_appliance, from_appliance));
            }
            TunnelMsg::RemoteSessionClosed { id } => closed = Some(id),
            _ => {}
        }
    }

    let opened = opened.expect("没有收到 RemoteSessionOpened");
    let (bid, to_appliance, from_appliance) = bytes.expect("没有收到 RemoteSessionBytes");
    assert_eq!(bid, opened);
    assert_eq!(closed, Some(opened));
    assert!(to_appliance > 0, "到一体机的字节数为 0");
    assert!(from_appliance > 60_000, "来自一体机的字节数偏小：{from_appliance}");

    handle.shutdown().await;
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn two_concurrent_sessions_get_distinct_ids() {
    let (tx, mut rx) = mpsc::channel(64);
    let handle = factory(tmp_known_hosts())
        .establish(params(TUNNEL_PW, REVERSE_PORT), tx)
        .await
        .unwrap();
    while !matches!(next_msg(&mut rx).await, TunnelMsg::ForwardRegistered { .. }) {}

    let a = engineer_runs("sleep 3; echo a");
    let b = engineer_runs("sleep 3; echo b");
    let (ra, rb) = tokio::join!(a, b);
    assert!(ra.status.success() && rb.status.success());

    let mut ids = std::collections::HashSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline && ids.len() < 2 {
        if let TunnelMsg::RemoteSessionOpened { id } = next_msg(&mut rx).await {
            ids.insert(id);
        }
    }
    assert_eq!(ids.len(), 2, "两条并发会话应有两个不同 id：{ids:?}");

    handle.shutdown().await;
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn unreachable_appliance_reports_dial_failure_and_keeps_the_tunnel() {
    let mut p = params(TUNNEL_PW, REVERSE_PORT);
    // 指向一个没人监听的端口，模拟一体机不可达。
    p.appliance = "127.0.0.1:9".parse().unwrap();

    let (tx, mut rx) = mpsc::channel(64);
    let handle = factory(tmp_known_hosts()).establish(p, tx).await.unwrap();
    while !matches!(next_msg(&mut rx).await, TunnelMsg::ForwardRegistered { .. }) {}

    let out = engineer_runs("true").await;
    assert!(!out.status.success(), "一体机不可达时工程师应连不上");

    let mut saw_failure = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline && !saw_failure {
        if let TunnelMsg::ApplianceDialFailed { reason, .. } = next_msg(&mut rx).await {
            assert!(!reason.is_empty());
            saw_failure = true;
        }
    }
    assert!(saw_failure, "没有收到 ApplianceDialFailed");

    // 隧道本身必须还在：换回正常目标不需要重连整条隧道，这里只断言没有 Disconnected。
    handle.shutdown().await;
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn close_remote_session_drops_only_that_session() {
    let (tx, mut rx) = mpsc::channel(64);
    let handle = factory(tmp_known_hosts())
        .establish(params(TUNNEL_PW, REVERSE_PORT), tx)
        .await
        .unwrap();
    while !matches!(next_msg(&mut rx).await, TunnelMsg::ForwardRegistered { .. }) {}

    let long = tokio::spawn(engineer_runs("sleep 30"));
    let mut id = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline && id.is_none() {
        if let TunnelMsg::RemoteSessionOpened { id: got } = next_msg(&mut rx).await {
            id = Some(got);
        }
    }
    let id = id.expect("没有收到 RemoteSessionOpened");

    handle.close_remote_session(id).await.unwrap();

    let out = tokio::time::timeout(Duration::from_secs(20), long)
        .await
        .expect("断开后工程师侧应当立刻结束")
        .unwrap();
    assert!(!out.status.success(), "被断开的会话不该正常结束");

    // 隧道仍在，能接受新会话。
    let again = engineer_runs("cat /etc/appliance-id").await;
    assert!(again.status.success(), "{}", String::from_utf8_lossy(&again.stderr));

    handle.shutdown().await;
}
```

把 Task 7 测试里的共用辅助抽到 `crates/rmc-core/tests/common/mod.rs`，内容为 Task 7 第一步中 `tmp_known_hosts`、`gateway`、`appliance`、`factory`、`params`、`next_msg` 六个函数，并加 `pub const REVERSE_PORT: u16 = 22001;`、`pub const TUNNEL_USER: &str = "tunnel-zhang";`、`pub const TUNNEL_PW: &str = "tunnel-init-pw";`，全部改为 `pub`。`ssh_tunnel.rs` 改为 `mod common; use common::*;`。

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-core --test forwarding -- --ignored --test-threads=1
```

预期：`engineer_command_reaches_the_appliance` 超时或连接被拒，`pump::run` 是空实现。

- [ ] **Step 3: 写最小实现**

替换 `crates/rmc-core/src/ssh/pump.rs`：

```rust
//! forwarded-tcpip 通道到一体机的双向转发与逐会话流量账目。

use crate::addr::HostPort;
use crate::tunnel::TunnelMsg;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

/// 流量上报周期。界面每两秒看到一次增量足够，过密会刷爆事件通道。
pub const BYTES_REPORT_INTERVAL: Duration = Duration::from_secs(2);

/// 关闭某条远程会话的句柄，由 SshTunnel 持有。
pub struct Closer(oneshot::Sender<()>);

impl Closer {
    pub fn close(self) {
        let _ = self.0.send(());
    }
}

pub fn spawn(
    id: u64,
    channel: russh::Channel<russh::client::Msg>,
    appliance: HostPort,
    tx: mpsc::Sender<TunnelMsg>,
) -> Closer {
    let (close_tx, close_rx) = oneshot::channel();
    tokio::spawn(async move {
        run(id, channel, appliance, tx, close_rx).await;
    });
    Closer(close_tx)
}

pub async fn run(
    id: u64,
    channel: russh::Channel<russh::client::Msg>,
    appliance: HostPort,
    tx: mpsc::Sender<TunnelMsg>,
    mut close_rx: oneshot::Receiver<()>,
) {
    let upstream = match TcpStream::connect((appliance.host.as_str(), appliance.port)).await {
        Ok(s) => s,
        Err(e) => {
            let _ = tx
                .send(TunnelMsg::ApplianceDialFailed {
                    id,
                    reason: format!("连接 {appliance} 失败：{e}"),
                })
                .await;
            let _ = channel.eof().await;
            return;
        }
    };
    let _ = upstream.set_nodelay(true);
    let _ = tx.send(TunnelMsg::RemoteSessionOpened { id }).await;

    let to_appliance = Arc::new(AtomicU64::new(0));
    let from_appliance = Arc::new(AtomicU64::new(0));

    // 周期上报增量计数，界面据此显示流量。
    let reporter = {
        let tx = tx.clone();
        let to = to_appliance.clone();
        let from = from_appliance.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(BYTES_REPORT_INTERVAL);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let msg = TunnelMsg::RemoteSessionBytes {
                    id,
                    to_appliance: to.load(Ordering::Relaxed),
                    from_appliance: from.load(Ordering::Relaxed),
                };
                if tx.send(msg).await.is_err() {
                    return;
                }
            }
        })
    };

    let (mut up_read, mut up_write) = tokio::io::split(upstream);
    let mut ch_stream = channel.into_stream();

    let pump = async {
        let mut ch_buf = vec![0u8; 32 * 1024];
        let mut up_buf = vec![0u8; 32 * 1024];
        loop {
            tokio::select! {
                r = ch_stream.read(&mut ch_buf) => match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if up_write.write_all(&ch_buf[..n]).await.is_err() {
                            break;
                        }
                        to_appliance.fetch_add(n as u64, Ordering::Relaxed);
                    }
                },
                r = up_read.read(&mut up_buf) => match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if ch_stream.write_all(&up_buf[..n]).await.is_err() {
                            break;
                        }
                        from_appliance.fetch_add(n as u64, Ordering::Relaxed);
                    }
                },
            }
        }
    };

    tokio::select! {
        _ = pump => {}
        _ = &mut close_rx => {}
    }

    reporter.abort();
    let _ = ch_stream.shutdown().await;
    let _ = up_write.shutdown().await;

    // 结束前补一次最终计数，再报关闭。
    let _ = tx
        .send(TunnelMsg::RemoteSessionBytes {
            id,
            to_appliance: to_appliance.load(Ordering::Relaxed),
            from_appliance: from_appliance.load(Ordering::Relaxed),
        })
        .await;
    let _ = tx.send(TunnelMsg::RemoteSessionClosed { id }).await;
}
```

在 `ssh/handler.rs` 中把 `tokio::spawn(... pump::run ...)` 改成登记 `Closer`：把 `ClientHandler` 加一个字段

```rust
pub channels: Arc<tokio::sync::Mutex<std::collections::HashMap<u64, super::pump::Closer>>>,
```

并把回调体改为

```rust
let closer = super::pump::spawn(id, channel, self.appliance.clone(), self.tx.clone());
self.channels.lock().await.insert(id, closer);
let _ = tx_unused;
Ok(())
```

`SshTunnelFactory::establish` 里构造 `ClientHandler` 时传入与 `SshTunnel` 共享的同一个 `channels`。

- [ ] **Step 4: 运行测试确认通过**

```bash
cargo test -p rmc-core --test forwarding -- --ignored --test-threads=1
```

预期：5 passed。单次约 90 秒。

- [ ] **Step 5: 提交**

```bash
git add crates/rmc-core/src/ssh crates/rmc-core/tests/forwarding.rs crates/rmc-core/tests/common
git commit -m "feat(core): 通道转发到一体机与逐会话流量账目"
```

---

### Task 9: 预检

**Files:**
- Create: `crates/rmc-core/src/preflight.rs`
- Modify: `crates/rmc-core/src/lib.rs`
- Test: `crates/rmc-core/tests/preflight.rs`

**Interfaces:**
- Consumes: Task 6 的 `Transport`
- Produces:
  - `pub enum StepOutcome { Pass { detail: String }, Fail { detail: String, class: ErrorClass }, Skipped { detail: String } }`
  - `pub struct PreflightStep { pub name: &'static str, pub outcome: StepOutcome }`
  - `pub struct PreflightReport { pub steps: Vec<PreflightStep> }`，方法 `passed() -> bool`、`first_failure() -> Option<&PreflightStep>`
  - `pub const STEP_APPLIANCE_TCP: &str`、`STEP_APPLIANCE_HOSTKEY`、`STEP_GATEWAY_DNS`、`STEP_GATEWAY_TLS` 四个步骤名
  - `pub async fn run(transport: &Transport, gateway: &HostPort, appliance: &HostPort) -> PreflightReport`

- [ ] **Step 1: 写下失败的测试**

创建 `crates/rmc-core/tests/preflight.rs`：

```rust
use rmc_core::addr::HostPort;
use rmc_core::error::ErrorClass;
use rmc_core::platform::{NoProxy, NoProxyAuth};
use rmc_core::preflight::{self, StepOutcome, STEP_APPLIANCE_HOSTKEY, STEP_APPLIANCE_TCP, STEP_GATEWAY_DNS, STEP_GATEWAY_TLS};
use rmc_core::transport::tls::TlsRoots;
use rmc_core::transport::Transport;
use std::sync::Arc;

fn transport() -> Transport {
    let mut roots = TlsRoots::webpki();
    if let Ok(pem) = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/harness-ca.pem")) {
        roots.with_extra_pem(&pem).unwrap();
    }
    Transport::new(Arc::new(NoProxy), Arc::new(NoProxyAuth), roots)
}

#[tokio::test]
async fn report_lists_four_steps_in_fixed_order() {
    let r = preflight::run(
        &transport(),
        &"gateway.test:8443".parse().unwrap(),
        &"127.0.0.1:2322".parse().unwrap(),
    )
    .await;
    let names: Vec<_> = r.steps.iter().map(|s| s.name).collect();
    assert_eq!(
        names,
        vec![STEP_APPLIANCE_TCP, STEP_APPLIANCE_HOSTKEY, STEP_GATEWAY_DNS, STEP_GATEWAY_TLS]
    );
}

#[tokio::test]
async fn unreachable_appliance_fails_first_step_and_skips_hostkey() {
    let r = preflight::run(
        &transport(),
        &"gateway.test:8443".parse().unwrap(),
        &"127.0.0.1:9".parse().unwrap(),
    )
    .await;
    assert!(!r.passed());
    let first = r.first_failure().unwrap();
    assert_eq!(first.name, STEP_APPLIANCE_TCP);
    assert!(matches!(
        r.steps[1].outcome,
        StepOutcome::Skipped { .. }
    ));
}

#[tokio::test]
async fn bad_gateway_name_fails_dns_and_skips_tls() {
    let r = preflight::run(
        &transport(),
        &"no-such-host.invalid:443".parse().unwrap(),
        &"127.0.0.1:2322".parse().unwrap(),
    )
    .await;
    let dns = r.steps.iter().find(|s| s.name == STEP_GATEWAY_DNS).unwrap();
    match &dns.outcome {
        StepOutcome::Fail { class, .. } => assert_eq!(*class, ErrorClass::Network),
        other => panic!("{other:?}"),
    }
    assert!(matches!(r.steps[3].outcome, StepOutcome::Skipped { .. }));
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn all_four_steps_pass_against_the_harness() {
    let r = preflight::run(
        &transport(),
        &"gateway.test:8443".parse().unwrap(),
        &"127.0.0.1:2322".parse().unwrap(),
    )
    .await;
    assert!(r.passed(), "{:#?}", r.steps);
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn appliance_hostkey_step_reports_a_sha256_fingerprint() {
    let r = preflight::run(
        &transport(),
        &"gateway.test:8443".parse().unwrap(),
        &"127.0.0.1:2322".parse().unwrap(),
    )
    .await;
    let step = r.steps.iter().find(|s| s.name == STEP_APPLIANCE_HOSTKEY).unwrap();
    match &step.outcome {
        StepOutcome::Pass { detail } => assert!(detail.contains("SHA256:"), "{detail}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
#[ignore = "需要 gateway/test-env 在运行"]
async fn untrusted_gateway_cert_fails_tls_step_as_fatal() {
    let t = Transport::new(Arc::new(NoProxy), Arc::new(NoProxyAuth), TlsRoots::webpki());
    let r = preflight::run(
        &t,
        &"gateway.test:8443".parse().unwrap(),
        &"127.0.0.1:2322".parse().unwrap(),
    )
    .await;
    let tls = r.steps.iter().find(|s| s.name == STEP_GATEWAY_TLS).unwrap();
    match &tls.outcome {
        StepOutcome::Fail { class, detail } => {
            assert_eq!(*class, ErrorClass::Fatal);
            assert!(detail.contains("证书"), "{detail}");
        }
        other => panic!("{other:?}"),
    }
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-core --test preflight
```

预期：编译失败，`unresolved import rmc_core::preflight`。

- [ ] **Step 3: 写最小实现**

创建 `crates/rmc-core/src/preflight.rs`：

```rust
//! 开启远程维护前的四步检查，见方案 3.4。
//! 前一步失败时后续依赖它的步骤标为 Skipped，而不是伪造失败。

use crate::addr::HostPort;
use crate::error::{Error, ErrorClass};
use crate::transport::Transport;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub const STEP_APPLIANCE_TCP: &str = "一体机 TCP";
pub const STEP_APPLIANCE_HOSTKEY: &str = "一体机 host key 指纹";
pub const STEP_GATEWAY_DNS: &str = "Gateway 域名解析";
pub const STEP_GATEWAY_TLS: &str = "Gateway TLS";

const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    Pass { detail: String },
    Fail { detail: String, class: ErrorClass },
    Skipped { detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightStep {
    pub name: &'static str,
    pub outcome: StepOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightReport {
    pub steps: Vec<PreflightStep>,
}

impl PreflightReport {
    pub fn passed(&self) -> bool {
        self.steps
            .iter()
            .all(|s| matches!(s.outcome, StepOutcome::Pass { .. }))
    }

    pub fn first_failure(&self) -> Option<&PreflightStep> {
        self.steps
            .iter()
            .find(|s| matches!(s.outcome, StepOutcome::Fail { .. }))
    }
}

fn fail(e: &Error) -> StepOutcome {
    StepOutcome::Fail { detail: e.to_string(), class: e.class() }
}

/// 读取一体机的 SSH banner 并取其 host key 指纹。
/// 只做 banner 与 KEX 的第一步，不认证，等价于 ssh-keyscan。
async fn appliance_banner(appliance: &HostPort) -> Result<String, Error> {
    let mut s = tokio::time::timeout(
        PROBE_TIMEOUT,
        TcpStream::connect((appliance.host.as_str(), appliance.port)),
    )
    .await
    .map_err(|_| Error::ApplianceUnreachable(format!("连接 {appliance} 超时")))?
    .map_err(|e| Error::ApplianceUnreachable(format!("连接 {appliance} 失败：{e}")))?;

    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(PROBE_TIMEOUT, s.read(&mut buf))
        .await
        .map_err(|_| Error::ApplianceUnreachable("读取 SSH banner 超时".into()))?
        .map_err(|e| Error::ApplianceUnreachable(format!("读取 SSH banner 失败：{e}")))?;
    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    if !banner.starts_with("SSH-2.0-") {
        return Err(Error::ApplianceUnreachable(format!(
            "{appliance} 未返回 SSH banner：{banner}"
        )));
    }
    Ok(banner)
}

/// 与一体机做一次 KEX 取 host key，随即断开。
async fn appliance_host_key(appliance: &HostPort) -> Result<String, Error> {
    use crate::knownhosts::fingerprint_sha256;

    struct Probe {
        fp: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    }

    #[async_trait::async_trait]
    impl russh::client::Handler for Probe {
        type Error = Error;
        async fn check_server_key(
            &mut self,
            key: &russh::keys::PublicKey,
        ) -> Result<bool, Self::Error> {
            let fp = fingerprint_sha256(&russh::keys::PublicKeyBase64::public_key_bytes(key));
            *self.fp.lock().unwrap() = Some(fp);
            // 取到指纹即可，不需要继续。
            Ok(true)
        }
    }

    let fp = std::sync::Arc::new(std::sync::Mutex::new(None));
    let cfg = std::sync::Arc::new(russh::client::Config::default());
    let handler = Probe { fp: fp.clone() };
    let session = tokio::time::timeout(
        PROBE_TIMEOUT,
        russh::client::connect(cfg, (appliance.host.as_str(), appliance.port), handler),
    )
    .await
    .map_err(|_| Error::ApplianceUnreachable("SSH 握手超时".into()))?
    .map_err(|e| Error::ApplianceUnreachable(format!("SSH 握手失败：{e}")))?;
    let _ = session.disconnect(russh::Disconnect::ByApplication, "", "").await;

    fp.lock()
        .unwrap()
        .clone()
        .ok_or_else(|| Error::ApplianceUnreachable("握手未返回 host key".into()))
}

pub async fn run(
    transport: &Transport,
    gateway: &HostPort,
    appliance: &HostPort,
) -> PreflightReport {
    let mut steps = Vec::with_capacity(4);

    // 1. 一体机 TCP 与 banner
    let appliance_ok = match appliance_banner(appliance).await {
        Ok(banner) => {
            steps.push(PreflightStep {
                name: STEP_APPLIANCE_TCP,
                outcome: StepOutcome::Pass { detail: format!("{appliance} 可达 · {banner}") },
            });
            true
        }
        Err(e) => {
            steps.push(PreflightStep { name: STEP_APPLIANCE_TCP, outcome: fail(&e) });
            false
        }
    };

    // 2. 一体机 host key 指纹
    if appliance_ok {
        let outcome = match appliance_host_key(appliance).await {
            Ok(fp) => StepOutcome::Pass { detail: fp },
            Err(e) => fail(&e),
        };
        steps.push(PreflightStep { name: STEP_APPLIANCE_HOSTKEY, outcome });
    } else {
        steps.push(PreflightStep {
            name: STEP_APPLIANCE_HOSTKEY,
            outcome: StepOutcome::Skipped { detail: "一体机不可达，未执行".into() },
        });
    }

    // 3. Gateway 域名解析
    let dns_ok = match transport.resolve_dns(&gateway.host).await {
        Ok(addrs) => {
            let list = addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            steps.push(PreflightStep {
                name: STEP_GATEWAY_DNS,
                outcome: StepOutcome::Pass { detail: format!("{} → {list}", gateway.host) },
            });
            true
        }
        Err(e) => {
            steps.push(PreflightStep { name: STEP_GATEWAY_DNS, outcome: fail(&e) });
            false
        }
    };

    // 4. Gateway TLS，经代理时含 CONNECT
    if dns_ok {
        let proxy = transport.effective_proxy(gateway).await;
        let outcome = match transport.connect(gateway).await {
            Ok(conn) => {
                drop(conn);
                let via = match proxy {
                    Some(p) => format!("经代理 {p}"),
                    None => "直连".to_string(),
                };
                StepOutcome::Pass { detail: format!("握手成功 · {via}") }
            }
            Err(e) => fail(&e),
        };
        steps.push(PreflightStep { name: STEP_GATEWAY_TLS, outcome });
    } else {
        steps.push(PreflightStep {
            name: STEP_GATEWAY_TLS,
            outcome: StepOutcome::Skipped { detail: "域名解析失败，未执行".into() },
        });
    }

    PreflightReport { steps }
}
```

在 `lib.rs` 加 `pub mod preflight;`。

- [ ] **Step 4: 运行测试确认通过**

```bash
cargo test -p rmc-core --test preflight
cargo test -p rmc-core --test preflight -- --ignored --test-threads=1
```

预期：3 passed，随后 3 passed。

- [ ] **Step 5: 提交**

```bash
git add crates/rmc-core/src/preflight.rs crates/rmc-core/src/lib.rs crates/rmc-core/tests/preflight.rs
git commit -m "feat(core): 预检四步与报告结构"
```

---

### Task 10: 状态机与 Supervisor

内核的行为规约都落在这里。用脚本化的假隧道加 tokio 的时间控制做纯单元测试，不依赖网络。

**Files:**
- Create: `crates/rmc-core/src/state.rs`
- Create: `crates/rmc-core/src/supervisor.rs`
- Modify: `crates/rmc-core/src/lib.rs`
- Test: `crates/rmc-core/tests/supervisor.rs`

**Interfaces:**
- Consumes: Task 2 的 `Backoff`/`Jitter`、Task 7 的 `TunnelFactory`/`TunnelHandle`/`TunnelMsg`、Task 9 的 `PreflightReport`、Task 5 的 `SystemEvents`
- Produces:
  - `pub enum State { Idle, Preflight, Connecting, Connected { degraded: bool }, Backoff { attempt: u32, delay: Duration }, Stopping, Failed { class: ErrorClass, message: String } }`
  - `pub enum Command { Start { username: String, password: Zeroizing<String>, gateway: HostPort, appliance: HostPort }, Cancel, Stop, RetryNow, DisconnectRemoteSession { id: u64 } }`
  - `pub struct RemoteSessionInfo { pub id: u64, pub opened_at: SystemTime, pub to_appliance: u64, pub from_appliance: u64 }`
  - `pub enum TunnelEvent { State(State), Preflight(PreflightReport), RemoteSessions(Vec<RemoteSessionInfo>), HostKey { fingerprint: String, first_seen: bool }, ConnectedSince(SystemTime) }`
  - `pub struct Deps { pub factory: Arc<dyn TunnelFactory>, pub transport: Arc<Transport>, pub events: Arc<dyn SystemEvents>, pub jitter: fn() -> Box<dyn Jitter> }`
  - `Supervisor::spawn(cfg: Config, deps: Deps) -> (mpsc::Sender<Command>, broadcast::Receiver<TunnelEvent>)`
  - `pub const PORT_BUSY_RETRY: Duration = Duration::from_secs(5)`，`pub const PORT_BUSY_BUDGET: Duration = Duration::from_secs(120)`，`pub const APPLIANCE_PROBE: Duration = Duration::from_secs(30)`

- [ ] **Step 1: 写下失败的测试**

创建 `crates/rmc-core/tests/supervisor.rs`：

```rust
//! 状态机的行为规约。全部用假隧道与 tokio 的时间控制，不碰网络。

use rmc_core::addr::HostPort;
use rmc_core::backoff::FixedJitter;
use rmc_core::config::Config;
use rmc_core::error::{Error, ErrorClass};
use rmc_core::platform::{NoProxy, NoProxyAuth, NoSystemEvents, SystemEvent, SystemEvents};
use rmc_core::state::{Command, State, TunnelEvent};
use rmc_core::supervisor::{Deps, Supervisor, PORT_BUSY_BUDGET, PORT_BUSY_RETRY};
use rmc_core::transport::tls::TlsRoots;
use rmc_core::transport::Transport;
use rmc_core::tunnel::{TunnelFactory, TunnelHandle, TunnelMsg, TunnelParams};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use zeroize::Zeroizing;

/// establish 的一次结果。
enum Outcome {
    /// 成功，随后按脚本向 tx 推送这些消息。
    Ok(Vec<TunnelMsg>),
    Err(Error),
}

/// 按队列逐次给出 establish 结果的假隧道工厂。
struct Scripted {
    outcomes: Mutex<VecDeque<Outcome>>,
    calls: Arc<Mutex<Vec<TunnelParams>>>,
}

impl Scripted {
    fn new(outcomes: Vec<Outcome>) -> (Arc<Self>, Arc<Mutex<Vec<TunnelParams>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let me = Arc::new(Self {
            outcomes: Mutex::new(outcomes.into()),
            calls: calls.clone(),
        });
        (me, calls)
    }
}

struct FakeHandle;

#[async_trait::async_trait]
impl TunnelHandle for FakeHandle {
    async fn close_remote_session(&self, _id: u64) -> rmc_core::Result<()> {
        Ok(())
    }
    async fn shutdown(self: Box<Self>) {}
}

#[async_trait::async_trait]
impl TunnelFactory for Scripted {
    async fn establish(
        &self,
        params: TunnelParams,
        tx: mpsc::Sender<TunnelMsg>,
    ) -> rmc_core::Result<Box<dyn TunnelHandle>> {
        self.calls.lock().unwrap().push(params);
        let outcome = self
            .outcomes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Outcome::Err(Error::SshTransport("脚本用尽".into())));
        match outcome {
            Outcome::Err(e) => Err(e),
            Outcome::Ok(msgs) => {
                tokio::spawn(async move {
                    for m in msgs {
                        if tx.send(m).await.is_err() {
                            return;
                        }
                    }
                });
                Ok(Box::new(FakeHandle))
            }
        }
    }
}

fn config() -> Config {
    Config {
        gateway: "gateway.company.com:443".parse().unwrap(),
        appliance: "192.168.100.10:22".parse().unwrap(),
        reverse_port: 22001,
        known_hosts_path: PathBuf::from("/tmp/rmc-test/known_hosts"),
        log_dir: PathBuf::from("/tmp/rmc-test/logs"),
    }
}

struct ManualEvents(broadcast::Sender<SystemEvent>);

impl SystemEvents for ManualEvents {
    fn subscribe(&self) -> broadcast::Receiver<SystemEvent> {
        self.0.subscribe()
    }
}

fn deps(factory: Arc<dyn TunnelFactory>, events: Arc<dyn SystemEvents>) -> Deps {
    Deps {
        factory,
        transport: Arc::new(Transport::new(
            Arc::new(NoProxy),
            Arc::new(NoProxyAuth),
            TlsRoots::webpki(),
        )),
        events,
        jitter: || Box::new(FixedJitter(1.0)),
    }
}

fn start() -> Command {
    Command::Start {
        username: "tunnel-zhang".into(),
        password: Zeroizing::new("pw".into()),
        gateway: "gateway.company.com:443".parse().unwrap(),
        appliance: "192.168.100.10:22".parse().unwrap(),
    }
}

/// 收集状态变迁，直到匹配 pred 或超时。
async fn states_until(
    rx: &mut broadcast::Receiver<TunnelEvent>,
    pred: impl Fn(&State) -> bool,
) -> Vec<State> {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    while tokio::time::Instant::now() < deadline {
        match rx.recv().await {
            Ok(TunnelEvent::State(s)) => {
                let hit = pred(&s);
                seen.push(s);
                if hit {
                    return seen;
                }
            }
            Ok(_) => {}
            Err(e) => panic!("事件通道异常：{e}"),
        }
    }
    panic!("等待状态超时，已见：{seen:?}");
}

#[tokio::test(start_paused = true)]
async fn happy_path_reaches_connected() {
    let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
        TunnelMsg::Authenticated { host_key_fp: "SHA256:aaa".into(), first_seen: true },
        TunnelMsg::ForwardRegistered { port: 22001 },
    ])]);
    let (tx, mut rx) = Supervisor::spawn(
        config(),
        deps(factory, Arc::new(NoSystemEvents::default())),
    );
    tx.send(start()).await.unwrap();

    let seen = states_until(&mut rx, |s| matches!(s, State::Connected { degraded: false })).await;
    assert!(matches!(seen[0], State::Preflight));
    assert!(seen.iter().any(|s| matches!(s, State::Connecting)));
}

#[tokio::test(start_paused = true)]
async fn auth_failure_returns_to_idle_and_does_not_retry() {
    let (factory, calls) = Scripted::new(vec![Outcome::Err(Error::AuthRejected)]);
    let (tx, mut rx) = Supervisor::spawn(
        config(),
        deps(factory.clone(), Arc::new(NoSystemEvents::default())),
    );
    tx.send(start()).await.unwrap();

    let seen = states_until(&mut rx, |s| matches!(s, State::Idle)).await;
    assert!(!seen.iter().any(|s| matches!(s, State::Backoff { .. })), "{seen:?}");
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert_eq!(calls.lock().unwrap().len(), 1, "认证失败后不得自动重试");
}

#[tokio::test(start_paused = true)]
async fn host_key_mismatch_goes_to_failed_and_does_not_retry() {
    let (factory, calls) = Scripted::new(vec![Outcome::Err(Error::HostKeyMismatch {
        expected: "SHA256:aaa".into(),
        actual: "SHA256:bbb".into(),
    })]);
    let (tx, mut rx) = Supervisor::spawn(
        config(),
        deps(factory, Arc::new(NoSystemEvents::default())),
    );
    tx.send(start()).await.unwrap();

    let seen = states_until(&mut rx, |s| matches!(s, State::Failed { .. })).await;
    match seen.last().unwrap() {
        State::Failed { class, message } => {
            assert_eq!(*class, ErrorClass::Fatal);
            assert!(message.contains("host key"), "{message}");
        }
        other => panic!("{other:?}"),
    }
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn network_failure_backs_off_along_the_documented_sequence() {
    let outcomes = (0..4)
        .map(|_| Outcome::Err(Error::Tcp("refused".into())))
        .chain(std::iter::once(Outcome::Ok(vec![
            TunnelMsg::Authenticated { host_key_fp: "SHA256:aaa".into(), first_seen: false },
            TunnelMsg::ForwardRegistered { port: 22001 },
        ])))
        .collect();
    let (factory, _calls) = Scripted::new(outcomes);
    let (tx, mut rx) = Supervisor::spawn(
        config(),
        deps(factory, Arc::new(NoSystemEvents::default())),
    );
    tx.send(start()).await.unwrap();

    let seen = states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;
    let delays: Vec<u64> = seen
        .iter()
        .filter_map(|s| match s {
            State::Backoff { delay, .. } => Some(delay.as_secs()),
            _ => None,
        })
        .collect();
    assert_eq!(delays, vec![1, 2, 5, 10]);
}

#[tokio::test(start_paused = true)]
async fn port_busy_retries_every_five_seconds_then_fails_after_budget() {
    let outcomes = (0..40)
        .map(|_| Outcome::Err(Error::ForwardPortBusy(22001)))
        .collect();
    let (factory, calls) = Scripted::new(outcomes);
    let (tx, mut rx) = Supervisor::spawn(
        config(),
        deps(factory, Arc::new(NoSystemEvents::default())),
    );
    tx.send(start()).await.unwrap();

    let seen = states_until(&mut rx, |s| matches!(s, State::Failed { .. })).await;
    match seen.last().unwrap() {
        State::Failed { class, .. } => assert_eq!(*class, ErrorClass::PortBusy),
        other => panic!("{other:?}"),
    }
    let n = calls.lock().unwrap().len();
    let expected = (PORT_BUSY_BUDGET.as_secs() / PORT_BUSY_RETRY.as_secs()) as usize;
    assert!(
        (expected..=expected + 2).contains(&n),
        "预算内应重试约 {expected} 次，实际 {n}"
    );
}

#[tokio::test(start_paused = true)]
async fn appliance_dial_failure_turns_degraded_and_recovers() {
    let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
        TunnelMsg::Authenticated { host_key_fp: "SHA256:aaa".into(), first_seen: false },
        TunnelMsg::ForwardRegistered { port: 22001 },
        TunnelMsg::ApplianceDialFailed { id: 1, reason: "refused".into() },
        TunnelMsg::RemoteSessionOpened { id: 2 },
    ])]);
    let (tx, mut rx) = Supervisor::spawn(
        config(),
        deps(factory, Arc::new(NoSystemEvents::default())),
    );
    tx.send(start()).await.unwrap();

    states_until(&mut rx, |s| matches!(s, State::Connected { degraded: true })).await;
    // 一条会话成功打开即视为恢复。
    states_until(&mut rx, |s| matches!(s, State::Connected { degraded: false })).await;
}

#[tokio::test(start_paused = true)]
async fn degraded_probe_recovers_when_the_appliance_comes_back() {
    // 探测走真实 TCP。开一个本地监听充当恢复后的一体机。
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            if listener.accept().await.is_err() {
                return;
            }
        }
    });

    let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
        TunnelMsg::Authenticated { host_key_fp: "SHA256:aaa".into(), first_seen: false },
        TunnelMsg::ForwardRegistered { port: 22001 },
        TunnelMsg::ApplianceDialFailed { id: 1, reason: "refused".into() },
    ])]);
    let (tx, mut rx) = Supervisor::spawn(
        config(),
        deps(factory, Arc::new(NoSystemEvents::default())),
    );
    // Start 里的一体机地址指向那个监听端口，探测应当成功。
    tx.send(Command::Start {
        username: "tunnel-zhang".into(),
        password: Zeroizing::new("pw".into()),
        gateway: "gateway.company.com:443".parse().unwrap(),
        appliance: format!("127.0.0.1:{port}").parse().unwrap(),
    })
    .await
    .unwrap();

    states_until(&mut rx, |s| matches!(s, State::Connected { degraded: true })).await;
    // 无需任何远程会话，仅靠 30 秒探测就应转回。
    states_until(&mut rx, |s| matches!(s, State::Connected { degraded: false })).await;
}

#[tokio::test(start_paused = true)]
async fn degraded_stays_degraded_while_the_appliance_is_still_down() {
    let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
        TunnelMsg::Authenticated { host_key_fp: "SHA256:aaa".into(), first_seen: false },
        TunnelMsg::ForwardRegistered { port: 22001 },
        TunnelMsg::ApplianceDialFailed { id: 1, reason: "refused".into() },
    ])]);
    let (tx, mut rx) = Supervisor::spawn(
        config(),
        deps(factory, Arc::new(NoSystemEvents::default())),
    );
    // 端口 1 上没人监听，探测一直失败。
    tx.send(Command::Start {
        username: "tunnel-zhang".into(),
        password: Zeroizing::new("pw".into()),
        gateway: "gateway.company.com:443".parse().unwrap(),
        appliance: "127.0.0.1:1".parse().unwrap(),
    })
    .await
    .unwrap();

    states_until(&mut rx, |s| matches!(s, State::Connected { degraded: true })).await;
    // 连续几个探测周期内都不应转回，也不应断开隧道。
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(35), rx.recv()).await {
            Ok(Ok(TunnelEvent::State(s))) => {
                assert!(
                    matches!(s, State::Connected { degraded: true }),
                    "一体机仍不可达时状态不该变成 {s:?}"
                );
            }
            _ => break,
        }
    }
}

#[tokio::test(start_paused = true)]
async fn disconnect_reconnects_and_reuses_credentials_without_a_new_start() {
    let (factory, calls) = Scripted::new(vec![
        Outcome::Ok(vec![
            TunnelMsg::Authenticated { host_key_fp: "SHA256:aaa".into(), first_seen: false },
            TunnelMsg::ForwardRegistered { port: 22001 },
            TunnelMsg::Disconnected { reason: "reset".into() },
        ]),
        Outcome::Ok(vec![
            TunnelMsg::Authenticated { host_key_fp: "SHA256:aaa".into(), first_seen: false },
            TunnelMsg::ForwardRegistered { port: 22001 },
        ]),
    ]);
    let (tx, mut rx) = Supervisor::spawn(
        config(),
        deps(factory, Arc::new(NoSystemEvents::default())),
    );
    tx.send(start()).await.unwrap();

    states_until(&mut rx, |s| matches!(s, State::Backoff { .. })).await;
    states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].username, calls[1].username);
}

#[tokio::test(start_paused = true)]
async fn network_event_clears_backoff_and_retries_at_once() {
    let outcomes = vec![
        Outcome::Err(Error::Tcp("refused".into())),
        Outcome::Err(Error::Tcp("refused".into())),
        Outcome::Err(Error::Tcp("refused".into())),
        Outcome::Ok(vec![
            TunnelMsg::Authenticated { host_key_fp: "SHA256:aaa".into(), first_seen: false },
            TunnelMsg::ForwardRegistered { port: 22001 },
        ]),
    ];
    let (factory, _calls) = Scripted::new(outcomes);
    let (ev_tx, _) = broadcast::channel(8);
    let events = Arc::new(ManualEvents(ev_tx.clone()));
    let (tx, mut rx) = Supervisor::spawn(config(), deps(factory, events));
    tx.send(start()).await.unwrap();

    states_until(&mut rx, |s| matches!(s, State::Backoff { attempt: 2, .. })).await;
    ev_tx.send(SystemEvent::NetworkChanged).unwrap();

    let seen = states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;
    // 事件触发后下一次退避必须回到序列起点。
    let delays: Vec<u64> = seen
        .iter()
        .filter_map(|s| match s {
            State::Backoff { delay, .. } => Some(delay.as_secs()),
            _ => None,
        })
        .collect();
    assert_eq!(delays.last(), Some(&1), "退避未清零：{delays:?}");
}

#[tokio::test(start_paused = true)]
async fn stop_from_connected_returns_to_idle() {
    let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
        TunnelMsg::Authenticated { host_key_fp: "SHA256:aaa".into(), first_seen: false },
        TunnelMsg::ForwardRegistered { port: 22001 },
    ])]);
    let (tx, mut rx) = Supervisor::spawn(
        config(),
        deps(factory, Arc::new(NoSystemEvents::default())),
    );
    tx.send(start()).await.unwrap();
    states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;

    tx.send(Command::Stop).await.unwrap();
    let seen = states_until(&mut rx, |s| matches!(s, State::Idle)).await;
    assert!(seen.iter().any(|s| matches!(s, State::Stopping)));
}

#[tokio::test(start_paused = true)]
async fn stop_during_backoff_returns_to_idle_and_stops_retrying() {
    let outcomes = (0..20).map(|_| Outcome::Err(Error::Tcp("refused".into()))).collect();
    let (factory, calls) = Scripted::new(outcomes);
    let (tx, mut rx) = Supervisor::spawn(
        config(),
        deps(factory, Arc::new(NoSystemEvents::default())),
    );
    tx.send(start()).await.unwrap();
    states_until(&mut rx, |s| matches!(s, State::Backoff { .. })).await;

    tx.send(Command::Stop).await.unwrap();
    states_until(&mut rx, |s| matches!(s, State::Idle)).await;
    let before = calls.lock().unwrap().len();
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert_eq!(calls.lock().unwrap().len(), before, "停止后仍在重试");
}

#[tokio::test(start_paused = true)]
async fn remote_sessions_are_reported_with_traffic_and_removed_on_close() {
    let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
        TunnelMsg::Authenticated { host_key_fp: "SHA256:aaa".into(), first_seen: false },
        TunnelMsg::ForwardRegistered { port: 22001 },
        TunnelMsg::RemoteSessionOpened { id: 7 },
        TunnelMsg::RemoteSessionBytes { id: 7, to_appliance: 100, from_appliance: 200 },
        TunnelMsg::RemoteSessionClosed { id: 7 },
    ])]);
    let (tx, mut rx) = Supervisor::spawn(
        config(),
        deps(factory, Arc::new(NoSystemEvents::default())),
    );
    tx.send(start()).await.unwrap();

    let mut with_traffic = false;
    let mut emptied = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline && !(with_traffic && emptied) {
        if let Ok(TunnelEvent::RemoteSessions(list)) = rx.recv().await {
            if list.iter().any(|s| s.id == 7 && s.from_appliance == 200) {
                with_traffic = true;
            }
            if with_traffic && list.is_empty() {
                emptied = true;
            }
        }
    }
    assert!(with_traffic, "没有收到带流量的会话列表");
    assert!(emptied, "会话关闭后列表未清空");
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-core --test supervisor
```

预期：编译失败，`unresolved import rmc_core::state`。

- [ ] **Step 3: 写实现**

创建 `crates/rmc-core/src/state.rs`：

```rust
//! 对外的状态、命令与事件类型，见方案 3.5。

use crate::addr::HostPort;
use crate::error::ErrorClass;
use crate::preflight::PreflightReport;
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Idle,
    Preflight,
    Connecting,
    Connected { degraded: bool },
    Backoff { attempt: u32, delay: Duration },
    Stopping,
    Failed { class: ErrorClass, message: String },
}

pub enum Command {
    Start {
        username: String,
        password: Zeroizing<String>,
        gateway: HostPort,
        appliance: HostPort,
    },
    Cancel,
    Stop,
    RetryNow,
    DisconnectRemoteSession { id: u64 },
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::Start { username, gateway, appliance, .. } => f
                .debug_struct("Start")
                .field("username", username)
                .field("password", &"<redacted>")
                .field("gateway", gateway)
                .field("appliance", appliance)
                .finish(),
            Command::Cancel => write!(f, "Cancel"),
            Command::Stop => write!(f, "Stop"),
            Command::RetryNow => write!(f, "RetryNow"),
            Command::DisconnectRemoteSession { id } => {
                f.debug_struct("DisconnectRemoteSession").field("id", id).finish()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSessionInfo {
    pub id: u64,
    pub opened_at: SystemTime,
    pub to_appliance: u64,
    pub from_appliance: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TunnelEvent {
    State(State),
    Preflight(PreflightReport),
    RemoteSessions(Vec<RemoteSessionInfo>),
    HostKey { fingerprint: String, first_seen: bool },
    ConnectedSince(SystemTime),
}
```

创建 `crates/rmc-core/src/supervisor.rs`：

```rust
//! 状态机。唯一改变状态的地方，界面只读事件、只发命令。

use crate::backoff::{Backoff, Jitter};
use crate::config::Config;
use crate::error::{Error, ErrorClass};
use crate::platform::{SystemEvent, SystemEvents};
use crate::preflight;
use crate::audit::{Audit, Level};
use crate::state::{Command, RemoteSessionInfo, State, TunnelEvent};
use crate::transport::Transport;
use crate::tunnel::{TunnelFactory, TunnelHandle, TunnelMsg, TunnelParams};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{broadcast, mpsc};
use zeroize::Zeroizing;

pub const PORT_BUSY_RETRY: Duration = Duration::from_secs(5);
pub const PORT_BUSY_BUDGET: Duration = Duration::from_secs(120);
pub const APPLIANCE_PROBE: Duration = Duration::from_secs(30);

const EVENT_CAPACITY: usize = 256;
const MSG_CAPACITY: usize = 256;

pub struct Deps {
    pub factory: Arc<dyn TunnelFactory>,
    pub transport: Arc<Transport>,
    pub events: Arc<dyn SystemEvents>,
    pub jitter: fn() -> Box<dyn Jitter>,
}

/// 一次 Start 之后持有的凭据，断线重连时复用。
struct Credentials {
    username: String,
    password: Zeroizing<String>,
    gateway: crate::addr::HostPort,
    appliance: crate::addr::HostPort,
}

impl Credentials {
    fn params(&self, reverse_port: u16) -> TunnelParams {
        TunnelParams {
            username: self.username.clone(),
            password: self.password.clone(),
            reverse_port,
            appliance: self.appliance.clone(),
        }
    }
}

pub struct Supervisor;

impl Supervisor {
    pub fn spawn(
        cfg: Config,
        deps: Deps,
    ) -> (mpsc::Sender<Command>, broadcast::Receiver<TunnelEvent>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (ev_tx, ev_rx) = broadcast::channel(EVENT_CAPACITY);
        tokio::spawn(run(cfg, deps, cmd_rx, ev_tx));
        (cmd_tx, ev_rx)
    }
}

struct Ctx {
    cfg: Config,
    deps: Deps,
    ev: broadcast::Sender<TunnelEvent>,
    state: State,
    creds: Option<Credentials>,
    handle: Option<Box<dyn TunnelHandle>>,
    sessions: BTreeMap<u64, RemoteSessionInfo>,
    backoff: Backoff,
    port_busy_since: Option<Instant>,
}

impl Ctx {
    fn set_state(&mut self, s: State) {
        self.state = s.clone();
        let _ = self.ev.send(TunnelEvent::State(s));
    }

    fn publish_sessions(&self) {
        let list = self.sessions.values().cloned().collect();
        let _ = self.ev.send(TunnelEvent::RemoteSessions(list));
    }

    async fn teardown(&mut self) {
        if let Some(h) = self.handle.take() {
            h.shutdown().await;
        }
        self.sessions.clear();
        self.publish_sessions();
    }
}

async fn run(
    cfg: Config,
    deps: Deps,
    mut cmd_rx: mpsc::Receiver<Command>,
    ev: broadcast::Sender<TunnelEvent>,
) {
    let mut sys = deps.events.subscribe();
    let jitter = deps.jitter;
    let mut ctx = Ctx {
        cfg,
        deps,
        ev,
        state: State::Idle,
        creds: None,
        handle: None,
        sessions: BTreeMap::new(),
        backoff: Backoff::new(jitter()),
        port_busy_since: None,
    };
    let (msg_tx, mut msg_rx) = mpsc::channel::<TunnelMsg>(MSG_CAPACITY);

    ctx.set_state(State::Idle);

    // 下一次尝试连接的时刻。None 表示不在重试中。
    let mut retry_at: Option<Instant> = None;
    // degraded 时下一次探测一体机的时刻。None 表示不在探测中。
    let mut probe_at: Option<Instant> = None;

    loop {
        let idle = Instant::now() + Duration::from_secs(3600);
        let sleep_until = retry_at.unwrap_or(idle);
        let probe_until = probe_at.unwrap_or(idle);

        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { ctx.teardown().await; return };
                match cmd {
                    Command::Start { username, password, gateway, appliance } => {
                        if !matches!(ctx.state, State::Idle | State::Failed { .. }) {
                            continue;
                        }
                        ctx.creds = Some(Credentials { username, password, gateway, appliance });
                        ctx.backoff = Backoff::new((ctx.deps.jitter)());
                        ctx.port_busy_since = None;
                        retry_at = None;
                        probe_at = None;
                        if run_preflight(&mut ctx).await {
                            retry_at = attempt(&mut ctx, &msg_tx).await;
                        }
                    }
                    Command::Cancel | Command::Stop => {
                        ctx.set_state(State::Stopping);
                        ctx.teardown().await;
                        ctx.creds = None;
                        retry_at = None;
                        probe_at = None;
                        ctx.set_state(State::Idle);
                    }
                    Command::RetryNow => {
                        if matches!(ctx.state, State::Backoff { .. } | State::Failed { .. }) {
                            ctx.backoff.reset();
                            retry_at = attempt(&mut ctx, &msg_tx).await;
                        }
                    }
                    Command::DisconnectRemoteSession { id } => {
                        if let Some(h) = ctx.handle.as_ref() {
                            let _ = h.close_remote_session(id).await;
                        }
                    }
                }
            }

            Ok(event) = sys.recv() => {
                // 网络变化与休眠恢复都清零退避并立刻重试。
                if matches!(ctx.state, State::Backoff { .. })
                    && matches!(event, SystemEvent::NetworkChanged | SystemEvent::ResumedFromSleep)
                {
                    ctx.backoff.reset();
                    retry_at = attempt(&mut ctx, &msg_tx).await;
                }
            }

            Some(msg) = msg_rx.recv() => {
                handle_msg(&mut ctx, msg, &msg_tx, &mut retry_at, &mut probe_at).await;
            }

            _ = tokio::time::sleep_until(sleep_until.into()), if retry_at.is_some() => {
                retry_at = attempt(&mut ctx, &msg_tx).await;
            }

            _ = tokio::time::sleep_until(probe_until.into()), if probe_at.is_some() => {
                probe_at = probe_appliance(&mut ctx).await;
            }
        }
    }
}

async fn run_preflight(ctx: &mut Ctx) -> bool {
    let Some(c) = ctx.creds.as_ref() else { return false };
    ctx.set_state(State::Preflight);
    let report =
        preflight::run(ctx.deps.transport.as_ref(), &c.gateway, &c.appliance).await;
    let passed = report.passed();
    let failure = report.first_failure().cloned();
    let _ = ctx.ev.send(TunnelEvent::Preflight(report));
    if !passed {
        let (class, message) = match failure.map(|s| s.outcome) {
            Some(crate::preflight::StepOutcome::Fail { class, detail }) => (class, detail),
            _ => (ErrorClass::Network, "预检未通过".to_string()),
        };
        ctx.set_state(State::Failed { class, message });
        return false;
    }
    true
}

/// 尝试建立一次隧道。返回下一次重试的时刻，None 表示不再重试。
async fn attempt(ctx: &mut Ctx, msg_tx: &mpsc::Sender<TunnelMsg>) -> Option<Instant> {
    let Some(creds) = ctx.creds.as_ref() else { return None };
    ctx.set_state(State::Connecting);

    let params = creds.params(ctx.cfg.reverse_port);
    match ctx.deps.factory.establish(params, msg_tx.clone()).await {
        Ok(handle) => {
            ctx.handle = Some(handle);
            ctx.port_busy_since = None;
            ctx.backoff.reset();
            let _ = ctx.ev.send(TunnelEvent::ConnectedSince(SystemTime::now()));
            ctx.set_state(State::Connected { degraded: false });
            None
        }
        Err(e) => schedule_retry(ctx, e),
    }
}

/// degraded 时每 30 秒探测一体机，恢复即转回。返回下一次探测时刻。
async fn probe_appliance(ctx: &mut Ctx) -> Option<Instant> {
    let appliance = ctx.creds.as_ref()?.appliance.clone();
    match ctx
        .deps
        .transport
        .probe_tcp(&appliance, Duration::from_secs(5))
        .await
    {
        Ok(_) => {
            ctx.audit.record(Level::Info, "一体机恢复可达");
            if matches!(ctx.state, State::Connected { degraded: true }) {
                ctx.set_state(State::Connected { degraded: false });
            }
            None
        }
        Err(_) => Some(Instant::now() + APPLIANCE_PROBE),
    }
}

/// 按错误分类决定是否以及何时重试。
fn schedule_retry(ctx: &mut Ctx, e: Error) -> Option<Instant> {
    match e.class() {
        ErrorClass::Fatal => {
            ctx.set_state(State::Failed { class: ErrorClass::Fatal, message: e.to_string() });
            None
        }
        ErrorClass::Auth => {
            // 回到 Idle 让界面提示重新输入，凭据同时清掉。
            ctx.creds = None;
            ctx.set_state(State::Idle);
            None
        }
        ErrorClass::PortBusy => {
            let since = *ctx.port_busy_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= PORT_BUSY_BUDGET {
                ctx.set_state(State::Failed {
                    class: ErrorClass::PortBusy,
                    message: format!("{e}，{} 秒内未能注册", PORT_BUSY_BUDGET.as_secs()),
                });
                return None;
            }
            ctx.set_state(State::Backoff { attempt: ctx.backoff.attempt(), delay: PORT_BUSY_RETRY });
            Some(Instant::now() + PORT_BUSY_RETRY)
        }
        ErrorClass::Network | ErrorClass::ApplianceUnreachable => {
            let delay = ctx.backoff.next_delay();
            ctx.set_state(State::Backoff { attempt: ctx.backoff.attempt(), delay });
            Some(Instant::now() + delay)
        }
    }
}

async fn handle_msg(
    ctx: &mut Ctx,
    msg: TunnelMsg,
    msg_tx: &mpsc::Sender<TunnelMsg>,
    retry_at: &mut Option<Instant>,
    probe_at: &mut Option<Instant>,
) {
    match msg {
        TunnelMsg::Authenticated { host_key_fp, first_seen } => {
            let _ = ctx.ev.send(TunnelEvent::HostKey { fingerprint: host_key_fp, first_seen });
        }
        TunnelMsg::ForwardRegistered { .. } => {}
        TunnelMsg::RemoteSessionOpened { id } => {
            ctx.sessions.insert(
                id,
                RemoteSessionInfo {
                    id,
                    opened_at: SystemTime::now(),
                    to_appliance: 0,
                    from_appliance: 0,
                },
            );
            ctx.publish_sessions();
            // 有会话成功打开说明一体机恢复了，不必再探测。
            if matches!(ctx.state, State::Connected { degraded: true }) {
                ctx.set_state(State::Connected { degraded: false });
                *probe_at = None;
            }
        }
        TunnelMsg::RemoteSessionBytes { id, to_appliance, from_appliance } => {
            if let Some(s) = ctx.sessions.get_mut(&id) {
                s.to_appliance = to_appliance;
                s.from_appliance = from_appliance;
                ctx.publish_sessions();
            }
        }
        TunnelMsg::RemoteSessionClosed { id } => {
            ctx.sessions.remove(&id);
            ctx.publish_sessions();
        }
        TunnelMsg::ApplianceDialFailed { .. } => {
            if matches!(ctx.state, State::Connected { degraded: false }) {
                ctx.set_state(State::Connected { degraded: true });
                // 进入 degraded 后开始周期探测一体机。
                *probe_at = Some(Instant::now() + APPLIANCE_PROBE);
            }
        }
        TunnelMsg::Disconnected { reason } => {
            ctx.teardown().await;
            if ctx.creds.is_some() {
                *retry_at = schedule_retry(ctx, Error::SshTransport(reason));
                // 立刻发起一次，不等下一轮 select 的定时器。
                if retry_at.is_none() {
                    return;
                }
                let _ = msg_tx;
            }
        }
    }
}
```

在 `lib.rs` 加 `pub mod state;` 与 `pub mod supervisor;`，并 `pub use state::{Command, State, TunnelEvent};`。

- [ ] **Step 4: 运行测试确认通过**

```bash
cargo test -p rmc-core --test supervisor
```

预期：13 passed。若 `port_busy_retries_every_five_seconds_then_fails_after_budget` 的次数偏差超过 2，检查 `port_busy_since` 是否在每次 `Start` 时被清空。

- [ ] **Step 5: 提交**

```bash
git add crates/rmc-core/src/state.rs crates/rmc-core/src/supervisor.rs \
        crates/rmc-core/src/lib.rs crates/rmc-core/tests/supervisor.rs
git commit -m "feat(core): 状态机与 Supervisor"
```

---

### Task 11: 审计日志

**Files:**
- Create: `crates/rmc-core/src/audit.rs`
- Modify: `crates/rmc-core/src/lib.rs`
- Modify: `crates/rmc-core/src/supervisor.rs`
- Test: `crates/rmc-core/tests/audit.rs`

**Interfaces:**
- Consumes: Task 10 的 `State`、`TunnelMsg`
- Produces:
  - `pub enum Level { Info, Warn, Error }`
  - `pub struct Audit`，`Audit::open(dir: PathBuf) -> Result<Self>`
  - `Audit::record(&self, level: Level, message: &str)`
  - `Audit::current_path(&self) -> PathBuf`（`rmc-YYYY-MM-DD.log`）
  - `Audit::prune(&self) -> Result<usize>`，删除超过 30 天的文件
  - `pub const RETENTION_DAYS: u64 = 30`
  - Supervisor 在每次状态变迁与每条 `TunnelMsg` 上调用 `record`

- [ ] **Step 1: 写下失败的测试**

创建 `crates/rmc-core/tests/audit.rs`：

```rust
use rmc_core::audit::{Audit, Level, RETENTION_DAYS};
use std::time::{Duration, SystemTime};

fn tmpdir() -> std::path::PathBuf {
    use std::time::UNIX_EPOCH;
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let d = std::env::temp_dir().join(format!("rmc-audit-{n}"));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn writes_lines_with_level_and_timestamp() {
    let dir = tmpdir();
    let a = Audit::open(dir.clone()).unwrap();
    a.record(Level::Info, "状态 Connecting → Connected");
    a.record(Level::Warn, "反向端口 22001 被占用");
    a.record(Level::Error, "Gateway 连接被重置");

    let text = std::fs::read_to_string(a.current_path()).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("INFO"), "{}", lines[0]);
    assert!(lines[1].contains("WARN"), "{}", lines[1]);
    assert!(lines[2].contains("ERROR"), "{}", lines[2]);
    // 时间戳形如 2026-09-13T11:12:44
    assert!(lines[0].starts_with("20"), "{}", lines[0]);
    assert!(lines[0].contains('T'), "{}", lines[0]);
}

#[test]
fn file_name_carries_the_date() {
    let dir = tmpdir();
    let a = Audit::open(dir).unwrap();
    let name = a.current_path().file_name().unwrap().to_string_lossy().to_string();
    assert!(name.starts_with("rmc-"), "{name}");
    assert!(name.ends_with(".log"), "{name}");
    assert_eq!(name.len(), "rmc-2026-09-13.log".len(), "{name}");
}

#[test]
fn appends_across_reopen() {
    let dir = tmpdir();
    Audit::open(dir.clone()).unwrap().record(Level::Info, "第一行");
    Audit::open(dir.clone()).unwrap().record(Level::Info, "第二行");
    let a = Audit::open(dir).unwrap();
    let text = std::fs::read_to_string(a.current_path()).unwrap();
    assert_eq!(text.lines().count(), 2, "{text}");
}

#[test]
fn prune_removes_files_older_than_retention() {
    let dir = tmpdir();
    let a = Audit::open(dir.clone()).unwrap();
    a.record(Level::Info, "今天");

    // 造一个 40 天前的文件
    let old = dir.join("rmc-2000-01-01.log");
    std::fs::write(&old, "老日志\n").unwrap();
    let long_ago = SystemTime::now() - Duration::from_secs(40 * 86_400);
    filetime::set_file_mtime(&old, filetime::FileTime::from_system_time(long_ago)).unwrap();

    let removed = a.prune().unwrap();
    assert_eq!(removed, 1);
    assert!(!old.exists());
    assert!(a.current_path().exists(), "当天日志不该被删");
}

#[test]
fn prune_keeps_files_inside_retention() {
    let dir = tmpdir();
    let a = Audit::open(dir.clone()).unwrap();
    let recent = dir.join("rmc-2026-09-01.log");
    std::fs::write(&recent, "较近的日志\n").unwrap();
    let days_ago = SystemTime::now() - Duration::from_secs((RETENTION_DAYS - 2) * 86_400);
    filetime::set_file_mtime(&recent, filetime::FileTime::from_system_time(days_ago)).unwrap();

    assert_eq!(a.prune().unwrap(), 0);
    assert!(recent.exists());
}

#[test]
fn prune_ignores_unrelated_files() {
    let dir = tmpdir();
    let a = Audit::open(dir.clone()).unwrap();
    let other = dir.join("notes.txt");
    std::fs::write(&other, "x").unwrap();
    let long_ago = SystemTime::now() - Duration::from_secs(400 * 86_400);
    filetime::set_file_mtime(&other, filetime::FileTime::from_system_time(long_ago)).unwrap();

    assert_eq!(a.prune().unwrap(), 0);
    assert!(other.exists(), "非日志文件不得被删");
}

#[test]
fn record_strips_newlines_to_keep_one_event_per_line() {
    let dir = tmpdir();
    let a = Audit::open(dir).unwrap();
    a.record(Level::Error, "第一段\n第二段\r\n第三段");
    let text = std::fs::read_to_string(a.current_path()).unwrap();
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(text.contains("第一段"), "{text}");
    assert!(text.contains("第三段"), "{text}");
}
```

再加一个跨模块断言，确认口令不会经由 Supervisor 落到日志。追加到 `crates/rmc-core/tests/supervisor.rs`：

```rust
#[tokio::test(start_paused = true)]
async fn password_never_reaches_the_audit_log() {
    use rmc_core::audit::Audit;

    let dir = std::env::temp_dir().join(format!(
        "rmc-audit-sup-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let mut cfg = config();
    cfg.log_dir = dir.clone();

    let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
        TunnelMsg::Authenticated { host_key_fp: "SHA256:aaa".into(), first_seen: true },
        TunnelMsg::ForwardRegistered { port: 22001 },
    ])]);
    let (tx, mut rx) = Supervisor::spawn(
        cfg,
        deps(factory, Arc::new(NoSystemEvents::default())),
    );
    tx.send(Command::Start {
        username: "tunnel-zhang".into(),
        password: Zeroizing::new("PLAINTEXT-SECRET-9f2a".into()),
        gateway: "gateway.company.com:443".parse().unwrap(),
        appliance: "192.168.100.10:22".parse().unwrap(),
    })
    .await
    .unwrap();
    states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;

    let a = Audit::open(dir.clone()).unwrap();
    let text = std::fs::read_to_string(a.current_path()).unwrap_or_default();
    assert!(!text.is_empty(), "Supervisor 应当写入审计日志");
    assert!(!text.contains("PLAINTEXT-SECRET-9f2a"), "口令进了日志：{text}");
    assert!(text.contains("Connected"), "状态变迁未入日志：{text}");
}
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cargo test -p rmc-core --test audit
```

预期：编译失败，`unresolved import rmc_core::audit`。

- [ ] **Step 3: 写最小实现**

在 `crates/rmc-core/Cargo.toml` 加：

```toml
time = { version = "0.3", features = ["formatting", "local-offset", "macros"] }

[dev-dependencies]
filetime = "0.2"
```

创建 `crates/rmc-core/src/audit.rs`：

```rust
//! 本地审计日志。按天滚动，保留 30 天。
//! 只记录状态变迁与会话账目，不记录口令与转发内容。

use crate::error::Result;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub const RETENTION_DAYS: u64 = 30;

const PREFIX: &str = "rmc-";
const SUFFIX: &str = ".log";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

pub struct Audit {
    dir: PathBuf,
}

fn today() -> time::OffsetDateTime {
    time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc())
}

impl Audit {
    pub fn open(dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn current_path(&self) -> PathBuf {
        let d = today();
        let name = format!(
            "{PREFIX}{:04}-{:02}-{:02}{SUFFIX}",
            d.year(),
            u8::from(d.month()),
            d.day()
        );
        self.dir.join(name)
    }

    /// 写一行。换行被折成空格，保证一个事件一行。
    pub fn record(&self, level: Level, message: &str) {
        let flat = message.replace("\r\n", " ").replace(['\n', '\r'], " ");
        let d = today();
        let line = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02} {} {}\n",
            d.year(),
            u8::from(d.month()),
            d.day(),
            d.hour(),
            d.minute(),
            d.second(),
            level.as_str(),
            flat
        );
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.current_path())
        {
            let _ = f.write_all(line.as_bytes());
        }
    }

    /// 删除修改时间早于保留期的日志文件，返回删除个数。
    pub fn prune(&self) -> Result<usize> {
        let cutoff = SystemTime::now() - Duration::from_secs(RETENTION_DAYS * 86_400);
        let mut removed = 0usize;
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if !is_log_file(&path) {
                continue;
            }
            let modified = entry.metadata()?.modified()?;
            if modified < cutoff {
                std::fs::remove_file(&path)?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

fn is_log_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with(PREFIX) && n.ends_with(SUFFIX))
        .unwrap_or(false)
}
```

在 `supervisor.rs` 的 `Ctx` 加 `audit: Audit` 字段，`run` 中用 `Audit::open(cfg.log_dir.clone())` 构造并在开始时调用一次 `prune()`。在 `set_state` 里记录状态变迁：

```rust
fn set_state(&mut self, s: State) {
    let level = match &s {
        State::Failed { .. } => Level::Error,
        State::Backoff { .. } | State::Connected { degraded: true } => Level::Warn,
        _ => Level::Info,
    };
    self.audit.record(level, &format!("状态 {:?} → {:?}", self.state, s));
    self.state = s.clone();
    let _ = self.ev.send(TunnelEvent::State(s));
}
```

在 `handle_msg` 开头加一行 `ctx.audit.record(Level::Info, &format!("{msg:?}"));`。`TunnelMsg` 与 `Command` 的 `Debug` 都已遮蔽口令，因此这两处不会泄露。

- [ ] **Step 4: 运行测试确认通过**

```bash
cargo test -p rmc-core --test audit
cargo test -p rmc-core --test supervisor password_never_reaches_the_audit_log
```

预期：7 passed，随后 1 passed。

- [ ] **Step 5: 提交**

```bash
git add crates/rmc-core/src/audit.rs crates/rmc-core/src/lib.rs \
        crates/rmc-core/src/supervisor.rs crates/rmc-core/Cargo.toml crates/rmc-core/tests/audit.rs
git commit -m "feat(core): 审计日志滚动与 30 天保留"
```

---

### Task 12: CI 与依赖审计

**Files:**
- Create: `.github/workflows/core.yml`
- Create: `deny.toml`
- Create: `crates/rmc-core/README.md`
- Modify: `docs/方案设计.md`（补 3.8 的反向端口来源）

**Interfaces:**
- Consumes: 前十一个任务的全部测试
- Produces: CI 工作流 `core`

- [ ] **Step 1: 写下工作流**

创建 `deny.toml`：

```toml
[advisories]
yanked = "deny"

[licenses]
allow = ["MIT", "Apache-2.0", "ISC", "BSD-2-Clause", "BSD-3-Clause", "Unicode-3.0", "Zlib"]

[bans]
multiple-versions = "warn"
# 明确禁止把 OpenSSL 拖进来，TLS 只用 rustls。
deny = [{ name = "openssl-sys" }, { name = "native-tls" }]
```

创建 `.github/workflows/core.yml`：

```yaml
name: core

on:
  push:
    paths: ["crates/**", "Cargo.*", "deny.toml", ".github/workflows/core.yml"]
  pull_request:
    paths: ["crates/**", "Cargo.*", "deny.toml", ".github/workflows/core.yml"]

jobs:
  unit:
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.82
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all -- --check
      - run: cargo clippy -p rmc-core --all-targets -- -D warnings
      - run: cargo test -p rmc-core --lib
      - run: cargo test -p rmc-core --test connect --test supervisor --test audit --test preflight

  integration:
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.82
      - uses: Swatinem/rust-cache@v2

      - name: 安装测试依赖
        run: |
          sudo apt-get update
          sudo apt-get install -y sshpass socat openssh-client
          echo "127.0.0.1 gateway.test" | sudo tee -a /etc/hosts

      - name: 拉起 Gateway 测试环境
        run: |
          mkdir -p gateway/test-env/engineer-keys
          ssh-keygen -q -t ed25519 -N '' -f gateway/test-env/engineer-keys/eng_ed25519
          cp gateway/test-env/engineer-keys/eng_ed25519.pub \
             gateway/test-env/engineer-keys/authorized_keys
          cd gateway/test-env && docker compose up -d --build
          cd ../.. && ./crates/rmc-core/tests/fetch-harness-cert.sh

      - name: 集成测试
        run: |
          cargo test -p rmc-core --test transport -- --ignored --test-threads=1
          cargo test -p rmc-core --test ssh_tunnel -- --ignored --test-threads=1
          cargo test -p rmc-core --test forwarding -- --ignored --test-threads=1
          cargo test -p rmc-core --test preflight -- --ignored --test-threads=1

      - name: 失败时导出容器日志
        if: failure()
        run: cd gateway/test-env && docker compose logs --no-color

  deny:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v2
```

- [ ] **Step 2: 本地跑一遍 CI 的全部命令**

```bash
cargo fmt --all -- --check
cargo clippy -p rmc-core --all-targets -- -D warnings
cargo test -p rmc-core
cargo install cargo-deny --locked && cargo deny check
```

预期：全部通过。`cargo deny` 若报出未列入 allow 的许可证，确认该依赖可接受后加入 `allow` 列表，不要改成 `allow-osi-fsf-free`。

- [ ] **Step 3: 写 crate 说明并回填方案**

创建 `crates/rmc-core/README.md`：

```markdown
# rmc-core

远程维护客户端的内核。平台无关，在 Linux 上完整可测。设计依据见
`../../docs/方案设计.md` 第 3 章。

## 对外接口

```rust
let (cmd_tx, mut ev_rx) = Supervisor::spawn(config, deps);
cmd_tx.send(Command::Start { username, password, gateway, appliance }).await?;
while let Ok(event) = ev_rx.recv().await {
    // TunnelEvent::State / Preflight / RemoteSessions / HostKey / ConnectedSince
}
```

界面只发 `Command`、只读 `TunnelEvent`，不直接调用内部模块。

## 平台能力注入

`platform.rs` 中的三个 trait 由 rmc-win 实现：`ProxyResolver`、
`ProxyAuthenticator`、`SystemEvents`。口令存储不在 core 内，界面填好口令后
经 `Command::Start` 下发。Linux 测试用同文件里的 `NoProxy`、`NoProxyAuth`、
`NoSystemEvents`。

## 测试

```bash
cargo test -p rmc-core                    # 单元与假隧道测试，不碰网络
cd ../../gateway/test-env && docker compose up -d
./tests/fetch-harness-cert.sh
cargo test -p rmc-core -- --ignored --test-threads=1   # 真实链路
```

`--test-threads=1` 是必须的：多个集成用例会争抢同一个反向端口。

## 口令处理

口令只以 `Zeroizing<String>` 存在于内存，`TunnelParams` 与 `Command` 的
`Debug` 实现都把它替换为 `<redacted>`，`tests/supervisor.rs` 有一条用例
断言口令不会出现在审计日志中。
```

回填方案：在 `docs/方案设计.md` 的 3.8 节列表中，`- 允许端口编译进客户端二进制；` 之后插入

```
- 本账号的反向端口随账号由运维下发，存在应用目录的配置文件里，取值须落在允许范围内；
```

- [ ] **Step 4: 推分支验证 CI**

```bash
git push -u origin HEAD
gh run watch
```

预期：`core` 的三个 job 全绿。

- [ ] **Step 5: 提交**

```bash
git add .github/workflows/core.yml deny.toml crates/rmc-core/README.md docs/方案设计.md
git commit -m "ci(core): 单元与集成测试工作流、依赖审计"
```

---

## 自检

**规格覆盖**

| 方案条目 | 对应任务 |
|---|---|
| 3.2 crate 划分 | Task 1（rmc-core 部分） |
| 3.3 六个组件 | Config/addr → Task 3；Transport → Task 5、6；SshTunnel → Task 7、8；Supervisor → Task 10；Preflight → Task 9；Audit → Task 11 |
| 3.3 只暴露三个接口 | Task 10 的 `lib.rs` 导出 |
| 3.4 隧道建立流程五步 | Task 7、8、9 |
| 3.5 状态机与状态表 | Task 10 |
| 3.6 五类错误与重连 | Task 1（分类）、Task 10（行为） |
| 3.6 凭据复用与事件清零退避 | Task 10 的两个用例 |
| 3.7 远程会话可见性与单独断开 | Task 8、10 |
| 3.8 known_hosts 首次记录 | Task 4、7 |
| 3.8 日志保留与不记录口令 | Task 11 |
| 3.9 系统代理与 SSPI 的注入点 | Task 5 的两个 trait，实现归 rmc-win |
| 8 章 rmc-core 全部用例 | Task 5 至 11 逐条对应 |

**留给 rmc-win 与 rmc-app 的接口**

- 需实现 `ProxyResolver`、`ProxyAuthenticator`、`SystemEvents` 三个 trait。
- 口令存储不在 core 内，`Command::Start` 由界面填好口令后下发。
- 界面渲染所需的全部信息都来自 `TunnelEvent` 五个变体，不要读 core 内部状态。
- `State` 的七个变体与方案 3.5 的界面表一一对应，颜色与可用操作在界面侧决定。
