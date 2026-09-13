//! russh 客户端回调。host key 校验与 forwarded-tcpip 通道的接收都在这里。
//!
//! R1（预扫描已发现）：`russh::client::Handler` 自 0.5x 起用原生
//! `async fn`（`-> impl Future`），`async-trait` 是 russh 的非默认
//! feature，`cargo add` 不会带出来——`impl` 这个 trait 时不能挂
//! `#[async_trait::async_trait]`，直接写 `async fn` 就是它要的形状。
//!
//! R3（预扫描已发现）：`check_server_key` 收的是
//! `&PublicKeyOrCertificate`，不是 `&PublicKey`——`PublicKeyBase64::
//! public_key_bytes` 是给 `PublicKey`/`PrivateKey` 用的，不适用于
//! `PublicKeyOrCertificate`，必须先 `.public_key()` 转一次。
//!
//! R4（预扫描已发现，后果最隐蔽的一处）：`server_channel_open_forwarded_tcpip`
//! 在 `session` 之前新增了一个 `reply: ChannelOpenHandle` 参数——
//! `ChannelOpenHandle` 落在 `russh::client::ChannelOpenHandle`，不是
//! crate 根。这个参数不能被忽略：`reply` 一旦被 drop 而没调用
//! `accept()`/`reject()`，等效于自动拒绝这条通道。把它随手命名成
//! `_reply` 能让代码编译通过、隧道正常连上、认证成功、反向端口也注册
//! 成功，但只要真的有人连进反向端口，通道会被悄悄拒绝，什么都转发不了
//! ——编译器抓不出这个问题，只能靠真的对着 gateway/test-env 跑一次
//! （见 tests/ssh_tunnel.rs 里的
//! `forwarded_channel_is_accepted_not_silently_rejected`）。

use crate::addr::HostPort;
use crate::error::Error;
use crate::knownhosts::{fingerprint_of, KnownHosts, Verdict};
use crate::tunnel::TunnelMsg;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

pub struct ClientHandler {
    pub gateway: HostPort,
    pub known_hosts: Arc<KnownHosts>,
    pub appliance: HostPort,
    pub reverse_port: u16,
    pub tx: mpsc::Sender<TunnelMsg>,
    pub next_session_id: Arc<AtomicU64>,
    /// host key 校验结果（指纹, 是否首次记录），establish 在认证成功后
    /// 读出来打包成 `TunnelMsg::Authenticated`。`check_server_key` 在
    /// 认证之前调用，用 `Mutex` 而不是直接返回值——它是 trait 方法，
    /// 签名由 russh 定死，没有别的地方能把结果带出去。
    pub verdict: Arc<Mutex<Option<(String, bool)>>>,
}

impl ClientHandler {
    pub fn alloc_session_id(&self) -> u64 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }
}

impl russh::client::Handler for ClientHandler {
    type Error = Error;

    /// 首次连接记录指纹，之后变更即拒绝。拒绝时返回 Err，握手随即失败，
    /// 且这个 Err 就是 `Error::HostKeyMismatch` 本身（不经过
    /// `From<russh::Error>` 那条笼统路径），分类是 Fatal，Supervisor
    /// 不会自动重试——见 error.rs 上 `From<russh::Error>` 的文档注释。
    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        use russh::keys::PublicKeyBase64;
        // R3：先转成 PublicKey 再取编码字节；PublicKeyOrCertificate 自己
        // 没有 public_key_bytes()。指纹算法与呈现方式见
        // knownhosts::fingerprint_of 的文档——直接产出 Fingerprint，不
        // 在这个安全关键路径上留一个本可以避免的 expect（R35）。
        let key = server_public_key.public_key();
        let fp = fingerprint_of(&key.public_key_bytes());
        match self.known_hosts.check(&self.gateway, &fp)? {
            Verdict::FirstSeen => {
                *self.verdict.lock().unwrap() = Some((fp.as_str().to_string(), true));
                Ok(true)
            }
            Verdict::Matched => {
                *self.verdict.lock().unwrap() = Some((fp.as_str().to_string(), false));
                Ok(true)
            }
        }
    }

    /// Gateway 上有人连到反向端口时触发。把通道接到一体机（Task 8 填实
    /// `pump::run`）。
    ///
    /// R4：`reply` 必须显式 `accept()` 或 `reject()`，两条路径都要走到
    /// 底——drop 掉 `reply` 等效于拒绝，见模块顶部的说明。
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        // 只接受自己注册过的端口和地址，防止服务端把别处的通道塞进来——
        // 全局约束：客户端请求的监听地址恒为 "127.0.0.1"，Gateway 的
        // forwarded-tcpip 消息按 OpenSSH 的实现会原样回显这个地址（跟
        // 实际绑定在哪个地址无关，GatewayPorts yes 之下实际绑定恒为
        // 通配、由服务端决定），所以这里比较的是"跟我们请求时说的一致"，
        // 不是在断言真实绑定地址。
        if connected_port as u16 != self.reverse_port || connected_address != "127.0.0.1" {
            tracing::warn!(
                connected_address,
                connected_port,
                "拒绝未注册的 forwarded-tcpip 通道"
            );
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }

        reply.accept().await;

        let id = self.alloc_session_id();
        let appliance = self.appliance.clone();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            super::pump::run(id, channel, appliance, tx).await;
        });
        Ok(())
    }
}
