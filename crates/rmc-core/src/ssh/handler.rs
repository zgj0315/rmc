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
//! ——编译器抓不出这个问题。`crate::ssh::test_support` 里的进程内 russh
//! 服务端在协议层面直接验证这一点（服务端主动开一个
//! forwarded-tcpip 通道，断言收到的是 CHANNEL_OPEN_CONFIRMATION 而不是
//! CHANNEL_OPEN_FAILURE，见 R40），`tests/ssh_tunnel.rs` 里
//! `establishes_and_reports_first_seen_host_key` 末尾另有一段对着真实
//! gateway/test-env 的原始 TCP 探测作为补充。

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
    /// 与 `SshTunnel` 共享的"当前打开的会话"账本，见
    /// `super::pump::SharedChannels` 上的文档。每次 accept 一条
    /// forwarded-tcpip 通道都把它原样传给 `pump::spawn`——插入/移除账本
    /// 的时机由 `pump::run` 自己负责，这里不直接碰这个 Mutex。
    pub channels: super::pump::SharedChannels,
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
        let blob = key.public_key_bytes();
        // R47（第二轮评审发现）：`public_key_bytes()` 上游实现是
        // `key_data().encoded().unwrap_or_default()`——编码失败时悄悄
        // 退化成空 `Vec`，而不是返回错误。空 blob 的指纹是一个固定值
        // （`SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU`，空字符串
        // 的 SHA256），会匹配**任何**同样触发了编码失败的服务端——这在
        // 实践中触发不了（当前支持的 key 类型都能正常编码），但拒绝它
        // 只要两行，没有理由留着这个口子。
        if blob.is_empty() {
            return Err(Error::SshTransport(
                "服务端公钥编码为空，无法计算指纹".into(),
            ));
        }
        let fp = fingerprint_of(&blob);
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
        // 只接受自己注册过的端口，防止服务端把别处的通道塞进来。
        //
        // R42（第二轮评审发现）：上一版这里还比较了
        // `connected_address != "127.0.0.1"`，已经删掉——两个字段都是
        // 服务端自己决定填什么的（这条消息报的是 Gateway 认为的"连接
        // 目标"，不是客户端能验证的东西），而这个账号只注册了一个端口，
        // 端口比对已经把范围收得够窄了，地址比对不能再排除任何攻击者
        // 服务端能满足的情况——不划走一分风险。它划走的是可用性：任何
        // 一个把这个字段回显成别的写法的 Gateway（不同的 sshd 实现、
        // Dropbear、IPv6 规整化写法、未来某个 OpenSSH 版本改了回显格式）
        // 会导致**全部**转发通道被拒绝，而 `establish()` 前面几步毫无
        // 异常——`Ok`、`Authenticated`、`ForwardRegistered` 照样发出去，
        // 界面显示隧道健康，实际什么都转发不了。这正是 R4 说的"通道被
        // 悄悄拒绝"那个后果，只是触发路径从"代码写错 `_reply`"换成了
        // "服务端回显的字符串跟预期不一样"，两条路径殊途同归，加这个
        // 检查反而是在制造它，不是在防它。
        if connected_port as u16 != self.reverse_port {
            tracing::warn!(
                connected_address,
                connected_port,
                "拒绝未注册端口的 forwarded-tcpip 通道"
            );
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }

        reply.accept().await;

        let id = self.alloc_session_id();
        super::pump::spawn(
            id,
            channel,
            self.appliance.clone(),
            self.tx.clone(),
            self.channels.clone(),
        );
        Ok(())
    }
}
