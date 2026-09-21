//! russh 客户端回调。host key 校验与 forwarded-tcpip 通道的接收都在这里。
//!
//! R1（预扫描已发现）：`russh::client::Handler` 自 0.5x 起用原生
//! `async fn`（`-> impl Future`），`async-trait` 是 russh 的非默认
//! feature，`cargo add` 不会带出来——`impl` 这个 trait 时不能挂
//! `#[async_trait::async_trait]`，直接写 `async fn` 就是它要的形状。
//!
//! R3（预扫描已发现）：`check_server_key` 收的是
//! `&PublicKeyOrCertificate`，不是 `&PublicKey`——取 ed25519 公钥字节
//! 之前必须先 `.public_key()` 转一次；`.public_key()` 返回**拥有值**，
//! 不能在同一行里再借它的字段（`k.public_key().key_data().ed25519()`
//! 一行写会 E0716），必须先 `let pk = k.public_key();` 绑定。
//!
//! R4（预扫描已发现，后果最隐蔽的一处）：`server_channel_open_forwarded_tcpip`
//! 在 `session` 之前新增了一个 `reply: ChannelOpenHandle` 参数——
//! `ChannelOpenHandle` 落在 `russh::client::ChannelOpenHandle`，不是
//! crate 根。这个参数不能被忽略：`reply` 一旦被 drop 而没调用
//! `accept()`/`reject()`，等效于自动拒绝这条通道。把它随手命名成
//! `_reply` 能让代码编译通过、隧道正常连上、认证成功、反向端口也注册
//! 成功，但只要真的有人连进反向端口，通道会被悄悄拒绝，什么都转发不了
//! ——编译器抓不出这个问题。`crate::ssh::test_support` 里的进程内 russh
//! 服务端在协议层面直接验证这一点。
//!
//! # Task 10：host key 校验从 known_hosts 换成核对连接码里的指纹
//!
//! 没有「首次连接自动信任」，也没有本地状态可以回退——`fingerprint` 是
//! 连接码解析出来那一刻就定死的值（`code::ServerFingerprint`），跟
//! Task 9 里 TLS 那一层核对的是同一个数。握手阶段指纹不符就直接
//! `Err(Error::HostKeyMismatch)`，`connect_stream` 的 `?` 把它原样透传
//! 出去，认证请求根本不会被发出去——见 `ssh::mod` 上 `establish_over`
//! 的说明与 `mod::tests::a_wrong_fingerprint_is_fatal_before_any_password_is_sent`。

use crate::addr::HostPort;
use crate::code::ServerFingerprint;
use crate::error::Error;
use crate::tunnel::TunnelMsg;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct ClientHandler {
    /// 连接码里带出来的运维服务器指纹，TLS（Task 9）与 SSH（本任务）
    /// 两层核对的是同一个值。
    pub fingerprint: ServerFingerprint,
    pub appliance: HostPort,
    /// 服务端回填的反向端口；0 表示还没申请。forwarded-tcpip 通道按它
    /// 过滤——见下面 `server_channel_open_forwarded_tcpip` 的说明。
    pub registered_port: Arc<AtomicU16>,
    pub tx: mpsc::Sender<TunnelMsg>,
    pub next_session_id: Arc<AtomicU64>,
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

    /// 核对连接码里的指纹，不一致立刻拒绝——拒绝时返回的 `Err` 就是
    /// `Error::HostKeyMismatch` 本身（不经过 `From<russh::Error>` 那条
    /// 笼统路径），分类是 Fatal，Supervisor 不会自动重试。
    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // R3：`public_key()` 返回拥有值，先绑定再借，否则 E0716。
        let pk = server_public_key.public_key();
        let Some(ed) = pk.key_data().ed25519() else {
            return Err(Error::SshTransport(
                "运维服务器的 host key 不是 ed25519".into(),
            ));
        };
        let actual = ServerFingerprint::of_ed25519_public(&ed.0);
        if actual != self.fingerprint {
            return Err(Error::HostKeyMismatch {
                expected: self.fingerprint.to_string(),
                actual: actual.to_string(),
            });
        }
        Ok(true)
    }

    /// Gateway 上有人连到反向端口时触发。把通道接到一体机（Task 8 填实
    /// `pump::run`）。
    ///
    /// R4：`reply` 必须显式 `accept()` 或 `reject()`，两条路径都要走到
    /// 底——drop 掉 `reply` 等效于拒绝，见模块顶部的说明。
    ///
    /// Task 10：判断的基准从"构造时写死的 `reverse_port`"换成了
    /// `registered_port`——服务端回填的端口在 `establish_over` 里
    /// `session.tcpip_forward("", 0)` 拿到结果之后才写进这个原子变量。
    ///
    /// R10-2（修复轮 1，订正）：**这个"恒为 0"的窗口不止覆盖握手/认证
    /// 阶段**，上一版文案在这里写得像窗口只到认证完成——不对，窗口一直
    /// 延伸到 `establish_over` 里 `registered_port.store(port, ...)`
    /// 那一行真正执行完为止：`tcpip_forward("", 0).await` 拿到服务端的
    /// 应答之后，`u16::try_from` 转换、`port == 0` 校验、`store` 写入这
    /// 几步都还没做完，`registered_port` 读到的仍然是 0。如果服务端在
    /// 应答 tcpip-forward 之后、`store` 完成之前的这一小段时间窗口内就
    /// 主动开出一条 forwarded-tcpip 通道（协议上没有任何东西禁止它这样
    /// 抢跑），这条通道会被这里的 `want == 0` 分支误判成"未注册"而拒绝
    /// ——即便它注册的端口完全正确。
    ///
    /// 这个误拒不是假设：**裁决明确接受它**（见 R10-2 的裁决，不改成
    /// `Notify`/`watch` 这类握手结构）——代价是"隧道刚建立、工程师立刻
    /// 连进反向端口"这个极窄的时间点上，可能多失败一次重试，不是永久性
    /// 的功能缺陷；引入握手结构去堵这条窗口的复杂度不随时间收益，不值得
    /// 为了一个几毫秒的窗口引入额外的同步原语。
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        _connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        let want = self.registered_port.load(Ordering::SeqCst);
        if want == 0 || connected_port != u32::from(want) {
            tracing::warn!(
                connected_port,
                want,
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
