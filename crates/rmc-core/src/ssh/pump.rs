//! forwarded-tcpip 通道到一体机的双向转发。
//!
//! 占位实现：只负责接住 `ClientHandler::server_channel_open_forwarded_tcpip`
//! 已经 accept 过的 `Channel`，暂不转发任何字节——真正的双向拷贝、
//! `ApplianceDialFailed`/`RemoteSessionOpened`/`RemoteSessionClosed`/
//! `RemoteSessionBytes` 上报都留给 Task 8。
//!
//! 这个函数不能删掉参数直接返回：`Channel<Msg>` 在这里被 `run` 拿到
//! 所有权，函数体什么都不做也没关系——`Channel` 本体（不是
//! `into_stream()` 之后包了 `ChannelCloseOnDrop` 的那个流）被 drop 时不会
//! 主动发送 channel-close，所以持有它但不读写，效果是"通道保持打开但不
//! 转发任何数据"，不是"悄悄把通道关掉"。这一点被
//! `establishes_and_reports_first_seen_host_key`（tests/ssh_tunnel.rs）
//! 末尾那段原始 TCP 探测用来证明 `reply.accept()` 真的被调用过：一个
//! 连到反向端口的原始 TCP 客户端会一直连着、读不到任何字节也读不到
//! EOF，而不是刚连上就被服务端挂断。

use crate::addr::HostPort;
use crate::tunnel::TunnelMsg;
use tokio::sync::mpsc;

/// 关闭某条远程会话的句柄。
pub struct Closer(#[allow(dead_code)] tokio::sync::oneshot::Sender<()>);

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
    // Task 8 实现：拨号一体机、双向拷贝字节、上报 TunnelMsg。
}
