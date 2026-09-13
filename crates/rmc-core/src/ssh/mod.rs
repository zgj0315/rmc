//! russh 实现的隧道：握手、host key 校验、口令认证、反向端口注册。

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
    pub fn new(transport: Arc<Transport>, known_hosts: Arc<KnownHosts>, gateway: HostPort) -> Self {
        Self {
            transport,
            known_hosts,
            gateway,
        }
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

        // R3（预扫描已发现）：不在这里 `.map_err(...)` 包一层。
        // `connect_stream` 返回 `Result<Handle<H>, H::Error>`，而
        // `H::Error = Error`（见 handler.rs 里 `type Error = Error`），
        // 这已经是我们自己的错误类型，不需要再映射一次。更重要的是：
        // 如果这里再包一层 map_err，`check_server_key` 返回的
        // `Error::HostKeyMismatch`（Fatal，不能自动重试）会被顺手裹成
        // `Error::SshTransport`（Network，无限退避重连）——把"连到一个
        // 冒充的 Gateway 应该立刻、永久地失败"变成"跟冒充者失联重试
        // 到天荒地老"。`recorded_but_changed_host_key_is_fatal`
        // （tests/ssh_tunnel.rs）钉住的就是这一条：谁把这行改回
        // `.map_err(...)`，这条测试的 `assert_eq!(err.class(),
        // ErrorClass::Fatal)` 立刻变红。
        let mut session = russh::client::connect_stream(config, conn, handler).await?;

        // 口令交给 russh 自己的 `String`（`P: Into<String>`），russh 不会
        // 对它做 zeroize——这是本模块唯一没法端到端保证"口令用后即焚"的
        // 环节，`Zeroizing<String>` 只能保证我们自己这一侧的副本被清零，
        // 一旦交出去就不再受我们控制，如实记在这里而不是假装做到了。
        let ok = session
            .authenticate_password(&params.username, params.password.as_str())
            .await?;
        if !ok.success() {
            return Err(Error::AuthRejected);
        }

        let (fp, first_seen) = verdict
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| Error::SshTransport("握手未产生 host key 校验结果".into()))?;
        let _ = tx
            .send(TunnelMsg::Authenticated {
                host_key_fp: fp,
                first_seen,
            })
            .await;

        session
            .tcpip_forward("127.0.0.1", params.reverse_port as u32)
            .await
            .map_err(|e| map_tcpip_forward_error(e, params.reverse_port))?;
        let _ = tx
            .send(TunnelMsg::ForwardRegistered {
                port: params.reverse_port,
            })
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

/// R9：`tcpip_forward` 的失败必须按*原因*分类，不能把 russh 返回的一切
/// 错误都笼统地当成"端口占用"。
///
/// russh 的 `tcpip_forward` 只有两种失败形状（见其源码）：
/// - `Error::RequestDenied`：服务端明确回了 SSH_MSG_REQUEST_FAILURE——
///   这条全局请求真的被拒了，可能是端口没在这个账号的 `PermitListen`
///   里，也可能是端口已经被同账号另一条会话占着（sshd 试图 bind 撞上
///   EADDRINUSE，两种服务端拒绝在协议层是同一个消息，客户端天然
///   分辨不出"为什么"被拒，见 tests/ssh_tunnel.rs 里两条
///   `#[ignore]` 用例上的说明）——这种情况退避重连没有意义，等一小段
///   固定时间再试才对，落 `ForwardPortBusy`（`PortBusy` 类）。
/// - 其他任何变体（`SendError`——请求都没发出去，会话早已经死了；
///   `Disconnect`——等回复的过程中连接断了）：这是链路层面的问题，跟
///   "端口是不是被占用"毫无关系，必须走退避重连（`Network` 类），不能
///   套用端口占用那套"固定 5 秒、最长 120 秒"的重试节奏——一次网络
///   抖动被误判成端口占用，最坏情况是重试 120 秒后放弃，比正常的
///   无限退避重连更差。
fn map_tcpip_forward_error(e: russh::Error, port: u16) -> Error {
    match e {
        russh::Error::RequestDenied => Error::ForwardPortBusy(port),
        other => Error::SshTransport(format!("反向端口 {port} 注册失败：{other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorClass;

    // 这条不需要 docker 环境，任何 `cargo test -p rmc-core` 都会跑到——
    // 它是 R9 真正的证据来源：tests/ssh_tunnel.rs 里
    // `port_outside_permitlisten_is_port_busy_class` 和
    // `second_tunnel_on_the_same_port_is_port_busy` 两条都只能观察到
    // 服务端真的把请求拒了（两种成因在协议层不可分辨，见上面的文档
    // 注释），没法在集成测试里证明"网络抖动不会被误判成端口占用"这条
    // 反向命题；这里直接摆事实：给这个函数喂 `SendError`/`Disconnect`，
    // 断言它们绝不会被判成 PortBusy。
    //
    // 会让这条测试变红的改法：把 `other => Error::SshTransport(...)`
    // 这个分支删掉，换成跟 `RequestDenied` 一样的 `ForwardPortBusy`
    // （也就是 brief 原文那种"一切失败都算端口占用"的写法）。
    #[test]
    fn request_denied_is_port_busy_but_disconnect_and_send_error_are_network() {
        let denied = map_tcpip_forward_error(russh::Error::RequestDenied, 22001);
        assert_eq!(denied.class(), ErrorClass::PortBusy);
        assert!(matches!(denied, Error::ForwardPortBusy(22001)));

        for e in [russh::Error::Disconnect, russh::Error::SendError] {
            let mapped = map_tcpip_forward_error(e, 22001);
            assert_eq!(
                mapped.class(),
                ErrorClass::Network,
                "会话中途断线不该被当成端口占用去做固定 5 秒/最长 120 秒重试"
            );
        }
    }
}
