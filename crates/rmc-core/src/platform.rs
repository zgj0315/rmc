//! 平台相关能力的注入点。rmc-core 只依赖这些 trait，Windows 实现
//! （系统代理发现、SSPI 协商、电源/网络事件）在后续任务的 rmc-win 里
//! 落地。这里定义的 trait 与默认实现（`NoProxy`/`NoProxyAuth`/
//! `NoSystemEvents`）本身不依赖任何 Windows API，`cargo test -p
//! rmc-core` 必须能在 Linux/macOS 上通过——这是本任务的硬约束，不是
//! 可选项。

use crate::addr::HostPort;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;
use zeroize::Zeroizing;

/// 可读可写的字节流：TCP、经 HTTP CONNECT 打通的隧道、裹了 TLS 之后的
/// 流，都实现这个 trait。任何同时满足 `AsyncRead + AsyncWrite + Send +
/// Unpin + 'static` 的类型自动获得实现，调用方不需要手写。
pub trait Io: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Io for T {}

/// 到 Gateway 的连接，可能是明文 TCP，也可能已经裹上 TLS——上层只关心
/// "能读写字节"这一件事，不关心具体是哪一层。
pub type Conn = Box<dyn Io>;

/// 解析系统代理配置。返回 `None` 表示直连，不经过代理。
///
/// 现场的代理策略通常来自 WinHTTP/WinINet 的系统配置（PAC 脚本、
/// 手工配置的固定代理），这些都是 Windows 平台特有的能力，故只留
/// trait，由 rmc-win 实现；rmc-core 自身不发起任何系统 API 调用。
#[async_trait::async_trait]
pub trait ProxyResolver: Send + Sync {
    async fn resolve(&self, target: &HostPort) -> Option<HostPort>;
}

/// 代理认证协商。每一轮把服务端上一次的 `Proxy-Authenticate` challenge
/// （若有）交进来，返回下一个 `Proxy-Authorization` 的值（不含 scheme
/// 前缀，`http_connect` 会自己拼上）。返回 `None` 表示协商到此为止、
/// 无法再往前推进——Negotiate/NTLM 的多轮协商由平台层的 SSPI 驱动，
/// rmc-core 只负责把 challenge 转交、把结果的 token 塞进下一次请求。
///
/// # 返回值为什么是 [`Zeroizing<String>`]（W36）
///
/// 这一段 base64 看着人畜无害，装的却是域凭据的派生物：NTLM Type-3
/// 消息里是 NT/LM response（离线爆破 NTLMv2 response 是成熟手法），
/// Kerberos AP-REQ 里是用会话密钥加密的 authenticator。它确实不进日志
/// 也不进错误（`send_request` 不打日志，`Error::ProxyAuthFailed` 只带
/// scheme），但普通 `String` 在 drop 时不抹零，这段字节会以残影的形式
/// 留在堆上直到被下一次分配覆盖——诊断包导出（Task 9）里一旦有人加进
/// 程内存快照，那就是现成的凭据派生物。
///
/// 同一条纪律见 `http_connect`：它把 token 拼进去的
/// `Proxy-Authorization` 头与整个请求缓冲也都是 `Zeroizing<String>`，
/// 只改这里的签名是堵不住的。
#[async_trait::async_trait]
pub trait ProxyAuthenticator: Send + Sync {
    async fn next_token(&self, scheme: &str, challenge: Option<&str>) -> Option<Zeroizing<String>>;
}

/// 系统事件。收到后 Supervisor（Task 10）清零退避计时并立即重连——
/// 网络切换、从睡眠唤醒之后没理由还按上一次失败算出的退避时间干等。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemEvent {
    NetworkChanged,
    ResumedFromSleep,
}

/// 系统事件源。`subscribe` 可以被多次调用，每次拿到独立的接收端——
/// 这是 `tokio::sync::broadcast` 的语义，不是这个 trait 另外加的约定。
pub trait SystemEvents: Send + Sync {
    fn subscribe(&self) -> broadcast::Receiver<SystemEvent>;
}

/// 直连，不经过任何代理。Linux/macOS 测试与确认没有代理的现场环境使用。
pub struct NoProxy;

#[async_trait::async_trait]
impl ProxyResolver for NoProxy {
    async fn resolve(&self, _target: &HostPort) -> Option<HostPort> {
        None
    }
}

/// 不做任何代理认证协商，遇到 407 直接失败——见
/// `transport::connect::http_connect` 收到 `None` 时的处理。
pub struct NoProxyAuth;

#[async_trait::async_trait]
impl ProxyAuthenticator for NoProxyAuth {
    async fn next_token(
        &self,
        _scheme: &str,
        _challenge: Option<&str>,
    ) -> Option<Zeroizing<String>> {
        None
    }
}

/// 不产生任何系统事件的占位实现，Linux/macOS 测试使用。内部持有的
/// `broadcast::Sender` 只是用来产出 `Receiver`（`subscribe` 靠它），
/// 从不对外暴露发送端，所以订阅者永远收不到任何事件——这正是"不产生
/// 事件"该有的样子，而不是"事件源根本不存在"（后者会让依赖
/// `subscribe()` 的调用方直接编译不过）。
pub struct NoSystemEvents(broadcast::Sender<SystemEvent>);

impl Default for NoSystemEvents {
    fn default() -> Self {
        Self(broadcast::channel(4).0)
    }
}

impl SystemEvents for NoSystemEvents {
    fn subscribe(&self) -> broadcast::Receiver<SystemEvent> {
        self.0.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_proxy_always_resolves_to_direct_connection() {
        let target: HostPort = "gateway.company.com:443".parse().unwrap();
        assert!(NoProxy.resolve(&target).await.is_none());
    }

    #[tokio::test]
    async fn no_proxy_auth_never_produces_a_token() {
        assert!(NoProxyAuth.next_token("Negotiate", None).await.is_none());
        assert!(NoProxyAuth
            .next_token("Negotiate", Some("TlRMTVNTUAAC"))
            .await
            .is_none());
    }

    #[test]
    fn no_system_events_subscriber_never_receives_anything() {
        // 没有任何人能拿到 NoSystemEvents 内部的 Sender 去发送事件——
        // 这条测试钉住的是"这个占位实现确实什么都不产出"，不是在测
        // tokio::sync::broadcast 本身的行为。
        let events = NoSystemEvents::default();
        let mut rx = events.subscribe();
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
    }
}
