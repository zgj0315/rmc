//! 对外的状态、命令与事件类型，见方案 3.5。
//!
//! 本模块只定义数据形状，不含任何行为——状态机本身（唯一改变 [`State`]
//! 的地方）在 `supervisor.rs`。界面只读 [`TunnelEvent`]、只发
//! [`Command`]，不直接持有或修改 [`State`]。

use crate::addr::HostPort;
use crate::code::ConnectionCode;
use crate::diagnostic::ProxyObservation;
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

/// 界面发给内核的命令。
///
/// `Start` 携带一条已经解析好的 [`ConnectionCode`]（账号、运维服务器
/// 地址、指纹都从它取）与界面上直接输入的一体机原始地址 `appliance`。
/// `appliance` 特意留成裸 `HostPort` 而不是 `ValidatedAddresses`——
/// 后者的唯一生产构造入口就是 `config::ValidatedAddresses::validate`
/// 本身，如果 `Command::Start` 直接收 `ValidatedAddresses`，调用方
/// （界面）就得自己先调用一次 `validate` 才能拼出这个命令，校验逻辑会
/// 被迫复制到 rmc-core 之外；让 Supervisor 处理这条命令时统一调用
/// `ValidatedAddresses::validate(code.server(), appliance)`，校验规则
/// 只有一份（见 `supervisor.rs` 顶部的说明与 `config.rs` 上
/// `ValidatedAddresses` 的文档）。
///
/// 本任务（Task 8）只接线：`code` 携带的指纹目前还没有任何人核对
/// （TLS 仍走公共 CA、SSH 仍走 known_hosts），那是 Task 9 的事。
pub enum Command {
    Start {
        code: ConnectionCode,
        password: Zeroizing<String>,
        appliance: HostPort,
    },
    /// 取消一次尚未连接成功的开启（Preflight/Connecting 阶段）。
    Cancel,
    /// 停止当前会话（含 Backoff 中的自动重连）。
    Stop,
    /// 立即重试，跳过当前的退避等待或端口占用重试间隔。
    RetryNow,
    DisconnectRemoteSession {
        id: u64,
    },
}

/// 手写 `Debug`：口令是 `Zeroizing<String>`，绝不能出现在日志或调试输出里
/// ——`Command::Start` 是全局约束"口令不进 Debug 输出"覆盖到的少数几个
/// 携带口令的类型之一，必须像 `tunnel::TunnelParams` 一样单独遮蔽。
impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::Start {
                code, appliance, ..
            } => f
                .debug_struct("Start")
                .field("account", &code.account().as_str())
                .field("server", &code.server())
                .field("password", &"<redacted>")
                .field("appliance", appliance)
                .finish(),
            Command::Cancel => write!(f, "Cancel"),
            Command::Stop => write!(f, "Stop"),
            Command::RetryNow => write!(f, "RetryNow"),
            Command::DisconnectRemoteSession { id } => f
                .debug_struct("DisconnectRemoteSession")
                .field("id", id)
                .finish(),
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
    /// SSH host key 与连接码里的指纹核对一致（Task 10：换掉了带
    /// `first_seen` 的 `HostKey` 变体——没有「首次记录」这一说，见
    /// `tunnel::TunnelMsg::Authenticated` 上的说明）。
    ServerVerified {
        fingerprint: String,
    },
    /// 反向端口已经由运维服务器回填注册（Task 10）。
    ForwardPort(u16),
    ConnectedSince(SystemTime),
    /// 这次连接实际经过了什么：直连，还是某一台代理。
    ///
    /// **W173：界面要显示的代理只有这一条来路。** rmc-app 侧有一道源码
    /// 扫描（`this_crate_never_polls_the_transport_for_the_current_proxy`）
    /// 把「界面自己去查 `Transport::effective_proxy`」整条路封死了，理由
    /// 见 [`crate::diagnostic::ProxyObservation`]。
    Proxy(ProxyObservation),
}

/// 共用测试夹具：一条合法的连接码，账号 `tunnel-zhang`、地址
/// `203.0.113.10:22000`。`rmc-core` 里凡是需要一条 `ConnectionCode`
/// 夹具的测试模块（`supervisor.rs` 等）都走这一个，不各自手造——
/// 手造的话，指纹用什么字节、账号是否合法这类细节会在多处重复决定。
///
/// `.expect(...)`：端口 22000 非 0，`new` 只会在端口为 0 时拒绝，这里
/// 传的是编译期常量，不可能失败。
#[cfg(test)]
pub(crate) fn test_code() -> ConnectionCode {
    use crate::code::{AccountName, ServerFingerprint};
    ConnectionCode::new(
        AccountName::parse("tunnel-zhang").unwrap(),
        "203.0.113.10".parse().unwrap(),
        22000,
        ServerFingerprint::of_ed25519_public(&[9u8; 32]),
    )
    .expect("测试夹具：端口非 0，构造必定成功")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_start_debug_never_prints_the_password() {
        // 与 tunnel::TunnelParams 上同名测试对称：Command::Start 是另一个
        // 携带口令的公开类型，容易在加字段时漏掉手写 Debug 的同步维护。
        let cmd = Command::Start {
            code: test_code(),
            password: Zeroizing::new("super-secret-pw".to_string()),
            appliance: HostPort::new("192.168.1.1", 61001).unwrap(),
        };
        let printed = format!("{cmd:?}");
        assert!(!printed.contains("super-secret-pw"), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
    }
}
