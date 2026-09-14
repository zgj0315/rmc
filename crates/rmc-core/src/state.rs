//! 对外的状态、命令与事件类型，见方案 3.5。
//!
//! 本模块只定义数据形状，不含任何行为——状态机本身（唯一改变 [`State`]
//! 的地方）在 `supervisor.rs`。界面只读 [`TunnelEvent`]、只发
//! [`Command`]，不直接持有或修改 [`State`]。

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

/// 界面发给内核的命令。
///
/// `Start` 携带的 `gateway`/`appliance` 是界面上直接输入的原始地址——
/// Supervisor 处理这条命令时必须先用它们跑一遍
/// `config::ValidatedAddresses::validate`，校验通过才能继续（见
/// `supervisor.rs` 顶部的说明与 `config.rs` 上 `ValidatedAddresses` 的
/// 文档）。这两条字段特意留成裸 `HostPort` 而不是 `ValidatedAddresses`——
/// 后者的唯一生产构造入口就是 `validate` 本身，如果 `Command::Start`
/// 直接收 `ValidatedAddresses`，调用方（界面）就得自己先调用一次
/// `validate` 才能拼出这个命令，校验逻辑会被迫复制到 rmc-core 之外；
/// 让 Supervisor 在处理命令时统一做这件事，校验规则只有一份。
pub enum Command {
    Start {
        username: String,
        password: Zeroizing<String>,
        gateway: HostPort,
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
                username,
                gateway,
                appliance,
                ..
            } => f
                .debug_struct("Start")
                .field("username", username)
                .field("password", &"<redacted>")
                .field("gateway", gateway)
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
    HostKey {
        fingerprint: String,
        first_seen: bool,
    },
    ConnectedSince(SystemTime),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_start_debug_never_prints_the_password() {
        // 与 tunnel::TunnelParams 上同名测试对称：Command::Start 是另一个
        // 携带口令的公开类型，容易在加字段时漏掉手写 Debug 的同步维护。
        let cmd = Command::Start {
            username: "tunnel-zhang".into(),
            password: Zeroizing::new("super-secret-pw".to_string()),
            gateway: HostPort::new("gateway.company.com", 443).unwrap(),
            appliance: HostPort::new("192.168.1.1", 61001).unwrap(),
        };
        let printed = format!("{cmd:?}");
        assert!(!printed.contains("super-secret-pw"), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
    }
}
