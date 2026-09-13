//! 隧道的抽象接口。Supervisor 只依赖这里，因此状态机可以用假隧道测试。
//!
//! R20：`appliance` 字段仍是裸 `HostPort`，不是 Task 3 的
//! `config::ValidatedAddresses`——config.rs 上 `ValidatedAddresses` 的文档
//! 注释已经把话挑明："Task 10 处理 Command::Start 时先调 validate，再用
//! 返回值里的地址去拨号"，也就是说这道校验的天然调用点在 Task 10，不在
//! 这里。这里权衡过，仍然决定不把 `ValidatedAddresses` 塞进
//! `TunnelParams`：
//!
//! - `ValidatedAddresses::validate` 拒绝一体机地址是本机回环——但
//!   `tests/ssh_tunnel.rs` 对着 gateway/test-env 跑真实链路，一体机在
//!   宿主上就是靠 docker 端口映射发布成 `127.0.0.1:2322`，对这套集成
//!   测试来说这恰恰是"需要指向 127.0.0.1 假一体机的测试"该用的地址，
//!   `config.rs` 早给这类测试留了后门——`ValidatedAddresses::for_test`。
//! - 但 `for_test` 是 `#[cfg(test)] pub(crate)`：只在 rmc-core 自己的
//!   单元测试里可见，`tests/ssh_tunnel.rs` 是外部集成测试 crate，编译
//!   时看不到 `#[cfg(test)]` 内容，也看不到 `pub(crate)` 符号。把
//!   `TunnelParams`/`SshTunnelFactory` 改成收 `ValidatedAddresses`，
//!   会让 Task 7 自己要求的这份集成测试直接编译不过——除非把 `for_test`
//!   放宽成 `pub`，而放宽可见性等于撤销 Task 3 审查刚刚关上的那道口子
//!   （一个校验、生产代码里唯一能跳过它的入口，如果外部 crate 也能调，
//!   跳过就不再是"仅供测试"）。
//!
//! 所以校验的调用点仍然按 config.rs 原有的说法留在 Task 10：Supervisor
//! 处理 `Command::Start` 时必须先 `ValidatedAddresses::validate(gateway,
//! appliance)`，校验通过后再取 `.gateway()`/`.appliance()` 拼出
//! `SshTunnelFactory`/`TunnelParams`；这里拿到的应当已经是校验过的值，
//! 这道契约没有编译期强制力，只能算文档承诺，读到这段注释的人（包括
//! Task 10 的作者）应当把它当成前置条件对待。

use crate::addr::HostPort;
use crate::error::Result;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

/// 建立一条隧道所需的全部输入。口令用 Zeroizing 承载，Debug 时被遮蔽。
///
/// 调用方（Task 10）必须保证 `appliance` 已经通过
/// `config::ValidatedAddresses::validate` 校验过，且校验时用的 gateway
/// 与这条隧道实际要连的 Gateway 是同一个——本类型自己不重复这道校验，
/// 理由见模块顶部的说明。
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
    Authenticated {
        host_key_fp: String,
        first_seen: bool,
    },
    ForwardRegistered {
        port: u16,
    },
    RemoteSessionOpened {
        id: u64,
    },
    RemoteSessionBytes {
        id: u64,
        to_appliance: u64,
        from_appliance: u64,
    },
    RemoteSessionClosed {
        id: u64,
    },
    ApplianceDialFailed {
        id: u64,
        reason: String,
    },
    Disconnected {
        reason: String,
    },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_params_debug_never_prints_the_password() {
        // 见 tests/ssh_tunnel.rs 里 password_never_appears_in_debug_output
        // 的对等单元测试版本：这条不需要 docker 环境，任何 `cargo test`
        // 都会跑到，钉住这条全局约束不依赖 #[ignore] 之外还能被验证。
        let p = TunnelParams {
            username: "tunnel-zhang".into(),
            password: Zeroizing::new("super-secret-pw".to_string()),
            reverse_port: 22001,
            appliance: HostPort::new("192.168.1.1", 61001).unwrap(),
        };
        let printed = format!("{p:?}");
        assert!(!printed.contains("super-secret-pw"), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
    }
}
