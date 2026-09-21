//! 隧道的抽象接口。Supervisor 只依赖这里，因此状态机可以用假隧道测试。
//!
//! R20：`appliance` 字段仍是裸 `HostPort`，不是 Task 3 的
//! `config::ValidatedAddresses`——config.rs 上 `ValidatedAddresses` 的文档
//! 注释已经把话挑明："Task 10 处理 Command::Start 时先调 validate，再用
//! 返回值里的地址去拨号"，也就是说这道校验的天然调用点在 Task 10，不在
//! 这里。这里权衡过，仍然决定不把 `ValidatedAddresses` 塞进
//! `TunnelParams`：
//!
//! **Task 13 注**：下面这段权衡里作为论据出现的 `tests/ssh_tunnel.rs` 与
//! `gateway/test-env`（docker 夹具）**都已经不存在了**——集成测试换成了
//! `crates/rmc-gateway/tests/e2e.rs` 的进程内端到端。这段记录原样保留是
//! 因为它说明的是**结论怎么来的**，不是"今天还能去哪儿核对"；要重新评估
//! R20 这个决定，得按 e2e.rs 那套新证据重走一遍，不能直接照搬下面的论据。
//!
//! - `ValidatedAddresses::validate` 拒绝一体机地址是本机回环——但
//!   `tests/ssh_tunnel.rs` 对着 gateway/test-env 跑真实链路（**已删**），一体机在
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
//! `TunnelParams`（R96 之后 `SshTunnelFactory` 不再收地址，两个地址
//! 一起走 `TunnelParams`，见下面 `TunnelParams` 上的说明）；这里拿到的
//! 应当已经是校验过的值，这道契约没有编译期强制力，只能算文档承诺，
//! 读到这段注释的人（包括 Task 10 的作者）应当把它当成前置条件对待。
//!
//! 注意 R96 只解决了这道契约的**后半句**——「校验时用的 gateway 与这条
//! 隧道实际要连的 Gateway 必须是同一个」现在由类型保证（只有一个
//! `params.gateway`，预检、拨号、host key 比对读的都是它）。前半句
//! 「必须先校验过」仍然是文档承诺。
//!
//! ## R48（第二轮评审）：加了进程内 russh 服务端（`ssh::test_support`，
//! 见 R40）之后，这条决定要不要翻过来？
//!
//! 评审的论点是对的，而且指向了一个我最初没意识到的机会：
//! `ssh::test_support` 这份新证据全部活在 `src/` 里，是
//! `#[cfg(test)] mod`，天然能看见 `ValidatedAddresses::for_test`（跟
//! `config.rs` 自己的单测是同一个可见性）——如果只看这份新证据要不要
//! 校验过的地址，答案是"不需要动 R20"，因为它压根不经过
//! `TunnelParams`/`SshTunnelFactory`（`establish_over` 是
//! `pub(crate)`，测试直接拿裸 `HostPort` 调它）。真正的问题是：这份新
//! 证据的存在，有没有让"把 `ValidatedAddresses` 塞进
//! `TunnelParams`/`SshTunnelFactory`"这件事本身变得免费？
//!
//! 答案仍然是没有，而且现在可以摆出比第一轮更具体的代价：
//! `tests/ssh_tunnel.rs`——docker 版集成测试，不是 `ssh::test_support`
//! ——依然是外部 crate，依然用 `127.0.0.1:2322` 当一体机地址（docker
//! 端口映射决定的，不是能改的测试选择），`ValidatedAddresses::validate`
//! 依然会拒绝这个地址，`for_test` 依然是它唯一的旁路且依然
//! `pub(crate)`。真把 `TunnelParams.appliance` 换成
//! `ValidatedAddresses`，后果不是"那十条 `#[ignore]` 用例又多验证不了
//! 一点"（R40 已经说明它们本来就没人自动跑），而是`tests/ssh_tunnel.rs`
//! 整个文件**编译不过**——`cargo test -p rmc-core` 会在编译阶段直接
//! 失败，连那 1 条没有 `#[ignore]` 的
//! `password_never_appears_in_debug_output` 也带着一起挂掉。这比"少一份
//! 冗余覆盖"重得多，是把一个当前编译通过、部分可用的文件变成完全不能用
//! 的文件。评审明确拒绝的两条旁路（`test-harness` feature、让一体机
//! 主机名解析到回环）都是想绕开这堵墙，而不是真的把墙拆掉——照办只会
//! 制造新的口子，不会让代价消失。
//!
//! 所以：**权衡过，仍然不采用**。`ssh::test_support` 的价值是独立的——
//! 它不需要 `ValidatedAddresses` 就已经把 host key 校验、认证、端口
//! 注册这些安全关键路径钉进了每一次 `cargo test`（R40），这份收益已经
//! 拿到手，不依赖这里的决定。如果将来 `tests/ssh_tunnel.rs` 被换掉或者
//! 不再需要真的对着 docker 里那个 127.0.0.1 一体机跑，这堵墙就会自己
//! 消失，到时候应该重新算一遍这笔账，而不是现在就为了凑成"进程内证据
//! 有了，所以类型约束也该跟上"这个直觉去拆一个还在用的外部测试文件。

use crate::addr::HostPort;
use crate::code::ServerFingerprint;
use crate::error::Result;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

/// 建立一条隧道所需的全部输入。口令用 Zeroizing 承载，Debug 时被遮蔽。
///
/// 调用方（Task 10）必须保证 `gateway`/`appliance` 这一对地址已经通过
/// `config::ValidatedAddresses::validate` 校验过——本类型自己不重复这道
/// 校验，理由见模块顶部的说明。
///
/// ## R96（最终复审发现）：`gateway` 为什么在这里，而不在工厂里
///
/// 这个字段是最终复审加的。原来 `SshTunnelFactory` 自己攥着一个
/// 构造时就固定的 `gateway`，`establish()` 拨的是**那一个**，host key
/// 也是对着**那一个**比对的；而 Supervisor 这一侧，`Command::Start`
/// 携带的 Gateway 地址只流向三处——`ValidatedAddresses` 的关系校验、
/// `Preflight::run`、审计日志那一行——一处都不参与拨号。
///
/// 后果不是抽象的：方案 §3.8/§3.10 允许现场工程师把界面上的运维服务器
/// 地址改成客户现场那一台再点「开启」。改完之后，预检对着**新**地址做
/// DNS/TCP/TLS（诊断页显示的是新地址的结果）、审计日志写「Gateway
/// 新地址」、地址关系校验也用新地址——而隧道建到的仍然是构造工厂时用
/// 的那一台，host key 比对用的也是那一台的。诊断页与追责日志会稳定地
/// 描述一台不是实际连上的机器；而 §3.8「Gateway 地址与端口可现场修改」
/// 在当时那套 API 下根本做不到（`Deps::factory` 在 `Supervisor::spawn`
/// 时一次性传入，此后无法更换）。
///
/// 测试当时完全失明：把 Supervisor 里取 gateway 那一行换成一个写死的
/// 错误地址，237 条测试 0 失败——假工厂 `Scripted` 看不到 gateway
/// （`TunnelParams` 里没有这个字段），`AlwaysPassPreflight` 忽略参数。
///
/// 修法是把 Gateway 地址从「工厂的构造参数」搬成「每次 establish 的
/// 入参」，并且**把工厂里那个字段整个删掉**——留着它只会留下两个可以
/// 各自漂移的真相来源。现在这三件事（预检探哪台、拨号拨哪台、host key
/// 对哪台）读的是同一个 `params.gateway`，在类型上就没有分叉的余地，
/// 不再是一条只能靠注释维持的调用方义务。
pub struct TunnelParams {
    pub username: String,
    pub password: Zeroizing<String>,
    /// 这条隧道实际要拨的 Gateway，也是 host key 要比对的那一台。
    pub gateway: HostPort,
    pub appliance: HostPort,
    /// 连接码里带出来的运维服务器指纹。TLS（Task 9）与 SSH（Task 10）
    /// 两层都核对同一个值，没有第二份拷贝。
    ///
    /// Task 10：`reverse_port` 字段删掉了——反向端口不再由客户端指定，
    /// 而是 `ssh::establish_over` 申请端口 0，由运维服务器按账号回填
    /// （见 `tunnel::TunnelMsg::ForwardRegistered`）。
    pub fingerprint: ServerFingerprint,
}

impl std::fmt::Debug for TunnelParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelParams")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("gateway", &self.gateway)
            .field("appliance", &self.appliance)
            // 指纹不是秘密——它跟账号名、地址一样是连接码里公开的一段。
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

/// 隧道运行期间向 Supervisor 上报的事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelMsg {
    /// SSH host key 与连接码里的指纹核对一致（`ssh::handler::
    /// ClientHandler::check_server_key`）。没有「首次记录」这一说——
    /// 指纹要么跟连接码一致，要么握手在这条消息能发出去之前就已经
    /// 失败了。
    Authenticated {
        fingerprint: ServerFingerprint,
    },
    /// 反向端口已经注册；`port` 是运维服务器按账号回填的值，不是客户端
    /// 自己申请的（Task 10：客户端始终申请端口 0）。
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

/// 关闭一条"当前不存在"的远程会话——可能是这个 id 从未被分配过，也可能是
/// 会话已经自然结束、实现已经把它从账本里摘掉。这两种情况在调用方看来都
/// 不该被误判成"隧道出问题了"，所以不走 `crate::error::Error` 那套由
/// `ErrorClass` 驱动重连行为的分类体系——这是一次性的单会话操作，不代表
/// 隧道本身的健康状况，不需要、也不应该触发任何重连逻辑。
///
/// 用来区分"成功关闭了一条真实存在的会话"（`Ok(())`）与"这条会话现在
/// 压根不在"（`Err(UnknownSessionId)`）——见 `ssh::pump::SharedChannels`
/// 上关于账本插入/移除时机的说明。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("远程会话 {0} 不存在（从未打开，或已经自然结束）")]
pub struct UnknownSessionId(pub u64);

#[async_trait::async_trait]
pub trait TunnelHandle: Send + Sync {
    /// 断开某一条远程会话，隧道本身保持。`id` 不对应任何一条当前打开的
    /// 会话时返回 `Err(UnknownSessionId)`——这个 id 从未存在过、或者对应
    /// 的会话已经自然结束，两种情况都不该被上层误当成"关闭失败"处理。
    async fn close_remote_session(&self, id: u64) -> std::result::Result<(), UnknownSessionId>;
    async fn shutdown(self: Box<Self>);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_params_debug_never_prints_the_password() {
        // 这一条原本是 `tests/ssh_tunnel.rs::password_never_appears_in_
        // debug_output`（docker 版集成测试，`#[ignore]`）的对等单元测试
        // 版本。那份集成测试已随旧 docker 夹具删除（Task 10/13），所以
        // **现在这条就是唯一钉住 `TunnelParams` 这一半的地方**，不再是
        // 谁的影子。`Command` 那一半由 `state.rs::command_start_debug_
        // never_prints_the_password` 钉。
        let p = TunnelParams {
            username: "tunnel-zhang".into(),
            password: Zeroizing::new("super-secret-pw".to_string()),
            gateway: HostPort::new("gateway.company.com", 443).unwrap(),
            appliance: HostPort::new("192.168.1.1", 61001).unwrap(),
            fingerprint: ServerFingerprint::of_ed25519_public(&[9u8; 32]),
        };
        let printed = format!("{p:?}");
        assert!(!printed.contains("super-secret-pw"), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
    }
}
