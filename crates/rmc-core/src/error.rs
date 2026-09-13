//! 错误类型与分类。分类直接决定 Supervisor 的重连行为，见方案 3.6。

/// 错误的处置类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// 立即 Failed，不重试，界面醒目提示。
    Fatal,
    /// 停止并回到 Idle，提示重新输入，不自动重试。
    Auth,
    /// 固定 5 秒重试，最长 120 秒。
    PortBusy,
    /// 按退避序列重连，不限次数。
    Network,
    /// 隧道保持，转 degraded，每 30 秒探测。
    ApplianceUnreachable,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Gateway host key 与已记录的不一致，已拒绝连接（记录 {expected}，本次 {actual}）")]
    HostKeyMismatch { expected: String, actual: String },

    #[error("Gateway TLS 证书链无效：{0}")]
    TlsInvalidCert(String),

    #[error("代理要求认证，协商失败：{0}")]
    ProxyAuthFailed(String),

    #[error("账号或口令不正确")]
    AuthRejected,

    #[error("反向端口 {0} 被占用，上一条隧道的监听尚未回收")]
    ForwardPortBusy(u16),

    #[error("域名解析失败：{0}")]
    Dns(String),

    #[error("TCP 连接失败：{0}")]
    Tcp(String),

    #[error("TLS 握手中断：{0}")]
    TlsHandshake(String),

    // R7：不写具体秒数。「10 秒一次、连续 3 次无应答」乘出来的 30 秒只是
    // 假设——方案设计.md §3.4 明确要求这个判定耗时必须等 rmc-core 建出来后
    // 实测，不能从算式直接推定：Gateway 侧同样的乘法算法实测偏了约 2.7 倍
    // （真实值约 80 秒，不是算出来的 30 秒），客户端用 russh 而非 OpenSSH，
    // 偏差可能不同。真实数字由后续任务测出后回填到方案文档，这里的 Display
    // 文案先不出现数字，避免重犯同一个错误。
    #[error("Gateway 长时间未响应 keepalive，判定连接已断开")]
    KeepaliveTimeout,

    #[error("SSH 链路中断：{0}")]
    SshTransport(String),

    #[error("一体机不可达：{0}")]
    ApplianceUnreachable(String),

    #[error("配置错误：{0}")]
    Config(String),

    /// 传输层 socket 级 io::Error 的落点，归 Network——一次网络抖动不该
    /// 杀死会话，这是安全默认。
    ///
    /// R15：故意不挂 `#[from]`。一个类型对 `std::io::Error` 的 `From`
    /// 实现只能有一份；如果这里挂着 `#[from]`，`?` 就会把任何
    /// `std::io::Error`（包括本该走 LocalIo 的本地文件系统错误）都顺手
    /// 转成 Io，而 Io 与 LocalIo 需要的处置完全相反（见 LocalIo 上的
    /// 注释）。少了 `#[from]` 这个"顺手"的路，才逼着调用方在每个 io 落点
    /// 上想一遍"这是 socket 还是本地文件"——构造时用 `Error::Io(e)`。
    #[error("IO 错误：{0}")]
    Io(std::io::Error),

    /// R14：本地文件系统操作失败（如 known_hosts 读写——权限错误、磁盘
    /// 满）。与 Io 分开是因为二者需要的处置完全相反：
    /// - Io 归 Network 是安全默认（一次网络抖动不该杀死会话），但也因此
    ///   不能把 Io 整体改成 Fatal——那样会连带把偶发的 socket 错误也变成
    ///   永久性失败。
    /// - 而 known_hosts 权限错误、磁盘满这类本地文件系统错误，退避重连
    ///   解决不了；如果和 Io 共用 Network 分类，Supervisor（Task 10）会
    ///   把隧道拆了重建、拆了重建，永远重连，工程师永远看不到需要处理
    ///   的原因。所以单列 Fatal，立刻停下来醒目提示。
    ///
    /// R15：同样故意不挂 `#[from]`（哪怕它没被 Io 占用，也不该挂）——
    /// `?` 的自动转换不知道一个 io::Error 到底是 socket 错误还是本地文件
    /// 错误，挂上 `#[from]` 只会制造第二条能被 `?` 悄悄选中的隐式路径，
    /// 而具体走哪条完全取决于哪个变体先写上 `#[from]`，这本身就是运气。
    /// 两个变体都要求显式构造：本地文件系统错误用 `Error::LocalIo(e)`，
    /// socket 级错误用 `Error::Io(e)`。
    #[error("本地文件操作失败：{0}")]
    LocalIo(std::io::Error),
}

impl Error {
    pub fn class(&self) -> ErrorClass {
        match self {
            Error::HostKeyMismatch { .. }
            | Error::TlsInvalidCert(_)
            | Error::ProxyAuthFailed(_)
            | Error::Config(_)
            | Error::LocalIo(_) => ErrorClass::Fatal,
            Error::AuthRejected => ErrorClass::Auth,
            Error::ForwardPortBusy(_) => ErrorClass::PortBusy,
            Error::Dns(_)
            | Error::Tcp(_)
            | Error::TlsHandshake(_)
            | Error::KeepaliveTimeout
            | Error::SshTransport(_)
            | Error::Io(_) => ErrorClass::Network,
            Error::ApplianceUnreachable(_) => ErrorClass::ApplianceUnreachable,
        }
    }
}

/// `russh::client::Handler` 要求 `Self::Error: From<russh::Error>`——这是
/// trait 定义本身的约束，不是我们能绕开的可选项。
///
/// 这里只做兜底：`Keys`/`NoAuthMethod` 说明这条连接压根没能力完成认证
/// （密钥格式不对、没有可用的认证方法），落 Auth 类不落 Network——
/// 重试同一条网络路径不会让"这把密钥"或"这种认证方法"变得可用。其余
/// 一切 russh 内部错误（KEX 失败、连接被对端挂断、协议不一致……）落
/// `SshTransport`，也就是 Network 类。
///
/// 这条 `From` 只是满足 trait bound、兜住 russh 内部隐式产生的转换
/// （例如 `connect_stream` 在密钥交换失败时会自己调
/// `H::Error::from(crate::Error::Disconnect)`）——它不是本模块处理
/// russh 错误的唯一路径：`ssh::mod` 里 `tcpip_forward` 的失败需要把
/// `RequestDenied` 单独分去 `PortBusy`，这条更细的判断必须写在调用
/// 处自己的 `match` 里，不能指望这条笼统的 `From` replace 它——见 R9，
/// 一旦所有 russh 错误都经这一条笼统路径改判，`RequestDenied` 与
/// 会话中途断线的 `Disconnect`/`SendError` 就会被强行归成同一类，
/// 该退避重连的场景被误判成"端口占用，5 秒后重试"。
impl From<russh::Error> for Error {
    fn from(e: russh::Error) -> Self {
        match e {
            russh::Error::Keys(_) | russh::Error::NoAuthMethod => Error::AuthRejected,
            other => Error::SshTransport(other.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_mismatch_is_fatal() {
        let e = Error::HostKeyMismatch {
            expected: "SHA256:aaa".into(),
            actual: "SHA256:bbb".into(),
        };
        assert_eq!(e.class(), ErrorClass::Fatal);
    }

    #[test]
    fn tls_cert_error_is_fatal() {
        assert_eq!(
            Error::TlsInvalidCert("unknown issuer".into()).class(),
            ErrorClass::Fatal
        );
    }

    #[test]
    fn auth_rejected_is_auth_class() {
        assert_eq!(Error::AuthRejected.class(), ErrorClass::Auth);
    }

    #[test]
    fn proxy_auth_failure_is_fatal_not_network() {
        // 代理要求认证而协商失败时，重试同一条路径不会变好，必须让用户看到原因。
        assert_eq!(
            Error::ProxyAuthFailed("Negotiate".into()).class(),
            ErrorClass::Fatal
        );
    }

    #[test]
    fn port_busy_is_its_own_class() {
        assert_eq!(Error::ForwardPortBusy(22001).class(), ErrorClass::PortBusy);
    }

    #[test]
    fn dns_tcp_tls_keepalive_are_network() {
        for e in [
            Error::Dns("no such host".into()),
            Error::Tcp("connection refused".into()),
            Error::TlsHandshake("reset by peer".into()),
            Error::KeepaliveTimeout,
        ] {
            assert_eq!(e.class(), ErrorClass::Network, "{e}");
        }
    }

    #[test]
    fn ssh_transport_is_network() {
        // SSH 链路层中断也走退避重连，不单列分类。
        assert_eq!(
            Error::SshTransport("channel closed".into()).class(),
            ErrorClass::Network
        );
    }

    #[test]
    fn config_error_is_fatal() {
        // 配置错误重试无意义，必须让用户看到并修正。
        assert_eq!(
            Error::Config("port must be in 22000-22999".into()).class(),
            ErrorClass::Fatal
        );
    }

    #[test]
    fn io_error_is_network() {
        // socket 层 io::Error 按网络类处理走退避重连——这是安全默认，不能
        // 因为要处理本地文件系统错误就把它整体改成 Fatal（那样一次 socket
        // 抖动就会把会话判死）。R15：不再挂 `#[from]`，显式构造。
        let io_err = std::io::Error::other("connection reset");
        assert_eq!(Error::Io(io_err).class(), ErrorClass::Network);
    }

    #[test]
    fn local_io_error_is_fatal_not_network() {
        // R14：known_hosts 权限错误、磁盘满这类本地文件系统错误，重连解决
        // 不了。如果和 Io 共用 Network 分类，Supervisor 会把隧道拆了重建、
        // 拆了重建，永远重连，工程师永远看不到需要处理的原因。单列 LocalIo
        // 为 Fatal，让它立刻停下来醒目提示。
        let io_err = std::io::Error::other("permission denied");
        assert_eq!(Error::LocalIo(io_err).class(), ErrorClass::Fatal);
    }

    #[test]
    fn appliance_unreachable_has_own_class() {
        assert_eq!(
            Error::ApplianceUnreachable("connection refused".into()).class(),
            ErrorClass::ApplianceUnreachable
        );
    }

    #[test]
    fn error_display_never_contains_a_password() {
        // 所有变体的 Display 都由固定文案加上不含口令的细节拼成。
        let e = Error::AuthRejected;
        assert!(!e.to_string().contains("password"));
        assert_eq!(e.to_string(), "账号或口令不正确");
    }

    #[test]
    fn russh_keys_and_no_auth_method_errors_become_auth_class() {
        // Handler trait 要求的 From<russh::Error>：这两个变体说明这条连接
        // 压根没有能力完成认证，落 Auth 而不是 Network——退避重连解决不了
        // "密钥格式不对"或"没有可用认证方法"。
        assert_eq!(
            Error::from(russh::Error::NoAuthMethod).class(),
            ErrorClass::Auth
        );
    }

    #[test]
    fn other_russh_errors_become_network_class() {
        // 其余 russh 内部错误统一落 SshTransport/Network——一次 KEX 失败或
        // 中途断线应该走退避重连，不该被判死。
        let e = Error::from(russh::Error::Disconnect);
        assert_eq!(e.class(), ErrorClass::Network);
        assert!(matches!(e, Error::SshTransport(_)));
    }

    #[test]
    fn keepalive_timeout_display_has_no_number() {
        // R7：见 KeepaliveTimeout 变体上的注释，30 秒是未经实测的假设，不能出现在文案里。
        let text = Error::KeepaliveTimeout.to_string();
        assert!(
            !text.chars().any(|c| c.is_ascii_digit()),
            "Display 文案不应包含具体秒数：{text}"
        );
    }
}
