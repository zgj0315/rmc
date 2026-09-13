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

// Task 7 会给 SSH 层引入 russh 依赖；`client::Handler` trait 要求
// `Self::Error: From<russh::Error>`，届时在此补 `impl From<russh::Error> for Error`
// （连同 `SshTransport` 之类的落点），这里先留一句话，免得到时候重新踩这个坑。
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

    #[error("本地文件操作失败：{0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    pub fn class(&self) -> ErrorClass {
        match self {
            Error::HostKeyMismatch { .. }
            | Error::TlsInvalidCert(_)
            | Error::ProxyAuthFailed(_)
            | Error::Config(_) => ErrorClass::Fatal,
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
        // 本地文件操作失败（如写状态文件）按网络类处理，走退避重连。
        let io_err = std::io::Error::other("disk full");
        assert_eq!(Error::from(io_err).class(), ErrorClass::Network);
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
    fn keepalive_timeout_display_has_no_number() {
        // R7：见 KeepaliveTimeout 变体上的注释，30 秒是未经实测的假设，不能出现在文案里。
        let text = Error::KeepaliveTimeout.to_string();
        assert!(
            !text.chars().any(|c| c.is_ascii_digit()),
            "Display 文案不应包含具体秒数：{text}"
        );
    }
}
