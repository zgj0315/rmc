//! HTTP CONNECT。407 的多轮协商在同一条 TCP 连接上完成，因为
//! Negotiate 与 NTLM 都是连接绑定的认证——换一条新连接重新握手，
//! 服务端会认成另一个客户端，协商永远推进不到第二轮。

use crate::addr::HostPort;
use crate::error::{Error, Result};
use crate::platform::{Io, ProxyAuthenticator};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 协商轮数上限，防止代理与协商器互相顶牛导致死循环——例如协商器的
/// 实现有 bug，对每一轮 challenge 都返回同一个注定会被拒绝的 token。
const MAX_ROUNDS: usize = 5;

/// 代理响应头结束前允许读取的最大字节数，防止恶意或损坏的代理用一个
/// 永远不出现 `\r\n\r\n` 的响应把这里拖成无限增长的缓冲区。
const MAX_HEADER_BYTES: usize = 16 * 1024;

struct Response {
    status: u16,
    auth_scheme: Option<String>,
    auth_challenge: Option<String>,
}

/// RFC 7235 的 token68：只由 `ALPHA / DIGIT / '-' '.' '_' '~' '+' '/'`
/// 组成，允许在末尾补 0 个或多个 `=` 作为 base64 padding。这是
/// Negotiate/NTLM 承载 challenge 的形状。
///
/// R8：这条校验原来的版本（brief 原文）判别式是"字符串里含不含
/// `=`"——想用它把 `realm="corp"` 这类逗号分隔的 auth-param 列表过滤
/// 掉，但 base64 编码的 token 补 `=` 收尾是家常便饭（NTLM Type-2
/// 消息几乎总是这样），那个判别式会把真正的 challenge 也一并丢弃，
/// 协商器永远拿不到 challenge，只能从第一轮从头重来，直到撞上
/// `MAX_ROUNDS` 报协商失败——这正好是本任务存在的理由要解决的场景，
/// 被自己的实现挡死。真正该判别的不是"有没有 `=`"，而是字符集与
/// `=` 出现的位置：token68 除了结尾的 padding 之外不出现 `=`，也不
/// 出现空白、逗号、引号这些 auth-param 列表才有的分隔符。
fn looks_like_token68(s: &str) -> bool {
    let core = s.trim_end_matches('=');
    !core.is_empty()
        && core.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
}

/// 逐字节读到 `\r\n\r\n` 为止，不多读一个字节。
///
/// 之所以不用 `BufReader` 包一层按行读：`BufReader` 会把内部缓冲区
/// 填得比"响应头"更满，一旦代理把响应头之后的隧道字节（真正到 target
/// 的数据）跟头部结尾挨得很近发出去，`BufReader` 可能连带把它们读
/// 进内部缓冲区——而这个函数返回之后，调用方要在同一个 `stream` 上
/// 继续读隧道数据，`BufReader` 一销毁，那些已经从 socket 里取走、还
/// 没被调用方看到的字节就丢了。逐字节读传 1 字节的缓冲区，
/// `AsyncRead::read` 每次最多只消费 1 个字节，不会多拿，隧道数据原样
/// 留在内核 socket 缓冲区里，交还给调用方直接从 `stream` 读。
async fn read_response<S: Io>(stream: &mut S) -> Result<Response> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| Error::Tcp(format!("读取代理响应失败：{e}")))?;
        if n == 0 {
            return Err(Error::Tcp("代理在响应头结束前关闭了连接".into()));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(Error::Tcp(format!(
                "代理响应头超过 {MAX_HEADER_BYTES} 字节"
            )));
        }
    }

    let text = String::from_utf8_lossy(&buf).to_string();
    let mut lines = text.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| Error::Tcp("代理响应为空".into()))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Tcp(format!("无法解析代理状态行：{status_line}")))?;

    let mut auth_scheme = None;
    let mut auth_challenge = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("proxy-authenticate") && auth_scheme.is_none() {
            let value = value.trim();
            let (scheme, rest) = match value.split_once(' ') {
                Some((s, r)) => (s, Some(r.trim().to_string())),
                None => (value, None),
            };
            auth_scheme = Some(scheme.to_string());
            auth_challenge = rest.filter(|r| looks_like_token68(r));
        }
    }

    Ok(Response {
        status,
        auth_scheme,
        auth_challenge,
    })
}

async fn send_request<S: Io>(
    stream: &mut S,
    target: &HostPort,
    authorization: Option<&str>,
) -> Result<()> {
    let mut req =
        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: Keep-Alive\r\n");
    if let Some(value) = authorization {
        req.push_str("Proxy-Authorization: ");
        req.push_str(value);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| Error::Tcp(format!("发送 CONNECT 失败：{e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| Error::Tcp(format!("发送 CONNECT 失败：{e}")))
}

/// 在已连上代理的流上完成 CONNECT。返回 `Ok` 之后，流内即为到 target
/// 的字节通道，调用方直接在同一个 `stream` 上继续做 TLS 握手/SSH
/// 握手，不需要重新连接。
pub async fn http_connect<S: Io>(
    stream: &mut S,
    target: &HostPort,
    auth: &dyn ProxyAuthenticator,
) -> Result<()> {
    let mut authorization: Option<String> = None;

    for _ in 0..MAX_ROUNDS {
        send_request(stream, target, authorization.as_deref()).await?;
        let resp = read_response(stream).await?;

        match resp.status {
            200 => return Ok(()),
            407 => {
                let scheme = resp.auth_scheme.clone().unwrap_or_else(|| "Basic".into());
                match auth
                    .next_token(&scheme, resp.auth_challenge.as_deref())
                    .await
                {
                    Some(token) => authorization = Some(format!("{scheme} {token}")),
                    None => {
                        return Err(Error::ProxyAuthFailed(format!(
                            "代理要求 {scheme}，本机无法协商"
                        )))
                    }
                }
            }
            other => {
                return Err(Error::Tcp(format!("代理拒绝 CONNECT，状态码 {other}")));
            }
        }
    }

    Err(Error::ProxyAuthFailed(format!(
        "代理认证协商超过 {MAX_ROUNDS} 轮仍未通过"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token68_accepts_unpadded_and_padded_base64() {
        assert!(looks_like_token68("TlRMTVNTUAAC"));
        assert!(looks_like_token68(
            "TlRMTVNTUAACAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        ));
        assert!(looks_like_token68("YQ=="));
    }

    #[test]
    fn token68_rejects_auth_param_lists() {
        assert!(!looks_like_token68("realm=\"corp\""));
        assert!(!looks_like_token68("realm=\"corp\", qop=\"auth\""));
    }

    #[test]
    fn token68_rejects_empty_and_padding_only() {
        assert!(!looks_like_token68(""));
        assert!(!looks_like_token68("==="));
    }
}
