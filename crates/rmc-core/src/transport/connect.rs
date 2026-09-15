//! HTTP CONNECT。407 的多轮协商在同一条 TCP 连接上完成，因为
//! Negotiate 与 NTLM 都是连接绑定的认证——换一条新连接重新握手，
//! 服务端会认成另一个客户端，协商永远推进不到第二轮。

use crate::addr::HostPort;
use crate::error::{Error, Result};
use crate::platform::{Io, ProxyAuthenticator};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

/// 协商轮数上限，防止代理与协商器互相顶牛导致死循环——例如协商器的
/// 实现有 bug，对每一轮 challenge 都返回同一个注定会被拒绝的 token。
const MAX_ROUNDS: usize = 5;

/// 代理响应头结束前允许读取的最大字节数，防止恶意或损坏的代理用一个
/// 永远不出现 `\r\n\r\n` 的响应把这里拖成无限增长的缓冲区。
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// scheme 名进错误文案之前的长度上限。
///
/// 这一段是代理响应头里**未经任何长度约束**的字节：`MAX_HEADER_BYTES`
/// 允许整条响应头到 16KB，而 auth-scheme 只是一个 HTTP token，现实里
/// 最长的也就 `Negotiate` 这种量级。仓库对"不受信任的原文进用户可见
/// 错误"的规范见 `knownhosts::redact_for_error`（那条由
/// `damaged_line_error_message_is_bounded_in_length` 守着，要求错误
/// 文案 < 1000 字节），这里照同一条办。
const MAX_SCHEME_CHARS: usize = 64;

/// 代理在 `Proxy-Authenticate` 里通告的一种认证方式。
///
/// `token68` 是这一种方式随附的 challenge（Negotiate/NTLM 用它承载
/// SPNEGO/NTLMSSP 消息），没有就是 `None`——`Basic realm="corp"` 这类
/// 带 auth-param 的通告在这里就是 `token68: None`。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Challenge {
    scheme: String,
    token68: Option<String>,
}

struct Response {
    status: u16,
    /// 代理通告的**全部**认证方式，按响应头里出现的顺序。
    challenges: Vec<Challenge>,
}

/// RFC 7230 §3.2.6 的 token（auth-scheme 就是一个 token）。
fn is_http_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// scheme 名截断到 [`MAX_SCHEME_CHARS`]。不做转义：能走到这里的 scheme
/// 已经过 [`is_http_token`]，按定义不含控制字符与非 ASCII。
fn bounded_scheme(raw: &str) -> String {
    let mut chars = raw.chars();
    let head: String = chars.by_ref().take(MAX_SCHEME_CHARS).collect();
    if chars.next().is_some() {
        format!("{head}…（已截断）")
    } else {
        head
    }
}

/// 解析一条 `Proxy-Authenticate` 的值，取出其中通告的全部认证方式。
///
/// # 支持哪种形状，不支持哪种（W35）
///
/// 企业代理同时通告 `Basic` / `NTLM` / `Negotiate` 是常态，顺序不由
/// 我们控制。RFC 9110 §11.6.1 允许两种写法，**两种都支持**：
///
/// 1. 分成多行，每行一条 `Proxy-Authenticate:`（真实代理最常见的写法）；
/// 2. 挤在一行里用逗号分隔：`Proxy-Authenticate: Negotiate, NTLM, Basic`。
///
/// 第二种的麻烦在于逗号本身有二义：它既分隔 challenge，也分隔同一个
/// challenge 内部的 auth-param（`Digest realm="x", qop="auth"`）。这里
/// 的判别式是**逗号切出来的这一段，第一个词是不是一个合法的 HTTP
/// token**：
///
/// - `qop="auth"` 含 `=` 与 `"`，不是 token → 判成上一条 challenge 的
///   auth-param 续段，跳过；
/// - `Negotiate` / `NTLM` / `Basic` 是 token → 判成一条新的 challenge。
///
/// token68 本身**不可能**含逗号（RFC 7235 的 token68 字符集里没有），
/// 所以不存在"为了处理逗号把带 challenge 的行切坏"这回事——
/// `Negotiate TlRMTVNTUAAC=, NTLM` 切完两段都是完整的。
///
/// **不支持**的形状：auth-param 的**引号串里含逗号**，例如
/// `Basic realm="corp, inc"`。那会被切成 `Basic realm="corp` 与
/// `inc"` 两段；第二段的第一个词 `inc"` 含引号、不是 token，于是被当
/// 成续段跳过——**scheme 的识别仍然是对的**，代价只是 realm 的原文残
/// 缺（本模块从不读 realm）。真正会误判的是引号串里逗号之后恰好跟着
/// 一个 token 再跟空白，例如 `Basic realm="corp, Negotiate 没有开"`
/// ——那会多认出一条根本不存在的 `Negotiate`。见
/// `a_comma_inside_a_quoted_auth_param_is_a_documented_limitation`。
/// 不为它加引号串状态机：本模块只认 Negotiate/NTLM/Basic 三种通告，
/// 而前两种承载的都是 token68、从不带 auth-param。
fn parse_proxy_authenticate(value: &str) -> Vec<Challenge> {
    let mut out = Vec::new();
    for segment in value.split(',') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let (head, rest) = match segment.split_once(char::is_whitespace) {
            Some((h, r)) => (h, r.trim()),
            None => (segment, ""),
        };
        if !is_http_token(head) {
            continue;
        }
        out.push(Challenge {
            scheme: bounded_scheme(head),
            token68: Some(rest)
                .filter(|r| looks_like_token68(r))
                .map(str::to_string),
        });
    }
    out
}

/// 在代理通告的全部认证方式里挑一个来协商。
///
/// **`Negotiate` > `NTLM` > 通告里的第一条。** 前两条是 SSPI 能用当前
/// 登录用户身份自动完成的，`Negotiate` 还能在拿不到 Kerberos 票时自己
/// 回落到 NTLM，所以优先。
///
/// 为什么不能只看第一条（W35）：代理把 `Basic` 排在前面是常态，而顺序
/// 不由我们控制。只取第一条会在**最常见的企业配置**下把整个 SSPI 能力
/// 旁路掉——表现是 `ProxyAuthFailed("代理要求 Basic")`，而这台机器明明
/// 能做 Negotiate。
///
/// 兜底取第一条而不是返回 `None`：一台只支持 Basic 的代理，诊断页要能
/// 如实说出"代理要求 Basic 认证"，那是真的从响应头里读到的。
fn select_challenge(challenges: &[Challenge]) -> Option<&Challenge> {
    for want in ["Negotiate", "NTLM"] {
        if let Some(c) = challenges
            .iter()
            .find(|c| c.scheme.eq_ignore_ascii_case(want))
        {
            return Some(c);
        }
    }
    challenges.first()
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

    // 收集**全部** `Proxy-Authenticate`，而不是只取第一条（W35）：
    // 企业代理同时通告 Basic / NTLM / Negotiate 是常态，而且很可能把
    // Basic 排在最前面。挑哪一条由 `select_challenge` 决定。
    let mut challenges = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("proxy-authenticate") {
            challenges.extend(parse_proxy_authenticate(value));
        }
    }

    Ok(Response { status, challenges })
}

/// 把 scheme 与 token 拼成 `Proxy-Authorization` 的值。
///
/// 返回 `Zeroizing<String>`：token 是域凭据的派生物，理由见
/// [`ProxyAuthenticator::next_token`] 的文档。**只改 trait 的签名堵不住
/// 这一段**——token 一旦被抄进一个普通 `String`，那个 `String` drop 时
/// 不抹零。
///
/// 容量一次算够，见 [`connect_request`] 的说明。
fn authorization_header(scheme: &str, token: &Zeroizing<String>) -> Zeroizing<String> {
    let mut v = Zeroizing::new(String::with_capacity(scheme.len() + 1 + token.len()));
    v.push_str(scheme);
    v.push(' ');
    v.push_str(token.as_str());
    v
}

/// 拼出一整条 CONNECT 请求。
///
/// 同样返回 `Zeroizing<String>`：`Proxy-Authorization` 的值会被原样抄
/// 进这个缓冲区，它是这条 token 在本进程里的第二份副本。
///
/// # 为什么容量要一次算够，而不是 `format!` + `push_str`
///
/// `Zeroizing<String>` 只保证**这一个 `String` 在 drop 时**被抹零。而
/// `String` 扩容走的是"另分配一块、把旧内容拷过去、把旧块原样还给
/// 分配器"——**旧块不会被抹零**。所以只要 token 已经进了缓冲区、之后
/// 还发生过一次扩容，堆上就留下一份没抹掉的副本，`Zeroizing` 对它无能
/// 为力。这正是"只改签名就宣布堵住了"的那种假堵。
///
/// 一次 `String::with_capacity` 到位、之后只 push 不超过这个长度，就
/// 不会再扩容。`the_request_buffer_never_grows_after_the_token_is_in`
/// 用 `capacity() == len()` 反查这件事。
fn connect_request(target: &HostPort, authorization: Option<&str>) -> Zeroizing<String> {
    let target = target.to_string();
    // "CONNECT " + target + " HTTP/1.1\r\n" + "Host: " + target + "\r\n"
    //   + "Proxy-Connection: Keep-Alive\r\n" + [auth 行] + "\r\n"
    let fixed = "CONNECT  HTTP/1.1\r\nHost: \r\nProxy-Connection: Keep-Alive\r\n\r\n".len();
    let auth_len = authorization.map_or(0, |v| "Proxy-Authorization: \r\n".len() + v.len());
    let mut req = Zeroizing::new(String::with_capacity(fixed + 2 * target.len() + auth_len));
    req.push_str("CONNECT ");
    req.push_str(&target);
    req.push_str(" HTTP/1.1\r\nHost: ");
    req.push_str(&target);
    req.push_str("\r\nProxy-Connection: Keep-Alive\r\n");
    if let Some(value) = authorization {
        req.push_str("Proxy-Authorization: ");
        req.push_str(value);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    req
}

async fn send_request<S: Io>(
    stream: &mut S,
    target: &HostPort,
    authorization: Option<&str>,
) -> Result<()> {
    let req = connect_request(target, authorization);
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
    let mut authorization: Option<Zeroizing<String>> = None;

    for _ in 0..MAX_ROUNDS {
        send_request(stream, target, authorization.as_ref().map(|a| a.as_str())).await?;
        let resp = read_response(stream).await?;

        match resp.status {
            200 => return Ok(()),
            407 => {
                // 代理说要认证，却一个 scheme 都没给。**不能编一个
                // "Basic" 出来**（W35）：那会让诊断页说出"代理要求
                // Basic 认证"这句代理从没说过的话，把"响应头坏了"
                // 误导成"换一种认证方式就行"。
                let Some(challenge) = select_challenge(&resp.challenges) else {
                    return Err(Error::ProxyAuthFailed(
                        "代理要求认证，但响应里没有给出任何 Proxy-Authenticate 方式".into(),
                    ));
                };
                match auth
                    .next_token(&challenge.scheme, challenge.token68.as_deref())
                    .await
                {
                    Some(token) => {
                        authorization = Some(authorization_header(&challenge.scheme, &token))
                    }
                    None => {
                        return Err(Error::ProxyAuthFailed(format!(
                            "代理要求 {}，本机无法协商",
                            challenge.scheme
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

    fn target() -> HostPort {
        "gateway.company.com:443".parse().unwrap()
    }

    fn ch(scheme: &str, token68: Option<&str>) -> Challenge {
        Challenge {
            scheme: scheme.into(),
            token68: token68.map(str::to_string),
        }
    }

    // ================= W35：一行里的多个 challenge =================

    #[test]
    fn one_header_line_can_carry_several_comma_separated_schemes() {
        // 改红：把 `parse_proxy_authenticate` 的 `value.split(',')` 换成
        // `std::iter::once(value)`（即只按整行当一条 challenge 解析）
        // ——第一条断言只会得到一条 scheme 为 `Negotiate` 的记录，
        // 后两格对不上。
        assert_eq!(
            parse_proxy_authenticate("Negotiate, NTLM, Basic"),
            vec![ch("Negotiate", None), ch("NTLM", None), ch("Basic", None)]
        );
    }

    #[test]
    fn a_token68_is_not_split_even_though_it_can_end_with_padding() {
        // token68 的字符集里没有逗号，所以按逗号切不会把带 challenge 的
        // 那一段切坏——哪怕它以 base64 的 `=` padding 收尾。
        assert_eq!(
            parse_proxy_authenticate("Negotiate TlRMTVNTUAACAAA=, NTLM"),
            vec![ch("Negotiate", Some("TlRMTVNTUAACAAA=")), ch("NTLM", None)]
        );
    }

    #[test]
    fn auth_params_are_not_mistaken_for_schemes() {
        // `Digest realm="x", qop="auth"` 是**一条** challenge：逗号后面
        // 那一段是它的 auth-param，不是一个新的 scheme。判别式是"第一个
        // 词是不是合法 HTTP token"——`qop="auth"` 含 `=` 和 `"`，不是。
        //
        // 改红：把 `if !is_http_token(head) { continue; }` 删掉——会多出
        // 一条 scheme 是 `qop="auth"` 的假 challenge，而且它排在
        // `Negotiate` 前面，`select_challenge` 的兜底分支会挑中它。
        assert_eq!(
            parse_proxy_authenticate("Digest realm=\"x\", qop=\"auth\", Negotiate"),
            vec![ch("Digest", None), ch("Negotiate", None)]
        );
    }

    #[test]
    fn a_comma_inside_a_quoted_auth_param_is_a_documented_limitation() {
        // 这条钉住的是**已知的不支持形状**（见 `parse_proxy_authenticate`
        // 的文档），不是期望的行为：引号串里的逗号会把一条 challenge 切
        // 成两段。
        //
        // 良性的那一半：碎片 `inc"` 不是 token，被当成 auth-param 续段
        // 跳过，scheme 的识别仍然正确。
        assert_eq!(
            parse_proxy_authenticate("Basic realm=\"corp, inc\", Negotiate"),
            vec![ch("Basic", None), ch("Negotiate", None)]
        );
        // 会误判的那一半：引号串里逗号后面恰好跟着一个 token + 空白，
        // 于是多认出一条根本不存在的 `Negotiate`。后果有界——协商器会
        // 拿它去谈，代理不认，最多在 MAX_ROUNDS 之内报 ProxyAuthFailed。
        assert_eq!(
            parse_proxy_authenticate("Basic realm=\"corp, Negotiate 没有开\""),
            vec![ch("Basic", None), ch("Negotiate", None)],
            "这是已知限制；如果哪天补了引号串状态机，这条断言应当被改成只剩 Basic"
        );
    }

    #[test]
    fn an_empty_or_garbage_header_yields_no_challenge() {
        assert!(parse_proxy_authenticate("").is_empty());
        assert!(parse_proxy_authenticate("   ,  , ").is_empty());
        // 整行都是 auth-param、一个 scheme 都没有：不硬造 scheme。
        assert!(parse_proxy_authenticate("realm=\"corp\"").is_empty());
    }

    // ================= W35：挑哪一条 =================

    #[test]
    fn negotiate_wins_over_ntlm_which_wins_over_anything_else() {
        // ★ W35 的正题。代理把 Basic 排在最前面是常态，顺序不由我们控制；
        // 只取第一条就会把整个 SSPI 能力旁路掉。
        //
        // 改红：把 `select_challenge` 改成 `challenges.first()`——前三格
        // 分别变成 Basic、Basic、NTLM。
        let cases: [(&str, &str); 6] = [
            ("Basic, NTLM, Negotiate", "Negotiate"),
            ("Basic realm=\"corp\", Negotiate", "Negotiate"),
            ("Basic, NTLM", "NTLM"),
            ("Negotiate, NTLM", "Negotiate"),
            ("NTLM, Negotiate", "Negotiate"),
            // 一条都不认识：如实用代理真正给出的第一条，不编。
            ("Digest realm=\"corp\"", "Digest"),
        ];
        for (header, expected) in cases {
            let challenges = parse_proxy_authenticate(header);
            assert_eq!(
                select_challenge(&challenges).map(|c| c.scheme.as_str()),
                Some(expected),
                "header={header}"
            );
        }
        // 一个 scheme 都没有时返回 None——调用方据此报"代理没给出任何
        // 认证方式"，而不是编一个 Basic 出来。
        assert!(select_challenge(&[]).is_none());
    }

    #[test]
    fn scheme_matching_in_selection_is_case_insensitive() {
        // RFC 7235 §2.1：auth-scheme 大小写不敏感。
        let challenges = parse_proxy_authenticate("basic, negotiate");
        assert_eq!(
            select_challenge(&challenges).map(|c| c.scheme.as_str()),
            Some("negotiate")
        );
    }

    #[test]
    fn the_selected_challenge_keeps_its_own_token68() {
        // 挑中 Negotiate 就要带 Negotiate 那一条的 challenge，不能串到
        // 别的 scheme 的 token 上去。
        let challenges = parse_proxy_authenticate("NTLM TlRMTVNTUAAB, Negotiate TlRMTVNTUAAC");
        let picked = select_challenge(&challenges).unwrap();
        assert_eq!(picked.scheme, "Negotiate");
        assert_eq!(picked.token68.as_deref(), Some("TlRMTVNTUAAC"));
    }

    // ================= W32：scheme 名的长度上限 =================

    #[test]
    fn a_absurdly_long_scheme_name_is_bounded_before_it_reaches_an_error() {
        // 代理响应头整行上限是 16KB，而 scheme 是按第一个空白切出来的，
        // 没有任何长度约束就进了 `Error::ProxyAuthFailed` 的文案。规范
        // 见 `knownhosts::tests::damaged_line_error_message_is_bounded_in_length`。
        //
        // 改红：把 `bounded_scheme` 改成 `raw.to_string()`。
        let junk = "x".repeat(20_000);
        let challenges = parse_proxy_authenticate(&junk);
        let scheme = &challenges[0].scheme;
        assert!(
            scheme.len() < 1000,
            "scheme 没有被截断：{} 字节",
            scheme.len()
        );
        assert!(scheme.starts_with("xxxx"), "至少要保留可读的一部分");
        let text = Error::ProxyAuthFailed(format!("代理要求 {scheme}，本机无法协商")).to_string();
        assert!(text.len() < 1000, "错误文案没有被截断：{} 字节", text.len());
    }

    // ================= W36：token 的两个落脚点 =================

    #[test]
    fn the_authorization_header_and_the_request_buffer_are_both_zeroizing() {
        // ★ W36。token 逃出 `next_token` 之后还要落两个地方：拼出来的
        // `Proxy-Authorization` 值，和整条写进 socket 的请求缓冲。只把
        // trait 的返回类型改成 `Zeroizing` 而这两个仍是普通 `String`，
        // 等于什么都没堵住。
        //
        // 改红：把 `authorization_header` 或 `connect_request` 的返回类型
        // 换回 `String`——下面两行 `let _: &Zeroizing<String>` 编译不过，
        // 整个 rmc-core 的测试目标构建失败。
        //
        // 这是**编译期的红**，不是运行期的红：`Zeroizing` 的保证发生在
        // drop 之后的那块堆内存上，而在安全 Rust 里观察它本身就是 UB
        // （读已释放的内存）。所以这里钉的是类型，不是字节。
        let token = Zeroizing::new("TlRMTVNTUAAD".to_string());
        let header = authorization_header("Negotiate", &token);
        let _: &Zeroizing<String> = &header;
        assert_eq!(header.as_str(), "Negotiate TlRMTVNTUAAD");

        let req = connect_request(&target(), Some(header.as_str()));
        let _: &Zeroizing<String> = &req;
        assert!(
            req.contains("Proxy-Authorization: Negotiate TlRMTVNTUAAD\r\n"),
            "{}",
            req.as_str()
        );
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn the_request_buffer_never_grows_after_the_token_is_in() {
        // `Zeroizing<String>` 只管住"这一个 String drop 时抹零"。`String`
        // 扩容会把**旧缓冲区原样还给分配器、不抹零**，于是 token 在堆上
        // 留一份没抹掉的副本——只改签名、缓冲区照样 `format!` + `push_str`
        // 地长，等于没堵。
        //
        // 改红：把 `connect_request` 换回
        // `Zeroizing::new(format!(...))` + `push_str`——`format!` 与随后的
        // push 会把容量顶成 2 的幂，`capacity() == len()` 不成立。
        //
        // 实测补一句成色：把 `authorization_header` 换回
        // `Zeroizing::new(format!("{scheme} {token}"))` 这条测试**不会红**，
        // 而且那不是漏网——token 是那次 `format!` 里**最后**写进去的东西，
        // 之后不再有 push，所以没有"token 进了缓冲之后又扩容"的窗口。
        // 真正有那个窗口的是 `connect_request`（token 之后还要 push 两次
        // `\r\n`），这条断言钉住的就是它。
        //
        // 说明一句这条断言的成色：`String::with_capacity(n)` 的契约是
        // "**至少** n"，不是"恰好 n"。今天的 std 分配器给的是恰好 n，
        // 所以 `capacity() == len()` 能反查出"一次算够、之后没长过"；
        // 哪天 std 改成过量分配，这条会因为"实现细节变了"而红，不是因为
        // 回归——那时把它换成别的反查手段，别直接删掉。
        let token = Zeroizing::new("TlRMTVNTUAAD".repeat(40));
        let header = authorization_header("Negotiate", &token);
        assert_eq!(
            header.capacity(),
            header.len(),
            "Proxy-Authorization 的缓冲扩过容"
        );

        let req = connect_request(&target(), Some(header.as_str()));
        assert_eq!(req.capacity(), req.len(), "请求缓冲扩过容");
        assert!(req.contains(header.as_str()));

        // 不带 authorization 的那一路同样不能算错容量。
        let plain = connect_request(&target(), None);
        assert_eq!(plain.capacity(), plain.len(), "请求缓冲扩过容（无认证）");
    }

    #[test]
    fn a_request_without_authorization_carries_no_proxy_authorization_header() {
        // 一正一反成对：没有 token 时不能凭空多出一个空的
        // `Proxy-Authorization`（代理会把它当成一次失败的认证尝试）。
        let req = connect_request(&target(), None);
        assert!(!req.contains("Proxy-Authorization"), "{}", req.as_str());
        assert!(req.starts_with("CONNECT gateway.company.com:443 HTTP/1.1\r\n"));
        assert!(req.contains("Host: gateway.company.com:443\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
    }
}
