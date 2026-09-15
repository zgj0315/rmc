//! 代理认证的 SSPI 协商（Negotiate / NTLM）。
//!
//! 架构按 [`crate`] 顶部的约定分两层：
//!
//! - **纯逻辑**（本文件的上半部分，任何平台都编译、都跑测试）：scheme
//!   到安全包的映射、SPN 的构造、challenge/token 的 base64 编解码、
//!   上下文的生命周期状态机、以及协商结局的分类。
//! - **Win32**（`imp` 子模块，整块 `#[cfg(windows)]`）：只负责
//!   `AcquireCredentialsHandleW` / `InitializeSecurityContextW` 这两个
//!   调用与缓冲区搬运，一有判断就交回上面那一层。
//!
//! # 上下文的生命周期（账本 README 点名的那条约束）
//!
//! [`rmc_core::platform::ProxyAuthenticator::next_token`] 收的是
//! `&self` 不是 `&mut self`，所以上下文只能藏在内部的
//! `std::sync::Mutex` 里（trait 要求 `Sync`，`RefCell` 不行）。
//!
//! 更要紧的是**什么时候换一个新上下文**：Negotiate 与 NTLM 都是
//! **连接绑定**的认证，一条 TCP 连接上的多轮协商必须走同一个上下文，
//! 而换一条连接就必须从头来过。可是 `Transport::new` 只调用一次，
//! `Arc<dyn ProxyAuthenticator>` 被 `Transport` 持有到进程结束——同一个
//! 协商器实例要伺候此后每一次重连。
//!
//! 「新一轮协商开始」的唯一信号是首次调用时 `challenge == None`
//! （`http_connect` 第一次发 CONNECT 时手里还没有任何 challenge）。
//! 因此 [`SspiProxyAuthenticator::next_token`] 在 `challenge.is_none()`
//! 时**无条件重建**上下文。计划原文写的是「只在还没建过时才建」，
//! 那会让第一次协商结束（无论成败）之后的每一次重连都拿不到 token、
//! 直接 `ProxyAuthFailed`——客户端在第一次断线之后永久废掉，而那恰恰
//! 是 Supervisor 存在的全部场景。见
//! `a_challengeless_call_starts_a_fresh_context_for_the_next_connection`
//! 与 `a_failed_negotiation_does_not_disable_the_authenticator_forever`。
//!
//! # token 是敏感数据
//!
//! 协商 token 是 base64，看起来人畜无害，但它承载的是域凭据的派生物
//! （NTLM 的 Type-3 消息里是 NT/LM response，Kerberos 的 AP-REQ 里是
//! 用会话密钥加密的 authenticator）。因此：token 的字节一律装在
//! [`zeroize::Zeroizing`] 里；[`SspiStep`] 手写 `Debug` 把内容隐去
//! （派生的 `Debug` 会把 `&[u8]` 渲染成十进制数组，ASCII 子串匹配认不
//! 出来——账本里第 18 个反例正是栽在这上面）；[`AuthOutcome`] 不带
//! 任何一段 token 或 challenge 原文，日志里也只出现轮次与状态码。
//!
//! 唯一一处没有被 `Zeroizing` 覆盖的是 `next_token` 的返回值本身：
//! rmc-core 的 trait 签名是 `Option<String>`，`http_connect` 又会把它
//! `format!` 进一个普通 `String` 请求缓冲区。要堵上这一段需要同时改
//! rmc-core 的 trait 与 `connect.rs`，不在本任务范围内，记在
//! task-3-report.md 的遗留问题里。

use base64::Engine;
use rmc_core::addr::HostPort;
use rmc_core::platform::{ProxyAuthenticator, ProxyResolver};
use std::fmt;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

#[cfg(windows)]
mod imp;

#[cfg(windows)]
pub use imp::NegotiateContext;

/// 标准 base64（带 `=` 补齐）。HTTP 的 `Proxy-Authorization` /
/// `Proxy-Authenticate` 用的就是 RFC 4648 §4 这一种，不是 URL-safe
/// 变体——`connect.rs` 的 `looks_like_token68` 也是按这个字符集写的。
fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

// =====================================================================
// scheme 与安全包
// =====================================================================

/// 要用哪个 SSPI 安全包。这不是一个可以随便选的实现细节：代理在
/// `Proxy-Authenticate` 里写的 scheme 决定了 `Proxy-Authorization` 里
/// 的 token 必须是什么格式——`Negotiate` 是 SPNEGO 包装过的，`NTLM`
/// 是裸的 NTLMSSP 消息，两者互不相容。计划原文对两个 scheme 都写死
/// `w!("Negotiate")`，在只支持 NTLM 的代理上会送去一个它解不开的
/// SPNEGO token。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SspiPackage {
    Negotiate,
    Ntlm,
}

impl SspiPackage {
    /// 从 HTTP 的 auth-scheme 认出安全包。**大小写不敏感**：RFC 7235
    /// §2.1 规定 auth-scheme 是大小写不敏感的 token，而 `http_connect`
    /// 把响应头里的 scheme 原样转交过来，代理写 `negotiate` 完全合法。
    ///
    /// 只认这两个：Basic 要明文口令、Digest 要共享密钥，都不能用当前
    /// 登录用户的身份自动完成，本版本不做（现场表现是诊断页显示
    /// 「代理要求 Basic 认证」，而不是静默失败）。
    pub fn from_http_scheme(scheme: &str) -> Option<Self> {
        if scheme.eq_ignore_ascii_case("Negotiate") {
            Some(Self::Negotiate)
        } else if scheme.eq_ignore_ascii_case("NTLM") {
            Some(Self::Ntlm)
        } else {
            None
        }
    }

    /// 传给 `AcquireCredentialsHandleW` 的包名，也是写进诊断行的名字。
    pub fn package_name(self) -> &'static str {
        match self {
            Self::Negotiate => "Negotiate",
            Self::Ntlm => "NTLM",
        }
    }
}

// =====================================================================
// SPN：协商器怎么知道代理是谁（W3）
// =====================================================================

/// 当前这次连接实际要经过的代理，`None` 表示直连。
///
/// 存在的理由：SSPI 的 SPN 必须用**代理主机名**构造
/// （`HTTP/proxy.company.com`），而
/// [`ProxyAuthenticator::next_token`] 的签名里
/// （`&self, scheme, challenge`）根本没有这个信息——计划原文因此拿
/// `scheme` 去拼 SPN，拼出了 `HTTP/Negotiate`。这条 trait 就是把那条
/// 缺失的信息在构造协商器时注入进来的口子。
pub trait ProxyEndpoint: Send + Sync {
    fn current_proxy(&self) -> Option<HostPort>;
}

/// 把一个 [`ProxyResolver`] 包一层，顺手记下每次解析的结果，供 SPN
/// 构造使用。装配时把同一个 `Arc` 同时交给 `Transport::new` 的
/// resolver 位与 [`SspiProxyAuthenticator::new`] 即可。
///
/// 为什么不让协商器自己再解析一次代理：`Transport::connect` 的顺序是
/// `effective_proxy()`（也就是 `resolve()`）→ TCP 连接 → `http_connect`，
/// 协商器被调用时那次解析刚刚发生过。再解析一次意味着在企业网络上
/// 再跑一遍 WPAD 发现（MSDN 明说可能"several seconds"），而且两次结果
/// 未必一致——记下来才是准确的那一个。
pub struct ProxyEndpointRecorder {
    inner: Arc<dyn ProxyResolver>,
    last: Mutex<Option<HostPort>>,
}

impl ProxyEndpointRecorder {
    pub fn new(inner: Arc<dyn ProxyResolver>) -> Self {
        Self {
            inner,
            last: Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl ProxyResolver for ProxyEndpointRecorder {
    async fn resolve(&self, target: &HostPort) -> Option<HostPort> {
        let hop = self.inner.resolve(target).await;
        // 无条件覆盖（包括覆盖成 `None`）：这一次判定直连，就必须把上
        // 一次的代理主机清掉，否则下一次协商会拿着一个过期的 SPN 去
        // 找一台根本不在链路上的代理。
        *lock(&self.last) = hop.clone();
        hop
    }
}

impl ProxyEndpoint for ProxyEndpointRecorder {
    fn current_proxy(&self) -> Option<HostPort> {
        lock(&self.last).clone()
    }
}

/// SPN（Service Principal Name）。形如 `HTTP/proxy.company.com`：
///
/// - **服务类**固定是 `HTTP`（Kerberos 里 HTTP 代理与 Web 服务共用这
///   一个服务类，IE/Edge/Chrome 都是这么拼的）；
/// - **主机**取代理的主机名，**不带端口**——Windows 集成认证默认不把
///   端口写进 SPN（IE 的 `EnableSPNPortAssignment` 默认就是不带）；
/// - 统一小写，让日志与诊断行里同一台代理只有一种写法。
///
/// 参数收的是 [`HostPort`] 而不是 `&str`：端口从类型上就被分开了，
/// "不小心把端口拼进 SPN"这件事构造不出来。
pub fn spn_for_proxy(proxy: &HostPort) -> Option<String> {
    let host = proxy.host().trim().trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    Some(format!("HTTP/{}", host.to_ascii_lowercase()))
}

// =====================================================================
// 安全上下文
// =====================================================================

/// 一次 `step` 的结果。**三态，不是 `Option`**：`Option<Vec<u8>>` 会把
/// 「协商正常走完、没有更多 token 要发」与「协商失败」压成同一个
/// `None`，而这两件事在诊断页上要给出完全不同的处置建议（前者是代理
/// 拒绝了一份格式正确的凭据，后者是本机这边就没谈成）。
pub enum SspiStep {
    /// 下一个要发出去的 token（还没做 base64）。
    Token(Zeroizing<Vec<u8>>),
    /// 协商正常结束，SSPI 没有更多 token 要发了。
    Done,
    /// 协商失败。字符串里只放状态码与原因，**绝不放 token 或
    /// challenge 的任何一段**。
    Failed(String),
}

// 手写 `Debug`：派生的那个会把 `Zeroizing<Vec<u8>>` 里的字节渲染成
// 十进制数组（`[78, 84, 76, ...]`），于是"日志里不要出现 token"这条
// 纪律只要有人写了一句 `tracing::debug!("{step:?}")` 就破功，而且
// ASCII 子串匹配根本认不出来——账本 18 个反例里的最后一个就是栽在
// 这个渲染差异上。
impl fmt::Debug for SspiStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(t) => write!(f, "Token(<{} 字节，内容已隐去>)", t.len()),
            Self::Done => write!(f, "Done"),
            Self::Failed(why) => write!(f, "Failed({why})"),
        }
    }
}

/// 一次协商的安全上下文，每调用一次 [`SspiContext::step`] 推进一段。
///
/// `Send` 是硬要求：`step` 会被 [`tokio::task::spawn_blocking`] 搬到
/// 阻塞线程池里执行（见 [`SspiProxyAuthenticator::next_token`]）。
pub trait SspiContext: Send {
    /// `input` 是服务端 challenge 的**原始字节**（已解过 base64），
    /// 首段为 `None`。
    fn step(&mut self, input: Option<&[u8]>) -> SspiStep;
}

// =====================================================================
// SSPI 状态码的解读——纯映射，从 `imp` 里抠出来的
// =====================================================================
//
// 这四个常量与 `windows::Win32::Foundation` 里的同名 `HRESULT` 数值
// 相同（Win32 头文件定义、稳定的 ABI 常量）。这里重新声明成普通 `i32`
// 的理由跟 `proxy::AUTOPROXY_AUTO_DETECT` 那几个完全一样：`windows`
// crate 只在 `[target.'cfg(windows)'.dependencies]` 里，这台 macOS 上
// 根本没有这些符号，而下面的 [`classify_sspi_status`] 必须能在这里
// 跑表驱动测试。两份数值不漂移由 `imp.rs` 的 `const _: () = assert!`
// 在编译期核对。

/// `SEC_E_OK`。
pub const SEC_STATUS_OK: i32 = 0x0000_0000;
/// `SEC_I_CONTINUE_NEEDED`。
pub const SEC_STATUS_CONTINUE_NEEDED: i32 = 0x0009_0312;
/// `SEC_I_COMPLETE_NEEDED`。
pub const SEC_STATUS_COMPLETE_NEEDED: i32 = 0x0009_0313;
/// `SEC_I_COMPLETE_AND_CONTINUE`。
pub const SEC_STATUS_COMPLETE_AND_CONTINUE: i32 = 0x0009_0314;

/// 一个 SSPI 状态码对这一段协商意味着什么。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SspiStatusKind {
    /// 协商还要继续，这一段**必须**有 token 发出去。
    Continue,
    /// 协商到此为止：有 token 就把最后一段发出去，没有就是走完了。
    Done,
    /// 失败。
    Failed,
}

/// 状态码 → 解读。纯函数。
///
/// 要点：`SEC_I_CONTINUE_NEEDED`（0x00090312）**是成功码**，不是错误
/// ——HRESULT 的符号位是 0。只按 `is_err()` 判断会把"还要再谈一轮"
/// 当成成功收工；只按 `== SEC_E_OK` 判断又会把它当成失败。两种错法
/// 在这台机器上都测不出来，所以这段判断值得从 `imp` 里搬出来。
pub fn classify_sspi_status(code: i32) -> SspiStatusKind {
    if code < 0 {
        // HRESULT 的符号位就是"失败"位，这也是 `HRESULT::is_err()`
        // 的定义。
        return SspiStatusKind::Failed;
    }
    match code {
        SEC_STATUS_CONTINUE_NEEDED | SEC_STATUS_COMPLETE_AND_CONTINUE => SspiStatusKind::Continue,
        _ => SspiStatusKind::Done,
    }
}

/// 这个状态码要不要补一次 `CompleteAuthToken`。
///
/// Negotiate/NTLM 走 HTTP 时通常不会返回这两个码（它们是 Digest 之类
/// 的包才用的），但收到了就必须照约定补上，否则那个 token 是半成品。
pub fn needs_complete_auth_token(code: i32) -> bool {
    code == SEC_STATUS_COMPLETE_NEEDED || code == SEC_STATUS_COMPLETE_AND_CONTINUE
}

/// `SEC_E_TARGET_UNKNOWN`。以下六个同样由 `imp.rs` 的 const 断言核对。
pub const SEC_STATUS_TARGET_UNKNOWN: i32 = 0x8009_0303u32 as i32;
/// `SEC_E_SECPKG_NOT_FOUND`。
pub const SEC_STATUS_SECPKG_NOT_FOUND: i32 = 0x8009_0305u32 as i32;
/// `SEC_E_INVALID_TOKEN`。
pub const SEC_STATUS_INVALID_TOKEN: i32 = 0x8009_0308u32 as i32;
/// `SEC_E_LOGON_DENIED`。
pub const SEC_STATUS_LOGON_DENIED: i32 = 0x8009_030Cu32 as i32;
/// `SEC_E_NO_CREDENTIALS`。
pub const SEC_STATUS_NO_CREDENTIALS: i32 = 0x8009_030Eu32 as i32;
/// `SEC_E_NO_AUTHENTICATING_AUTHORITY`。
pub const SEC_STATUS_NO_AUTHENTICATING_AUTHORITY: i32 = 0x8009_0311u32 as i32;

/// 把状态码翻成一句给现场工程师看的话。**只有状态码与原因，没有任何
/// 一段 token。**
///
/// 这几条是现场最可能撞上的：前三条指向"本机/域配置有问题"，
/// `LOGON_DENIED` 指向"这个用户不被允许"，后两条分别是"没凭据"与
/// "联系不上域控"——诊断页要靠这个区别给出不同的处置建议。认不出来
/// 的码也一律把原始值带出去，好让远程工程师自己查。
pub fn describe_sspi_status(code: i32) -> String {
    let why = match code {
        SEC_STATUS_TARGET_UNKNOWN => "代理的 SPN 在域里找不到（SEC_E_TARGET_UNKNOWN）",
        SEC_STATUS_SECPKG_NOT_FOUND => "找不到这个安全包（SEC_E_SECPKG_NOT_FOUND）",
        SEC_STATUS_INVALID_TOKEN => "代理送来的 token 无法解析（SEC_E_INVALID_TOKEN）",
        SEC_STATUS_LOGON_DENIED => "域拒绝了这次登录（SEC_E_LOGON_DENIED）",
        SEC_STATUS_NO_CREDENTIALS => "当前用户没有可用于该代理的凭据（SEC_E_NO_CREDENTIALS）",
        SEC_STATUS_NO_AUTHENTICATING_AUTHORITY => {
            "联系不上可以签发票据的域控（SEC_E_NO_AUTHENTICATING_AUTHORITY）"
        }
        _ => "SSPI 报错",
    };
    format!("{why}，状态码 0x{:08X}", code as u32)
}

// =====================================================================
// 协商结局：给诊断页的带类型出口
// =====================================================================

/// 一次（或一段）协商的结局。
///
/// `next_token` 的返回值是 `Option<String>`，`None` 同时表示"scheme
/// 不支持"、"challenge 是坏的"、"建不出上下文"、"协商走完了"、"协商
/// 失败了"五件事——跟 Task 2 里 `resolve()` 的 `Option` 把"不走代理"
/// 与"解析失败"压平是同一类问题，解法也一样：另开一个带类型的出口，
/// 诊断页（方案 §3.10 的「代理认证（SSPI Negotiate）」一行）读它。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuthOutcome {
    /// 这个进程还没被任何代理要求过认证。
    #[default]
    NotAttempted,
    /// 代理要求的 scheme 本机不做（Basic/Digest）。带的是 scheme 名，
    /// 不是任何凭据。
    UnsupportedScheme(String),
    /// 不知道当前经过哪个代理，SPN 构造不出来。
    UnknownProxyEndpoint,
    /// 代理给的 challenge 不是合法 base64。**不带原文**。
    MalformedChallenge,
    /// 收到 challenge，但本机这边没有正在进行的协商（状态对不上）。
    ChallengeWithoutNegotiation,
    /// 建不出安全上下文：机器不在域里、包不可用、当前用户没有凭据。
    ContextUnavailable(SspiPackage),
    /// 已经发出第 `round` 段 token，代理接不接受要看 CONNECT 的结果。
    TokenIssued { package: SspiPackage, round: usize },
    /// 协商正常走完，SSPI 没有更多 token 可发，而代理仍在要求认证。
    Completed { package: SspiPackage, rounds: usize },
    /// 协商失败。`detail` 只有状态码与原因。
    Failed {
        package: SspiPackage,
        round: usize,
        detail: String,
    },
}

impl AuthOutcome {
    /// 诊断页那一行要显示的东西：`(是否通过, 说明文字)`。
    ///
    /// **第一项永远不会是 `Some(true)`**，这不是偷懒：协商器只知道
    /// 自己发出了什么，"代理接受了"这件事只有拿到 200 的
    /// `http_connect` 知道。由调用方把"CONNECT 成功"与这里的
    /// [`AuthOutcome::TokenIssued`] 合起来才是那一行的"通过"。写成
    /// `Some(true)` 就又是一条"测试通过 ≠ 验证了名字声称的事"。
    ///
    /// `None` 表示这一项没有结论（还没轮到，或者结论不在这里）。
    pub fn diagnostic(&self) -> (Option<bool>, String) {
        match self {
            Self::NotAttempted => (None, "代理没有要求认证".into()),
            Self::UnsupportedScheme(s) => (
                Some(false),
                format!("代理要求 {s} 认证，本机只做 Negotiate 与 NTLM"),
            ),
            Self::UnknownProxyEndpoint => (
                Some(false),
                "代理要求认证，但当前链路没有记录到代理地址，无法构造 SPN".into(),
            ),
            Self::MalformedChallenge => (
                Some(false),
                "代理返回的 challenge 不是合法的 base64，协商无法继续".into(),
            ),
            Self::ChallengeWithoutNegotiation => (
                Some(false),
                "代理在没有在途协商的情况下送来 challenge，协商状态不一致".into(),
            ),
            Self::ContextUnavailable(p) => (
                Some(false),
                format!("无法建立 {} 安全上下文，请确认本机已加入域且当前用户已登录", p.package_name()),
            ),
            Self::TokenIssued { package, round } => (
                None,
                format!(
                    "已向代理发出第 {round} 段 {} token，是否被接受要看 CONNECT 的结果",
                    package.package_name()
                ),
            ),
            Self::Completed { package, rounds } => (
                Some(false),
                format!(
                    "{} 协商在 {rounds} 段之后走完，代理仍要求认证——凭据格式没问题，是代理不接受当前用户",
                    package.package_name()
                ),
            ),
            Self::Failed {
                package,
                round,
                detail,
            } => (
                Some(false),
                format!("{} 协商在第 {round} 段失败：{detail}", package.package_name()),
            ),
        }
    }
}

// =====================================================================
// 协商器本体
// =====================================================================

/// 中毒了也把里面的值拿出来接着用。
///
/// W20.2 的形状：`lock().unwrap()` 在一次 panic 之后会让**此后每一次**
/// 调用都 panic。对一个被 `Transport` 持有到进程结束的单例来说，这是
/// 把一次偶发故障变成永久故障——正是本任务要消灭的那类"第一次出事
/// 之后客户端就废了"。这里守着的是同一条纪律。
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// 正在进行的协商。`round` 是本次协商已经推进过几段。
#[derive(Default)]
struct Negotiation {
    context: Option<Box<dyn SspiContext>>,
    round: usize,
}

struct Inner<F> {
    endpoint: Arc<dyn ProxyEndpoint>,
    factory: F,
    /// 在途协商。这把锁会被 `spawn_blocking` 里的 SSPI 调用**长时间**
    /// 持有（首段 Negotiate 可能真的去联系域控），所以它跟下面的
    /// `outcome` 是两把独立的锁：诊断页读结局时不该被一次正在进行的
    /// 协商挡住，更不该因此把异步执行线程堵上。
    negotiation: Mutex<Negotiation>,
    /// 只做短暂持有。加锁顺序固定是 `negotiation` → `outcome`，绝不
    /// 反过来。
    outcome: Mutex<AuthOutcome>,
}

/// 用 SSPI 完成代理认证的 [`ProxyAuthenticator`]。
///
/// 工厂闭包收 `(安全包, SPN)` 两样东西——**不是 scheme**。计划原文的
/// `Fn(&str)` 收的是 scheme，于是调用点只能拿 scheme 去拼 SPN，拼出
/// `HTTP/Negotiate`；把形状改成这样之后，"用 scheme 当主机名"在类型
/// 上就写不出来了。Windows 上的现成装配见
/// [`system_sspi_authenticator`]。
pub struct SspiProxyAuthenticator<F> {
    inner: Arc<Inner<F>>,
}

impl<F> fmt::Debug for SspiProxyAuthenticator<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 这个类型结构上就拿不到 token：它只存上下文（不透明）与
        // 结局（按设计不带 token），所以这里能安全地打印结局。
        f.debug_struct("SspiProxyAuthenticator")
            .field(
                "in_flight",
                &lock(&self.inner.negotiation).context.is_some(),
            )
            .field("outcome", &*lock(&self.inner.outcome))
            .finish()
    }
}

impl<F> SspiProxyAuthenticator<F>
where
    F: Fn(SspiPackage, &str) -> Option<Box<dyn SspiContext>> + Send + Sync + 'static,
{
    pub fn new(endpoint: Arc<dyn ProxyEndpoint>, factory: F) -> Self {
        Self {
            inner: Arc::new(Inner {
                endpoint,
                factory,
                negotiation: Mutex::new(Negotiation::default()),
                outcome: Mutex::new(AuthOutcome::NotAttempted),
            }),
        }
    }

    /// 最近一次协商的结局，供诊断页使用。见 [`AuthOutcome::diagnostic`]。
    pub fn last_outcome(&self) -> AuthOutcome {
        lock(&self.inner.outcome).clone()
    }
}

impl<F> Inner<F>
where
    F: Fn(SspiPackage, &str) -> Option<Box<dyn SspiContext>> + Send + Sync + 'static,
{
    fn set_outcome(&self, outcome: AuthOutcome) {
        *lock(&self.outcome) = outcome;
    }

    /// 推进一段协商。**整个函数都跑在 `spawn_blocking` 的阻塞线程上**
    /// ——`InitializeSecurityContextW` 是同步调用，首段可能真的去向域控
    /// 取 Kerberos 票，耗时不可预期。
    fn advance(
        &self,
        package: SspiPackage,
        start_new: bool,
        challenge: Option<Zeroizing<Vec<u8>>>,
    ) -> Option<String> {
        let mut neg = lock(&self.negotiation);

        if start_new {
            // ★ 无条件重建。见模块文档"上下文的生命周期"。丢掉旧的
            // 上下文会触发它的 Drop（Windows 上就是
            // DeleteSecurityContext + FreeCredentialsHandle）。
            *neg = Negotiation::default();
            let Some(spn) = self
                .endpoint
                .current_proxy()
                .as_ref()
                .and_then(spn_for_proxy)
            else {
                self.set_outcome(AuthOutcome::UnknownProxyEndpoint);
                return None;
            };
            match (self.factory)(package, &spn) {
                Some(ctx) => neg.context = Some(ctx),
                None => {
                    self.set_outcome(AuthOutcome::ContextUnavailable(package));
                    return None;
                }
            }
        }

        // 收到 challenge 却没有在途协商：**不能**在这里新建一个上下文
        // 再把服务端的 challenge 当首段输入喂进去——真实 SSPI 的首段
        // 不接受服务端 token，那样只会换回一个看不懂的错误码。
        if neg.context.is_none() {
            self.set_outcome(AuthOutcome::ChallengeWithoutNegotiation);
            return None;
        }

        neg.round += 1;
        let round = neg.round;
        let step = match neg.context.as_mut() {
            Some(ctx) => ctx.step(challenge.as_ref().map(|c| c.as_slice())),
            None => unreachable!("上一行刚确认过上下文存在"),
        };

        match step {
            SspiStep::Token(token) => {
                self.set_outcome(AuthOutcome::TokenIssued { package, round });
                // 先编码到一个会被抹掉的缓冲里；逃出去的那份是 rmc-core
                // 的 trait 形状要求的普通 `String`（见模块文档末尾）。
                let encoded = Zeroizing::new(b64().encode(token.as_slice()));
                Some(encoded.as_str().to_string())
            }
            SspiStep::Done => {
                neg.context = None;
                self.set_outcome(AuthOutcome::Completed {
                    package,
                    rounds: round,
                });
                None
            }
            SspiStep::Failed(detail) => {
                neg.context = None;
                self.set_outcome(AuthOutcome::Failed {
                    package,
                    round,
                    detail,
                });
                None
            }
        }
    }
}

#[async_trait::async_trait]
impl<F> ProxyAuthenticator for SspiProxyAuthenticator<F>
where
    F: Fn(SspiPackage, &str) -> Option<Box<dyn SspiContext>> + Send + Sync + 'static,
{
    async fn next_token(&self, scheme: &str, challenge: Option<&str>) -> Option<String> {
        let Some(package) = SspiPackage::from_http_scheme(scheme) else {
            self.inner
                .set_outcome(AuthOutcome::UnsupportedScheme(scheme.to_string()));
            return None;
        };

        let decoded = match challenge {
            Some(c) => match b64().decode(c) {
                Ok(bytes) => Some(Zeroizing::new(bytes)),
                // 注意：不把 `c` 写进结局或日志——它是服务端 token。
                Err(_) => {
                    self.inner.set_outcome(AuthOutcome::MalformedChallenge);
                    return None;
                }
            },
            None => None,
        };

        // 「新一轮协商开始」的唯一信号。
        let start_new = decoded.is_none();

        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.advance(package, start_new, decoded))
            .await
            .unwrap_or_else(|e| {
                // 阻塞任务 panic 会让 `negotiation` 那把锁中毒；`lock()`
                // 用 `into_inner` 接住，所以下一次连接仍然能重新协商。
                tracing::error!("SSPI 协商的阻塞任务崩溃：{e}");
                None
            })
    }
}

/// 造安全上下文的工厂：收 `(安全包, SPN)`，给回一个上下文。
///
/// 装箱（而不是让 [`SspiProxyAuthenticator`] 的泛型参数一路裸奔到
/// 调用方）是为了让 `Arc<dyn ProxyAuthenticator>` 这类装配点能写出一个
/// 说得出名字的具体类型。
pub type SspiContextFactory =
    Box<dyn Fn(SspiPackage, &str) -> Option<Box<dyn SspiContext>> + Send + Sync>;

/// Windows 上的现成装配：把 [`NegotiateContext`] 接上去。Task 10 的
/// 接线只需要给一个 [`ProxyEndpoint`]，拼 SPN 这件事没有出错的余地。
#[cfg(windows)]
pub fn system_sspi_authenticator(
    endpoint: Arc<dyn ProxyEndpoint>,
) -> SspiProxyAuthenticator<SspiContextFactory> {
    SspiProxyAuthenticator::new(
        endpoint,
        Box::new(|package: SspiPackage, spn: &str| {
            NegotiateContext::new(package, spn).map(|c| Box::new(c) as Box<dyn SspiContext>)
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmc_core::addr::HostPort;
    use rmc_core::platform::ProxyAuthenticator;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use zeroize::Zeroizing;

    // NTLM 三段式里客户端会见到的三条消息的样本。内容是编出来的，
    // 形状（`NTLMSSP\0` 签名 + 消息类型字节）跟真实报文一致，好让下面
    // 那个"挑剔的"假上下文能真的分辨出自己收到的是不是一条 Type-2
    // challenge，而不是照单全收任何字节。
    const NEGOTIATE_MSG: &[u8] = b"NTLMSSP\x00\x01SECRET-TYPE1";
    const CHALLENGE_MSG: &[u8] = b"NTLMSSP\x00\x02SERVER-TYPE2";
    const AUTHENTICATE_MSG: &[u8] = b"NTLMSSP\x00\x03SECRET-DOMAIN-TOKEN";

    // 上面三条消息的标准 base64。**手写常量，不是用实现里那套编码器
    // 算出来的**——用同一个编码器算期望值，等于让实现自己给自己判卷，
    // 编码环节换成任何一种别的 base64 变体（URL-safe、不补 `=`）都
    // 照样全绿。
    const NEGOTIATE_B64: &str = "TlRMTVNTUAABU0VDUkVULVRZUEUx";
    const CHALLENGE_B64: &str = "TlRMTVNTUAACU0VSVkVSLVRZUEUy";
    const AUTHENTICATE_B64: &str = "TlRMTVNTUAADU0VDUkVULURPTUFJTi1UT0tFTg==";

    fn proxy() -> HostPort {
        "proxy.company.com:8080".parse().unwrap()
    }

    /// 固定答案的代理出口，替代真实的 `ProxyEndpointRecorder`。
    struct FixedEndpoint(Option<HostPort>);

    impl ProxyEndpoint for FixedEndpoint {
        fn current_proxy(&self) -> Option<HostPort> {
            self.0.clone()
        }
    }

    fn endpoint() -> Arc<dyn ProxyEndpoint> {
        Arc::new(FixedEndpoint(Some(proxy())))
    }

    /// 一次 `step` 调用的记录：哪个上下文、第几轮、收到了什么。
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Leg {
        ctx_id: usize,
        round: usize,
        input: Option<Vec<u8>>,
    }

    /// 协商走到第三次调用时怎么收尾。真实世界里这对应"SSPI 说没有更多
    /// token 了"与"SSPI 报错"两种结局，它们折成同一个 `None` 返回给
    /// `http_connect`，但诊断上必须分得开。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Ending {
        Completed,
        Failed,
    }

    /// **挑剔的**假上下文：它模拟 NTLM 客户端一侧的真实约束——首轮必须
    /// 没有输入（服务端还没说过话），第二轮必须收到解过 base64 的
    /// Type-2 challenge 原文。喂错东西它返回 `Failed`，不照单全收。
    ///
    /// 这一条是这批测试能证明"协商逻辑对"而不只是"调用没崩"的前提：
    /// 一个什么都接受的假上下文，会让"忘了解 base64"、"把服务端
    /// challenge 喂给一个全新的上下文"这类错误全部静默通过。
    struct ScriptedContext {
        id: usize,
        round: usize,
        ending: Ending,
        log: Arc<Mutex<Vec<Leg>>>,
    }

    impl SspiContext for ScriptedContext {
        fn step(&mut self, input: Option<&[u8]>) -> SspiStep {
            self.round += 1;
            self.log.lock().unwrap().push(Leg {
                ctx_id: self.id,
                round: self.round,
                input: input.map(|b| b.to_vec()),
            });
            match (self.round, input) {
                (1, None) => SspiStep::Token(Zeroizing::new(NEGOTIATE_MSG.to_vec())),
                (1, Some(_)) => SspiStep::Failed("首轮不该带 challenge".into()),
                (2, Some(bytes)) if bytes == CHALLENGE_MSG => {
                    SspiStep::Token(Zeroizing::new(AUTHENTICATE_MSG.to_vec()))
                }
                (2, Some(_)) => SspiStep::Failed("第二轮收到的不是 Type-2 challenge".into()),
                (2, None) => SspiStep::Failed("第二轮缺少 challenge".into()),
                _ => match self.ending {
                    Ending::Completed => SspiStep::Done,
                    Ending::Failed => SspiStep::Failed("代理不接受这次协商".into()),
                },
            }
        }
    }

    /// 每次工厂被调用时记下来的东西：用哪个安全包、SPN 是什么。
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Built {
        package: SspiPackage,
        spn: String,
    }

    /// 测试用的观察窗：谁被造出来过、每一段协商都收到了什么。
    #[derive(Clone)]
    struct Harness {
        log: Arc<Mutex<Vec<Leg>>>,
        built: Arc<Mutex<Vec<Built>>>,
    }

    impl Harness {
        fn legs(&self) -> Vec<Leg> {
            self.log.lock().unwrap().clone()
        }
        fn built(&self) -> Vec<Built> {
            self.built.lock().unwrap().clone()
        }
    }

    fn scripted(
        ep: Arc<dyn ProxyEndpoint>,
        ending: Ending,
    ) -> (SspiProxyAuthenticator<SspiContextFactory>, Harness) {
        let h = Harness {
            log: Arc::new(Mutex::new(Vec::new())),
            built: Arc::new(Mutex::new(Vec::new())),
        };
        let log = Arc::clone(&h.log);
        let built = Arc::clone(&h.built);
        let next_id = AtomicUsize::new(0);
        let auth = SspiProxyAuthenticator::new(
            ep,
            Box::new(move |package: SspiPackage, spn: &str| {
                built.lock().unwrap().push(Built {
                    package,
                    spn: spn.to_string(),
                });
                let id = next_id.fetch_add(1, Ordering::SeqCst);
                Some(Box::new(ScriptedContext {
                    id,
                    round: 0,
                    ending,
                    log: Arc::clone(&log),
                }) as Box<dyn SspiContext>)
            }) as SspiContextFactory,
        );
        (auth, h)
    }

    // ================= scheme 这一层 =================

    #[tokio::test]
    async fn unsupported_scheme_is_refused_before_any_context_is_built() {
        // 改红：把 `SspiPackage::from_http_scheme(scheme)` 的判空守卫删掉
        // （或让它对任意 scheme 都返回 `Negotiate`）——工厂里的 panic
        // 会被触发。
        let a = SspiProxyAuthenticator::new(endpoint(), |_: SspiPackage, _: &str| {
            panic!("不支持的 scheme 不该创建上下文");
        });
        assert!(a.next_token("Basic", None).await.is_none());
        assert!(a.next_token("Digest", None).await.is_none());
        assert_eq!(
            a.last_outcome(),
            AuthOutcome::UnsupportedScheme("Digest".into())
        );
    }

    #[tokio::test]
    async fn scheme_matching_is_case_insensitive() {
        // RFC 7235 §2.1：auth-scheme 是大小写不敏感的，而 `http_connect`
        // 把 `Proxy-Authenticate` 头里的 scheme 原样转交过来——代理写
        // `negotiate` 或 `NEGOTIATE` 都合法。
        //
        // 改红：把 `from_http_scheme` 里的 `eq_ignore_ascii_case` 换成
        // `==`（即 brief 原文的 `matches!(scheme, "Negotiate" | "NTLM")`）
        // ——四条里有两条会返回 None。
        for scheme in ["Negotiate", "negotiate", "NTLM", "ntlm"] {
            let (a, _h) = scripted(endpoint(), Ending::Completed);
            assert_eq!(
                a.next_token(scheme, None).await.as_deref(),
                Some(NEGOTIATE_B64),
                "scheme={scheme}"
            );
        }
    }

    #[tokio::test]
    async fn the_http_scheme_selects_the_security_package() {
        // 代理说 `NTLM` 就必须拿 NTLM 包：Negotiate 包产出的是 SPNEGO
        // 包装过的 token，塞进 `Proxy-Authorization: NTLM ...` 里代理
        // 解不开。brief 原文对两个 scheme 都写死 `w!("Negotiate")`。
        //
        // 改红：`next_token` 里把传给工厂的 package 写死成
        // `SspiPackage::Negotiate`——第二条断言会失败。
        let (a, h) = scripted(endpoint(), Ending::Completed);
        a.next_token("Negotiate", None).await.unwrap();
        let (b, hb) = scripted(endpoint(), Ending::Completed);
        b.next_token("NTLM", None).await.unwrap();
        assert_eq!(h.built()[0].package, SspiPackage::Negotiate);
        assert_eq!(hb.built()[0].package, SspiPackage::Ntlm);
    }

    // ================= base64 这一层 =================

    #[tokio::test]
    async fn the_first_round_carries_no_challenge_and_returns_base64() {
        // 改红：`next_token` 在 `challenge` 为 `None` 时改传
        // `Some(&[])` 给 `step`——挑剔的假上下文会判"首轮不该带
        // challenge"返回 Failed，token 变成 None。
        let (a, h) = scripted(endpoint(), Ending::Completed);
        assert_eq!(
            a.next_token("Negotiate", None).await.as_deref(),
            Some(NEGOTIATE_B64)
        );
        assert_eq!(
            h.legs(),
            vec![Leg {
                ctx_id: 0,
                round: 1,
                input: None
            }]
        );
    }

    #[tokio::test]
    async fn the_challenge_reaches_the_context_base64_decoded() {
        // 改红：把 `b64().decode(c)` 换成 `Ok(c.as_bytes().to_vec())`
        // ——上下文收到的是 base64 文本而不是 Type-2 原文，假上下文
        // 判失败，token 变成 None。
        let (a, h) = scripted(endpoint(), Ending::Completed);
        a.next_token("Negotiate", None).await.unwrap();
        assert_eq!(
            a.next_token("Negotiate", Some(CHALLENGE_B64))
                .await
                .as_deref(),
            Some(AUTHENTICATE_B64)
        );
        assert_eq!(h.legs()[1].input.as_deref(), Some(CHALLENGE_MSG));
    }

    #[tokio::test]
    async fn a_malformed_challenge_never_reaches_the_context() {
        // 改红：把解码失败那一支从 `return None` 换成
        // `Ok(Vec::new())`/`unwrap_or_default()`——第二段会被真的喂给
        // 上下文，`legs()` 变成两条，且 `last_outcome()` 不再是
        // `MalformedChallenge`。
        let (a, h) = scripted(endpoint(), Ending::Completed);
        a.next_token("Negotiate", None).await.unwrap();
        assert!(a
            .next_token("Negotiate", Some("!!not-base64!!"))
            .await
            .is_none());
        assert_eq!(a.last_outcome(), AuthOutcome::MalformedChallenge);
        assert_eq!(h.legs().len(), 1, "坏 challenge 不该进到上下文里");
    }

    // ================= 上下文生命周期（账本 README 点名的那条） =======

    #[tokio::test]
    async fn one_connection_reuses_one_context_across_rounds() {
        // Negotiate/NTLM 是连接绑定的：同一条 TCP 连接上的多轮必须走
        // 同一个上下文，换一个新的，服务端会认成另一个客户端。
        //
        // 改红：把 `next_token` 里"只有 challenge 为 None 才重建上下文"
        // 改成无条件重建——第二段会落到一个全新的上下文（ctx_id=1、
        // round=1），既对不上 `built().len() == 1`，挑剔的假上下文也会
        // 判"首轮不该带 challenge"。
        let (a, h) = scripted(endpoint(), Ending::Completed);
        a.next_token("Negotiate", None).await.unwrap();
        a.next_token("Negotiate", Some(CHALLENGE_B64))
            .await
            .unwrap();
        assert_eq!(h.built().len(), 1, "一条连接只该建一个上下文");
        assert_eq!(
            h.legs(),
            vec![
                Leg {
                    ctx_id: 0,
                    round: 1,
                    input: None
                },
                Leg {
                    ctx_id: 0,
                    round: 2,
                    input: Some(CHALLENGE_MSG.to_vec())
                },
            ]
        );
    }

    #[tokio::test]
    async fn a_challengeless_call_starts_a_fresh_context_for_the_next_connection() {
        // ★ W2。`Transport` 把 `Arc<dyn ProxyAuthenticator>` 持有到进程
        // 结束，每次重连都走同一个实例；而 Negotiate/NTLM 的上下文是
        // 连接绑定的，第二条连接必须从头协商。"新一轮开始"的唯一信号
        // 就是 `challenge == None`。
        //
        // 改红（要忠实复现 brief 的语义，四处一起改）：给
        // `Negotiation` 加一个 `spent: bool`；`if start_new {` 换成
        // `if start_new && !neg.spent {`；`SspiStep::Done` 与
        // `SspiStep::Failed` 两支在清掉上下文之后置 `neg.spent = true`。
        // 这就是 brief 原文 `Option<Option<Box<dyn SspiContext>>>` 的
        // 两层语义：外层建过了就不再建，内层用尽了就永远是 None。
        // 改完这条测试的第二条连接首段返回 None，`unwrap()` 直接 panic。
        // ——只把 `if start_new {` 改成
        // `if start_new && neg.context.is_none() {` 是**骗得过**这条的
        // （协商收尾时上下文已经被清掉，于是照样会重建），那种改法由
        // `a_reconnect_after_a_successful_negotiation_starts_a_fresh_context`
        // 接住。实测两种改法各自只被其中一边抓到，三条缺一不可。
        let (a, h) = scripted(endpoint(), Ending::Completed);

        // 第一条连接：两段 token，第三次调用时 SSPI 说没有更多 token。
        a.next_token("Negotiate", None).await.unwrap();
        a.next_token("Negotiate", Some(CHALLENGE_B64))
            .await
            .unwrap();
        assert!(a
            .next_token("Negotiate", Some(CHALLENGE_B64))
            .await
            .is_none());
        assert!(matches!(a.last_outcome(), AuthOutcome::Completed { .. }));

        // 第二条连接：重连之后代理又要求认证，必须能从头协商。
        assert_eq!(
            a.next_token("Negotiate", None).await.as_deref(),
            Some(NEGOTIATE_B64),
            "重连之后必须能开一个全新的上下文"
        );
        assert_eq!(h.built().len(), 2);
        assert_eq!(
            h.legs().last().unwrap(),
            &Leg {
                ctx_id: 1,
                round: 1,
                input: None
            }
        );
    }

    #[tokio::test]
    async fn a_reconnect_after_a_successful_negotiation_starts_a_fresh_context() {
        // ★ 上一条覆盖的是「协商走完了之后」，这一条覆盖的是现场更常见
        // 的那种：第一条连接**认证成功**（发完第二段 token 代理就回了
        // 200，不再问），几小时后链路断了，Supervisor 重连。这时候
        // 协商器手里还攥着一个用了一半的活上下文——Negotiate/NTLM 是
        // 连接绑定的，拿它接着谈第二条连接，服务端会认成另一个客户端。
        //
        // 改红：把 `if start_new {` 换成
        // `if start_new && neg.context.is_none() {`——第二条连接会落到
        // 第一个上下文的第 3 段，挑剔的假上下文按剧本给 `Done`，
        // `unwrap()` 直接 panic。（这条改法**骗不过**这条测试，但骗得过
        // 上面那两条：那两条里第一条连接已经走完、上下文已经被清掉了。
        // 三条测试合起来才把生命周期这件事围严。）
        let (a, h) = scripted(endpoint(), Ending::Completed);

        // 第一条连接：两段 token 之后代理放行，协商器这边上下文还活着。
        a.next_token("Negotiate", None).await.unwrap();
        a.next_token("Negotiate", Some(CHALLENGE_B64))
            .await
            .unwrap();
        assert!(matches!(
            a.last_outcome(),
            AuthOutcome::TokenIssued { round: 2, .. }
        ));

        // 断线重连：必须从一个全新的上下文重新开始。
        assert_eq!(
            a.next_token("Negotiate", None).await.as_deref(),
            Some(NEGOTIATE_B64),
            "重连必须换一个新上下文，不能接着用上一条连接那个"
        );
        assert_eq!(h.built().len(), 2);
        assert_eq!(
            h.legs().last().unwrap(),
            &Leg {
                ctx_id: 1,
                round: 1,
                input: None
            }
        );
    }

    #[tokio::test]
    async fn a_failed_negotiation_does_not_disable_the_authenticator_forever() {
        // ★ W2 的另一半，也是现场后果最重的一条：按 brief 的写法，
        // 第一次协商失败之后 `*slot = None`，此后每一次重连都在
        // `slot.as_mut()?` 上返回 None，`http_connect` 直接
        // `ProxyAuthFailed`——客户端在第一次断线之后永久废掉，而那
        // 恰恰是 Supervisor 存在的全部场景。
        //
        // 改红：同 `a_challengeless_call_starts_a_fresh_context_for_the_next_connection`
        // 那条注释里的四处改动（`spent` 标记），已实测变红。
        let (a, h) = scripted(endpoint(), Ending::Failed);
        a.next_token("Negotiate", None).await.unwrap();
        a.next_token("Negotiate", Some(CHALLENGE_B64))
            .await
            .unwrap();
        assert!(a
            .next_token("Negotiate", Some(CHALLENGE_B64))
            .await
            .is_none());
        assert!(matches!(a.last_outcome(), AuthOutcome::Failed { .. }));

        assert_eq!(
            a.next_token("Negotiate", None).await.as_deref(),
            Some(NEGOTIATE_B64),
            "上一次协商失败不该让后面每一次重连都失败"
        );
        assert_eq!(h.built().len(), 2);
    }

    #[tokio::test]
    async fn a_challenge_without_a_negotiation_in_flight_is_refused() {
        // 没有在途协商却收到 challenge，说明状态对不上了。这时候**不能**
        // 新建一个上下文再把服务端的 challenge 当首轮输入喂进去——真实
        // SSPI 的首轮不接受服务端 token。
        //
        // 改红：把这一支改成"没有上下文就建一个"——工厂会被调用，
        // `built()` 不再为空。
        let (a, h) = scripted(endpoint(), Ending::Completed);
        assert!(a
            .next_token("Negotiate", Some(CHALLENGE_B64))
            .await
            .is_none());
        assert_eq!(a.last_outcome(), AuthOutcome::ChallengeWithoutNegotiation);
        assert!(h.built().is_empty(), "不该为一个孤立的 challenge 建上下文");
        assert!(h.legs().is_empty());
    }

    // ================= 完成 vs 失败 =================

    #[tokio::test]
    async fn finishing_and_failing_both_return_none_but_stay_distinguishable() {
        // 一正一反成对：`next_token` 的 `Option<String>` 把"协商正常
        // 走完"与"协商失败"压成同一个 `None`（跟 Task 2 里 `resolve()`
        // 把"不走代理"和"解析失败"压平是同一类问题），解法也一样——
        // 另开一个带类型的出口。
        //
        // 改红：把 `SspiStep::Done` 与 `SspiStep::Failed` 两支折成同一个
        // `AuthOutcome`（例如都记成 `Failed`）——`assert_ne!` 变红。
        let (done, _) = scripted(endpoint(), Ending::Completed);
        let (failed, _) = scripted(endpoint(), Ending::Failed);
        for a in [&done, &failed] {
            a.next_token("Negotiate", None).await.unwrap();
            a.next_token("Negotiate", Some(CHALLENGE_B64))
                .await
                .unwrap();
            assert!(a
                .next_token("Negotiate", Some(CHALLENGE_B64))
                .await
                .is_none());
        }
        assert_ne!(done.last_outcome(), failed.last_outcome());
        assert!(matches!(
            done.last_outcome(),
            AuthOutcome::Completed {
                package: SspiPackage::Negotiate,
                rounds: 3
            }
        ));
        assert!(matches!(failed.last_outcome(), AuthOutcome::Failed { .. }));

        // 诊断页那一行（§3.10「代理认证（SSPI Negotiate）」）拿到的说明
        // 也必须不一样，否则现场工程师看到的还是同一句话。
        let (done_ok, done_text) = done.last_outcome().diagnostic();
        let (failed_ok, failed_text) = failed.last_outcome().diagnostic();
        assert_ne!(done_text, failed_text);
        assert_eq!(done_ok, Some(false));
        assert_eq!(failed_ok, Some(false));
    }

    #[tokio::test]
    async fn a_token_that_was_issued_is_not_reported_as_a_pass() {
        // 协商器只知道自己发出了什么，"代理接受了"这件事只有拿到 200
        // 的 `http_connect` 知道。诊断行因此不给 `Some(true)`——否则
        // 就是又一条"测试通过 ≠ 验证了名字声称的事"。
        //
        // 改红：让 `TokenIssued` 那一支返回 `(Some(true), ...)`。
        let (a, _) = scripted(endpoint(), Ending::Completed);
        a.next_token("Negotiate", None).await.unwrap();
        assert!(matches!(
            a.last_outcome(),
            AuthOutcome::TokenIssued { round: 1, .. }
        ));
        assert_eq!(a.last_outcome().diagnostic().0, None);
    }

    #[tokio::test]
    async fn a_factory_that_cannot_build_a_context_is_reported_as_such() {
        // 建不出上下文（不在域内、包不可用）跟"协商到一半失败"是两件
        // 不同的事，处置建议也不同。
        //
        // 改红：把这一支的 outcome 换成 `AuthOutcome::Failed{..}`。
        let a = SspiProxyAuthenticator::new(endpoint(), |_: SspiPackage, _: &str| None);
        assert!(a.next_token("Negotiate", None).await.is_none());
        assert_eq!(
            a.last_outcome(),
            AuthOutcome::ContextUnavailable(SspiPackage::Negotiate)
        );
    }

    // ================= SPN（W3） =================

    #[test]
    fn the_spn_is_built_from_the_proxy_host_without_the_port() {
        // 改红：把 `spn_for_proxy` 里的 `hp.host()` 换成 `hp`（用
        // `Display`）——SPN 会变成 `HTTP/proxy.company.com:8080`。
        assert_eq!(
            spn_for_proxy(&proxy()).as_deref(),
            Some("HTTP/proxy.company.com")
        );
        // 大小写归一：SPN 在 AD 里大小写不敏感，但统一成小写能让日志与
        // 诊断行里同一台代理只出现一种写法。
        assert_eq!(
            spn_for_proxy(&"PROXY.Company.COM:3128".parse().unwrap()).as_deref(),
            Some("HTTP/proxy.company.com")
        );
    }

    #[tokio::test]
    async fn the_spn_uses_the_proxy_host_not_the_auth_scheme() {
        // ★ W3。brief 原文是 `NegotiateContext::new(&format!("HTTP/{scheme}"))`
        // 而 `scheme` 是 "Negotiate"/"NTLM"，于是 SPN 成了
        // `HTTP/Negotiate`——紧挨着的注释还写着"SPN 用代理主机名"。
        //
        // 改红：把传给工厂的 spn 换成 `format!("HTTP/{scheme}")`。
        let (a, h) = scripted(endpoint(), Ending::Completed);
        a.next_token("Negotiate", None).await.unwrap();
        assert_eq!(
            h.built(),
            vec![Built {
                package: SspiPackage::Negotiate,
                spn: "HTTP/proxy.company.com".into()
            }]
        );
    }

    #[tokio::test]
    async fn without_a_known_proxy_no_context_is_built() {
        // 不知道代理是谁就构造不出 SPN；此时宁可什么都不做，也不要拿
        // 一个瞎编的 SPN 去协商——那只会换来一个看不懂的 SSPI 错误码。
        //
        // 改红：在拿不到代理时退回一个默认 SPN（例如 `HTTP/`），工厂
        // 会被调用，`built()` 不再为空。
        let a = SspiProxyAuthenticator::new(
            Arc::new(FixedEndpoint(None)) as Arc<dyn ProxyEndpoint>,
            |_: SspiPackage, _: &str| panic!("没有代理主机时不该建上下文"),
        );
        assert!(a.next_token("Negotiate", None).await.is_none());
        assert_eq!(a.last_outcome(), AuthOutcome::UnknownProxyEndpoint);
    }

    /// 按剧本逐次给答案的假解析器，用来测 `ProxyEndpointRecorder`。
    struct ScriptedResolver(Mutex<Vec<Option<HostPort>>>);

    #[async_trait::async_trait]
    impl rmc_core::platform::ProxyResolver for ScriptedResolver {
        async fn resolve(&self, _target: &HostPort) -> Option<HostPort> {
            self.0.lock().unwrap().remove(0)
        }
    }

    #[tokio::test]
    async fn the_recorder_publishes_the_proxy_the_resolver_chose_and_clears_it() {
        // 一正一反成对（账本 README 那条）：只测"记下来了"是不够的，
        // 必须同时测"下一次直连时清掉了"——留着上一次的代理主机，
        // 会让一次直连连接拿着过期的 SPN 去协商。
        //
        // 改红：把记录那一行换成 `if let Some(hp) = &hop { *last =
        // Some(hp.clone()) }`（只记 Some）——第二段断言变红。
        let inner = ScriptedResolver(Mutex::new(vec![Some(proxy()), None]));
        let rec = ProxyEndpointRecorder::new(Arc::new(inner));
        let gw: HostPort = "gateway.company.com:443".parse().unwrap();

        use rmc_core::platform::ProxyResolver;
        assert_eq!(rec.resolve(&gw).await, Some(proxy()));
        assert_eq!(rec.current_proxy(), Some(proxy()));

        assert_eq!(rec.resolve(&gw).await, None);
        assert_eq!(rec.current_proxy(), None, "直连之后不该留着上一次的代理");
    }

    // ================= 执行位置与中毒恢复 =================

    /// `step` 里睡一觉，模拟一次真实的 SSPI 调用——Negotiate 首轮可能
    /// 要向域控取票，是会走网络的同步调用。
    struct SlowContext(Duration);

    impl SspiContext for SlowContext {
        fn step(&mut self, _input: Option<&[u8]>) -> SspiStep {
            std::thread::sleep(self.0);
            SspiStep::Done
        }
    }

    #[tokio::test]
    async fn sspi_steps_do_not_starve_the_async_runtime() {
        // W16 在 Task 2 立的那条形状，这里同样适用：SSPI 的
        // `InitializeSecurityContext` 是同步阻塞调用，首轮拿 Kerberos
        // 票可能真的去联系域控。直接在异步线程上调用会把整个事件循环
        // （以及 `tokio::time::timeout` 自己）挡住。
        //
        // 改红：把 `spawn_blocking` 换成直接同步调用——这条会从"超时"
        // 变成等满 500ms 才返回，`is_err()` 断言失败。
        let a = SspiProxyAuthenticator::new(endpoint(), |_: SspiPackage, _: &str| {
            Some(Box::new(SlowContext(Duration::from_millis(500))) as Box<dyn SspiContext>)
        });
        let outcome =
            tokio::time::timeout(Duration::from_millis(50), a.next_token("Negotiate", None)).await;
        assert!(outcome.is_err(), "SSPI 调用不该占用调用方的异步执行线程");
    }

    struct PanickingContext;

    impl SspiContext for PanickingContext {
        fn step(&mut self, _input: Option<&[u8]>) -> SspiStep {
            panic!("模拟一次上下文内部的 panic");
        }
    }

    #[tokio::test]
    async fn a_panicking_step_does_not_wedge_the_authenticator_forever() {
        // W20.2 的形状搬到这里：持有状态的那把锁一旦中毒，
        // `lock().unwrap()` 会让**此后每一次**协商都 panic——对一个
        // 进程级单例来说这是永久性故障。用
        // `unwrap_or_else(|e| e.into_inner())` 接住。
        //
        // 改红：把 `state`/`outcome` 两处的
        // `unwrap_or_else(|e| e.into_inner())` 换回 `unwrap()`——第二次
        // 调用会因为 PoisonError 而 panic，测试失败。
        let n = Arc::new(AtomicUsize::new(0));
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = Arc::clone(&log);
        let a = SspiProxyAuthenticator::new(endpoint(), move |_: SspiPackage, _: &str| {
            if n.fetch_add(1, Ordering::SeqCst) == 0 {
                Some(Box::new(PanickingContext) as Box<dyn SspiContext>)
            } else {
                Some(Box::new(ScriptedContext {
                    id: 1,
                    round: 0,
                    ending: Ending::Completed,
                    log: Arc::clone(&log2),
                }) as Box<dyn SspiContext>)
            }
        });
        assert!(a.next_token("Negotiate", None).await.is_none());
        assert_eq!(
            a.next_token("Negotiate", None).await.as_deref(),
            Some(NEGOTIATE_B64),
            "一次 panic 不该让协商器永久失效"
        );
    }

    // ================= token 不外泄 =================

    #[test]
    fn the_debug_rendering_of_a_token_is_redacted() {
        // 账本第 18 个反例的教训：`&[u8]` 的 `Debug` 渲染成十进制数组，
        // 所以只查 ASCII 子串是查不出来的——三种形态都要查。
        //
        // 改红：给 `SspiStep` 加 `#[derive(Debug)]`（删掉手写的那个
        // impl）——十进制那条断言会失败。
        let step = SspiStep::Token(Zeroizing::new(AUTHENTICATE_MSG.to_vec()));
        let rendered = format!("{step:?}");
        assert!(!rendered.contains("SECRET"), "{rendered}");
        assert!(!rendered.contains(AUTHENTICATE_B64), "{rendered}");
        assert!(!rendered.contains("83, 69, 67"), "{rendered}");
        // 但仍然要能看出这是一个 token、有多长——否则排查时什么都看不到。
        assert!(rendered.contains("28"), "{rendered}");
    }

    #[tokio::test]
    async fn outcomes_never_carry_challenge_or_token_bytes() {
        // 协商 token 是 base64，看起来人畜无害，但它承载的是域凭据的
        // 派生物。`AuthOutcome` 会被诊断页显示、被日志打印，不能带上
        // 任何一段 token 或 challenge 原文。
        //
        // 改红：把 `MalformedChallenge` 换成
        // `MalformedChallenge(String)` 并塞进原始 challenge 文本；或者
        // 让 `TokenIssued` 带上 token——两条断言分别变红。
        let (a, _) = scripted(endpoint(), Ending::Completed);
        a.next_token("Negotiate", None).await.unwrap();
        let issued = format!("{:?} {}", a.last_outcome(), a.last_outcome().diagnostic().1);
        assert!(!issued.contains(NEGOTIATE_B64), "{issued}");
        assert!(!issued.contains("SECRET"), "{issued}");

        assert!(a
            .next_token("Negotiate", Some("!!SECRET-CHALLENGE!!"))
            .await
            .is_none());
        let bad = format!("{:?} {}", a.last_outcome(), a.last_outcome().diagnostic().1);
        assert!(!bad.contains("SECRET-CHALLENGE"), "{bad}");
    }
    // ================= SSPI 状态码的解读 =================

    #[test]
    fn sec_i_continue_needed_is_a_success_code_not_an_error() {
        // 这是这段映射最容易错的一格：SEC_I_CONTINUE_NEEDED 的符号位
        // 是 0，`HRESULT::is_err()` 对它是 false。把它按"成功"一把抓，
        // 会让"还要再谈一轮"被当成"协商收工"；按 `== SEC_E_OK` 判断
        // 又会把它当成失败。两种错法在这台 macOS 上都跑不到 Win32
        // 那一层，所以这段判断被搬到这里表驱动测。
        //
        // 改红：把 `classify_sspi_status` 里那条 match 的
        // `SEC_STATUS_CONTINUE_NEEDED` 去掉（落到 `_ => Done`）——
        // 第 2、4 行会失败。
        let cases = [
            (SEC_STATUS_OK, SspiStatusKind::Done),
            (SEC_STATUS_CONTINUE_NEEDED, SspiStatusKind::Continue),
            (SEC_STATUS_COMPLETE_NEEDED, SspiStatusKind::Done),
            (SEC_STATUS_COMPLETE_AND_CONTINUE, SspiStatusKind::Continue),
            // SEC_E_LOGON_DENIED / SEC_E_NO_CREDENTIALS / 任意负数
            (SEC_STATUS_LOGON_DENIED, SspiStatusKind::Failed),
            (SEC_STATUS_NO_CREDENTIALS, SspiStatusKind::Failed),
            (-1, SspiStatusKind::Failed),
            // 没见过的信息性成功码：当成"谈完了"，不当成失败。
            (0x0009_0320, SspiStatusKind::Done),
        ];
        for (code, expected) in cases {
            assert_eq!(
                classify_sspi_status(code),
                expected,
                "code=0x{:08X}",
                code as u32
            );
        }
    }

    #[test]
    fn only_the_two_complete_codes_ask_for_complete_auth_token() {
        // 改红：把 `needs_complete_auth_token` 改成恒 `false`——
        // 第 3、4 行失败；改成恒 `true`——第 1、2、5 行失败。
        let cases = [
            (SEC_STATUS_OK, false),
            (SEC_STATUS_CONTINUE_NEEDED, false),
            (SEC_STATUS_COMPLETE_NEEDED, true),
            (SEC_STATUS_COMPLETE_AND_CONTINUE, true),
            (SEC_STATUS_LOGON_DENIED, false),
        ];
        for (code, expected) in cases {
            assert_eq!(
                needs_complete_auth_token(code),
                expected,
                "code=0x{:08X}",
                code as u32
            );
        }
    }

    #[test]
    fn a_status_description_names_the_cause_and_keeps_the_raw_code() {
        // 诊断页要能把"没加入域/没凭据"跟"联系不上域控"分开——这两种
        // 的处置完全不同（前者找 IT 加域，后者查网络到域控的可达性）。
        // 同时永远保留原始状态码，好让远程工程师查 MSDN。
        //
        // 改红：把 `describe_sspi_status` 的 match 全删掉只留
        // `_ => "SSPI 报错"`——前两条 `assert_ne!` 变红。
        let no_cred = describe_sspi_status(SEC_STATUS_NO_CREDENTIALS);
        let no_kdc = describe_sspi_status(SEC_STATUS_NO_AUTHENTICATING_AUTHORITY);
        assert_ne!(no_cred, no_kdc);
        assert!(no_cred.contains("凭据"), "{no_cred}");
        assert!(no_kdc.contains("域控"), "{no_kdc}");
        assert!(no_cred.contains("0x8009030E"), "{no_cred}");
        // 不认识的码也要带上原始值，不能吞掉。
        assert!(
            describe_sspi_status(0x8009_0399u32 as i32).contains("0x80090399"),
            "未知状态码必须原样带出"
        );
    }
}
