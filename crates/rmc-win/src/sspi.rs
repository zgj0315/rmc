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
//! 「新一条连接开始了」这件事由
//! [`rmc_core::platform::ProxyAuthenticator::begin_connection`] **明说**
//! （`http_connect` 在它的轮询循环之前调用恰好一次），
//! [`SspiProxyAuthenticator::begin_connection`] 在那里**无条件**丢掉上一
//! 次连接留下的一切。于是「每次连接尝试新建一个上下文」这条硬约束是
//! **结构性的**，不再是从 challenge 里推断出来的。
//!
//! # 在 `begin_connection` 之前，这里靠猜（W45）
//!
//! 修复轮 2 之前，唯一的信号是 `challenge == None`：一条连接的第一个
//! 407 不带 token68，所以「没有 challenge」被当成「新一轮开始」。
//! 这条推断有一半是对的（计划原文写的「只在还没建过时才建」会让第一次
//! 协商结束之后的每一次重连都拿不到 token，客户端第一次断线就永久
//! 废掉），**另一半是错的**：同一条连接里，最后一段 token 发出之后
//! 代理再回一个**裸的** `Proxy-Authenticate: Negotiate`——NTLM 拒绝
//! Type-3 之后的标准写法——也是「没有 challenge」，而它的意思是
//! 「凭据没问题，是这个用户不被接受」。
//!
//! 同一个信号承担两个互斥的含义，而 `next_token` 手里没有任何连接身份
//! 可以把它们分开。实测的代价：一次注定失败的 CONNECT 里连建 **4 个**
//! 安全上下文、发 **5 次** CONNECT，最后诊断页对现场工程师说「协商还要
//! 继续」。现在是 **1 个**上下文、**3 次** CONNECT，诊断是「凭据格式
//! 没问题，是代理不接受当前用户」。两种形状各有一条走完整 `http_connect`
//! 链路的常驻端到端测试
//! （`a_407_carrying_a_token68_after_the_final_leg_is_a_refusal` 与
//! `a_bare_407_after_the_final_leg_is_a_refusal_too`）。
//!
//! W2 的那三条回归测试仍在，只是「新连接」的信号换成了
//! `begin_connection`：
//! `one_connection_reuses_one_context_across_rounds`、
//! `a_challengeless_call_starts_a_fresh_context_for_the_next_connection`、
//! `a_reconnect_after_a_successful_negotiation_starts_a_fresh_context`。
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
//! 这条纪律现在是**贯通的**（W36）：
//! [`rmc_core::platform::ProxyAuthenticator::next_token`] 的返回类型
//! 本身就是 `Option<Zeroizing<String>>`，`http_connect` 那一侧拼出来的
//! `Proxy-Authorization` 值与整条请求缓冲也都是 `Zeroizing<String>`。
//! 修复轮 1 之前，token 会在逃出本 crate 的那一刻被抄进两个 drop 时不
//! 抹零的普通 `String`。

use base64::Engine;
use rmc_core::addr::HostPort;
use rmc_core::diagnostic::{ConnectOutcome, ProxyAuthLine, ProxyAuthSummary};
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
///
/// # 这个类型假定「同一时刻只有一次解析在途」（W33）
///
/// `last` 是一格**全局的**、会被每一次 `resolve()` 覆盖的槽。它给出的
/// 是"最近一次解析的结果"，不是"这次协商所属的那条连接用的代理"。
/// 两者一致的前提是：一次 `resolve()` 与紧随其后的那次协商之间，没有
/// 别人再调 `resolve()`。
///
/// **不是**并发建连打破它：Supervisor 的 `connecting_or_connected()`
/// 已经挡住了同时建两条连接。真正的逃逸口是
/// [`rmc_core::transport::Transport::effective_proxy`] 被文档标成"供
/// 预检与界面显示使用"——Task 9 的诊断页、Task 10 的状态栏只要**轮询**
/// 它（那是完全合理的界面写法，而且它就是这么被文档推荐的），就会在
/// 一次协商进行到一半时改写这里的 `last`。后果是第二段协商拿着另一台
/// 代理的 SPN 去谈，换回 `SEC_E_TARGET_UNKNOWN`；**没有任何测试会红**，
/// 因为两边各自都是对的。
///
/// 要彻底解决得把"这次连接用哪个代理"沿调用链传下去，也就是再改一次
/// `ProxyAuthenticator::next_token` 的签名。在那之前，Task 9/10 的派发
/// 里必须写明：**不要轮询 `effective_proxy`**，界面要显示的代理从
/// `TunnelEvent` 里取。
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
///
/// # 两种拼不出有意义 SPN 的输入（W33）
///
/// - **返回 `None`**：主机名去掉末尾的点之后是空的。`HostPort::new(".",
///   8080)` 是一个**合法**的 `HostPort`（`valid_host` 放行只由 `.`
///   组成的串），走到这里会变成空主机名——宁可返回 `None` 让结局记成
///   [`AuthOutcome::UnknownProxyEndpoint`]，也不要拿一个 `HTTP/` 去换
///   一个看不懂的 SSPI 错误码。见
///   `a_proxy_host_that_is_only_a_dot_yields_no_spn`。
/// - **返回一个对 Kerberos 无意义的 SPN**：代理配成 IP 字面量时，这里
///   会拼出 `HTTP/10.1.2.3`。AD 里几乎不会有人给 IP 注册 SPN，
///   Kerberos 那一段会失败（`SEC_E_TARGET_UNKNOWN`，诊断页会如实报
///   出来），**但这不是死路**：Negotiate 会自己回落到 NTLM，而 NTLM
///   根本不看 SPN。所以这里不拦——拦了就把一台本来能用 NTLM 连上的
///   机器变成连不上。见 `an_ip_literal_proxy_still_yields_an_spn`。
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
    ///
    /// `last` 为真表示**这是本次协商的最后一段**：SSPI 已经收工，这段
    /// token 发出去之后本机这边没有东西可发了，代理接不接受是代理的事。
    ///
    /// 这个标志不是装饰（W31）：NTLM 的第二段与 Kerberos 的单段都是
    /// **带着 token 收工**的，所以在真实 Windows 上
    /// [`SspiStep::Done`] 几乎不会出现，"协商走完了"这件事只能从这里
    /// 读出来。没有它的话，"凭据格式没问题、是代理不接受当前用户"
    /// 这句诊断就挂在一个产不出来的状态上。
    Token {
        token: Zeroizing<Vec<u8>>,
        last: bool,
    },
    /// 协商正常结束，SSPI 没有更多 token 要发了。
    ///
    /// 注意它跟 `Token { last: true }` 的区别：这里是**连最后一段都
    /// 没有**。HTTP 上的 Negotiate/NTLM 很少走到这一支。
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
            Self::Token { token, last } => {
                write!(f, "Token(<{} 字节，内容已隐去>, last={last})", token.len())
            }
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

/// [`step_from`] 的产出：这一段协商的结果，加上 Win32 那一侧必须照做的
/// 两件事。
///
/// 两个布尔为什么不能留在 `imp.rs` 里：它们决定的是句柄的所有权与上下文
/// 的寿命，错一个就是"失败之后对一个未必有效的句柄调
/// `DeleteSecurityContext`"或者"协商还要继续却把上下文标成结束"。
#[derive(Debug)]
pub struct StepDecision {
    /// 交给上层的结果。
    pub step: SspiStep,
    /// 要不要把这次 `InitializeSecurityContextW` 产出的上下文句柄接管
    /// 过来（接管了才会在 `Drop` 里 `DeleteSecurityContext`）。
    pub adopt_context: bool,
    /// 这个上下文是不是到此为止、后续再 `step` 一律拒绝。
    pub finished: bool,
}

/// 一次 `InitializeSecurityContextW` 的返回码与输出 token → 这一段协商
/// 该怎么算。**纯函数，没有一个 Win32 符号。**
///
/// # 为什么这 35 行必须待在这一层（W29）
///
/// 它原本写在 `imp.rs` 的 `match` 里，也就是 `#[cfg(windows)]` 那一块
/// 零自动化覆盖的代码中。复审把 `Continue` 与 `Done` 两条 arm 的**函数
/// 体整个对调**（语义上是灾难：要继续的一段被标成结束、要收工的一段被
/// 当成还没完），实测结果是 `cargo zigbuild --tests` 绿、
/// `cargo-zigbuild clippy -- -D warnings` 绿、零告警，macOS 上 62 条测试
/// 一行都跑不到——**三条自动化防线全部双盲**。这已经是同一个坑的第三次
/// （Task 2 的 `autoproxy_flags`、`dwAccessType`，然后是它）。
///
/// 搬到这里之后，那个对调在 macOS 上就能被
/// `a_status_and_a_token_decide_the_step_the_context_and_the_finished_flag`
/// 当场抓住。
///
/// # 三条真正的判断
///
/// 1. **说"还要继续"却没给 token**：协商推不下去了，算失败——不是
///    "等下一轮"，因为没有东西可发给代理，下一轮永远不会来。
/// 2. **说"谈完了"却还带着 token**：这一段**仍然要发出去**，代理靠它
///    放行。NTLM 第二段与 Kerberos 单段走的都是这一支。
/// 3. **失败时不接管 `new_ctx`**：`InitializeSecurityContext` 失败之后
///    这个句柄的有效性没有文档保证，对一个未必有效的句柄调
///    `DeleteSecurityContext` 比可能漏掉一次清理更危险；而且这条路径
///    上协商已经结束，不会反复发生。
///
/// `code` 只用来拼那两句给人看的话（[`describe_sspi_status`] 与"要求
/// 继续却没给 token"里的原始码）；分类本身在 `kind` 里，由
/// [`classify_sspi_status`] 算好传进来。
pub fn step_from(
    kind: SspiStatusKind,
    token: Option<Zeroizing<Vec<u8>>>,
    package: SspiPackage,
    code: i32,
) -> StepDecision {
    // 长度为 0 的输出缓冲等于没有 token：SSPI 在"没东西可发"时给的就是
    // 一个空缓冲，不是 NULL。
    let token = token.filter(|t| !t.is_empty());
    match kind {
        SspiStatusKind::Continue => match token {
            Some(token) => StepDecision {
                step: SspiStep::Token { token, last: false },
                adopt_context: true,
                finished: false,
            },
            None => StepDecision {
                step: SspiStep::Failed(format!(
                    "{} 要求继续协商却没有给出 token，状态码 0x{:08X}",
                    package.package_name(),
                    code as u32
                )),
                adopt_context: true,
                finished: true,
            },
        },
        SspiStatusKind::Done => match token {
            // 最后一段 token 仍然要发出去，代理靠它放行。
            Some(token) => StepDecision {
                step: SspiStep::Token { token, last: true },
                adopt_context: true,
                finished: true,
            },
            // 连最后一段都没有：协商到此为止。
            None => StepDecision {
                step: SspiStep::Done,
                adopt_context: true,
                finished: true,
            },
        },
        SspiStatusKind::Failed => StepDecision {
            step: SspiStep::Failed(describe_sspi_status(code)),
            adopt_context: false,
            finished: true,
        },
    }
}

// =====================================================================
// 协商结局：给诊断页的带类型出口
// =====================================================================

/// scheme 名进 [`AuthOutcome::UnsupportedScheme`] 之前的字符数上限。
///
/// auth-scheme 是一个 HTTP token，现实里最长的也就 `Negotiate` 这种
/// 量级；64 个字符已经宽松到不可能误伤真实代理。
const MAX_SCHEME_CHARS: usize = 64;

/// 把一个来路不明的 scheme 名截断、并转义掉控制字符，再让它进结局与
/// 诊断行（W32）。
///
/// 为什么要做：`next_token` 收到的 `scheme` 最终来自代理响应头，
/// `read_response` 对它只做了"按第一个空白切开"，长度上限是整行的
/// 16KB；它随后原样进 [`AuthOutcome::UnsupportedScheme`]，而那个变体
/// 会被诊断页显示、被 `Debug` 打印。仓库对"不受信任的原文进用户可见
/// 文案"已有规范与现成测试
/// （`knownhosts::tests::damaged_line_error_message_is_bounded_in_length`
/// 要求错误文案 < 1000 字节），这里照同一条办。
///
/// 转义控制字符的理由跟那边一样：本函数的输入不保证来自 `connect.rs`
/// 的那条解析路径——这是一个公开 trait 的实现，任何调用方都能传进来
/// 一段带 NUL 的字节。
fn bounded_scheme(raw: &str) -> String {
    let mut chars = raw.chars();
    let head: String = chars.by_ref().take(MAX_SCHEME_CHARS).collect();
    let truncated = chars.next().is_some();
    let escaped: String = head
        .chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().collect::<String>()
            } else {
                c.to_string()
            }
        })
        .collect();
    if truncated {
        format!("{escaped}…（已截断）")
    } else {
        escaped
    }
}

/// 声明 [`AuthOutcome`]。
///
/// # 为什么这个枚举要经一个宏（W46）
///
/// `every_outcome_gives_the_diagnostic_line_its_own_verdict_and_its_own_words`
/// 那张表要能证明自己**一格都没漏**。原来的办法是一个没有 `_ =>` 兜底的
/// `variant_name`：往枚举里加变体，它会编译不过，逼着补一行——但**只逼着
/// 补那一行**。表那边只有一句 `names.len() == cases.len()`，查的是重复，
/// 不是遗漏；加第十一格、顺手给 `variant_name` 补一行、不动表，测试照样
/// 全绿，而新那一格的诊断文案一个字都没被看过。
///
/// 宏把"一共有几个变体"从人写的数字变成从变体列表里**数出来**的
/// [`AuthOutcome::VARIANTS`]。表于是可以写成一个定长数组
/// `[(AuthOutcome, Option<bool>, &str); AuthOutcome::VARIANTS]`——少一格
/// 就是 `error[E0308]: expected an array with a size of 11`，**编译不
/// 过**，而不是绿着骗人。[`AuthOutcome::VARIANT_NAMES`] 再把"漏的是哪
/// 一格"当场说出来。
macro_rules! declare_auth_outcome {
    (
        $(#[$emeta:meta])*
        pub enum $name:ident {
            $(
                $(#[$vmeta:meta])*
                $variant:ident
                $( ( $($tty:ty),* $(,)? ) )?
                $( { $( $(#[$fmeta:meta])* $fname:ident : $fty:ty ),* $(,)? } )?
            ),* $(,)?
        }
    ) => {
        $(#[$emeta])*
        pub enum $name {
            $(
                $(#[$vmeta])*
                $variant
                $( ( $($tty),* ) )?
                $( { $( $(#[$fmeta])* $fname : $fty ),* } )?
            ),*
        }

        impl $name {
            /// 全部变体的名字，按声明顺序。**由声明宏生成**，加一个变体
            /// 这里就多一格，不需要谁记得同步。
            pub const VARIANT_NAMES: &'static [&'static str] = &[$(stringify!($variant)),*];

            /// 变体总数。诊断行那张表的长度必须等于它。
            pub const VARIANTS: usize = Self::VARIANT_NAMES.len();

            /// 这个结局是哪一个变体。只用来把断言失败的信息说清楚
            /// （"漏的是哪一格"、"哪一格的文案不对"），不参与任何判断。
            pub fn variant_name(&self) -> &'static str {
                match self {
                    $( Self::$variant { .. } => stringify!($variant) ),*
                }
            }
        }
    };
}

// 下面这就是一个普通的 `pub enum`——包在宏里只为让编译器数得出变体
// 个数（`std::mem::variant_count` 至今仍是 unstable），于是"诊断表漏了
// 一格"从一条会绿的测试变成一个编译错误。展开后的真实声明用
// `cargo expand -p rmc-win sspi` 看。
declare_auth_outcome! {
    /// 一次（或一段）协商的结局。
    ///
    /// `next_token` 的返回值是 `Option<Zeroizing<String>>`，`None` 同时表示"scheme
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
        ///
        /// **这个字符串一律经 [`bounded_scheme`] 截断过**（W32）：它的来源
        /// 是代理响应头里未经长度约束的字节（`read_response` 按第一个空白
        /// 切 scheme，整行上限 16KB），而它会直接进诊断行与 `Debug`。仓库
        /// 的规范见 `knownhosts::redact_for_error`。
        UnsupportedScheme(String),
        /// 不知道当前经过哪个代理，SPN 构造不出来。
        UnknownProxyEndpoint,
        /// 代理给的 challenge 不是合法 base64。**不带原文**。
        MalformedChallenge,
        /// 收到 challenge，但本机这边没有正在进行的协商（状态对不上）。
        ChallengeWithoutNegotiation,
        /// 建不出安全上下文：机器不在域里、包不可用、当前用户没有凭据。
        ContextUnavailable(SspiPackage),
        /// 已经发出第 `round` 段 token，而且协商**还要继续**（SSPI 说
        /// `SEC_I_CONTINUE_NEEDED`）。
        TokenIssued { package: SspiPackage, round: usize },
        /// **最后一段** token 已经发出（共 `rounds` 段），本机这边收工，
        /// 等代理裁决。
        ///
        /// 这一格是 W31 补的。在它之前，NTLM 第二段与 Kerberos 单段——
        /// 也就是真实 Windows 上**绝大多数**协商的收尾——都落在
        /// [`AuthOutcome::TokenIssued`] 上，跟"还要再谈一轮"分不开，于是
        /// "凭据格式没问题、是代理不接受当前用户"这句最需要的话挂在了一个
        /// 产不出来的状态上。
        FinalTokenIssued { package: SspiPackage, rounds: usize },
        /// 本机这边的协商已经走完，没有 token 可发了，而代理仍在要求认证。
        ///
        /// 两条路径都会到这里，而且**第二条才是现实中的那条**：
        ///
        /// 1. SSPI 直接给了 [`SspiStep::Done`]（连最后一段都没有）——HTTP 上
        ///    的 Negotiate/NTLM 很少这样；
        /// 2. 最后一段 token 已经发出（[`AuthOutcome::FinalTokenIssued`]），
        ///    代理却又回了一个 407。那就是代理看过凭据之后**不接受**。
        ///
        /// 第 2 条路径在修复轮 1 里**只有一半走得通**（W45）：那个 407
        /// 带着 token68 才到得了，而它是**裸的**（NTLM 拒绝 Type-3 之后
        /// 的标准写法）时，裸 407 先被当成"新一轮开始"，这一格撞不上。
        /// 两种形状现在各有一条端到端测试。
        Completed { package: SspiPackage, rounds: usize },
        /// 协商失败。`detail` 只有状态码与原因。
        Failed {
            package: SspiPackage,
            round: usize,
            detail: String,
        },
    }
}

impl AuthOutcome {
    /// 把自己转抄成**平台中立**的 [`ProxyAuthSummary`]，交给诊断页。
    ///
    /// # 为什么要转抄一次（W158）
    ///
    /// `rmc-win` 是 rmc-app 的 `cfg(windows)` 专属依赖，所以 macOS 上的
    /// `cargo test` 里 **rmc-app 根本看不见 `AuthOutcome`**。历史裁决 W38
    /// 要的那张「CONNECT 结果 × 协商结局」完整映射如果写在 rmc-app 的
    /// `#[cfg(windows)]` 里，就落进了本项目**按构造检测不到任何语义改动**
    /// 的那一层（闸门 5 只编译、闸门 6 只静态检查，都不跑测试；Task 5 用
    /// 八枪实测过，连把 `Box::leak` 换成悬垂栈指针都六道全绿）。
    ///
    /// 于是判断与文案整体搬去 `rmc_core::diagnostic`，这里只剩这一次
    /// 一一对应的转抄。**转抄本身在 macOS 上也跑得到**——本模块是
    /// rmc-win 的纯逻辑层，不带 `#[cfg(windows)]`，
    /// `every_auth_outcome_transcribes_into_its_own_summary` 逐个变体
    /// 钉住它。
    ///
    /// `SspiPackage` 在镜像里换成了它的 `package_name()`：rmc-core 不该
    /// 认识任何 Windows 概念，而现场工程师要看的本来就是 `Negotiate` /
    /// `NTLM` 这两个字。
    pub fn summary(&self) -> ProxyAuthSummary {
        match self {
            Self::NotAttempted => ProxyAuthSummary::NotAttempted,
            Self::UnsupportedScheme(s) => ProxyAuthSummary::UnsupportedScheme(s.clone()),
            Self::UnknownProxyEndpoint => ProxyAuthSummary::UnknownProxyEndpoint,
            Self::MalformedChallenge => ProxyAuthSummary::MalformedChallenge,
            Self::ChallengeWithoutNegotiation => ProxyAuthSummary::ChallengeWithoutNegotiation,
            Self::ContextUnavailable(p) => ProxyAuthSummary::ContextUnavailable {
                package: p.package_name().to_string(),
            },
            Self::TokenIssued { package, round } => ProxyAuthSummary::TokenIssued {
                package: package.package_name().to_string(),
                round: *round,
            },
            Self::FinalTokenIssued { package, rounds } => ProxyAuthSummary::FinalTokenIssued {
                package: package.package_name().to_string(),
                rounds: *rounds,
            },
            Self::Completed { package, rounds } => ProxyAuthSummary::Completed {
                package: package.package_name().to_string(),
                rounds: *rounds,
            },
            Self::Failed {
                package,
                round,
                detail,
            } => ProxyAuthSummary::Failed {
                package: package.package_name().to_string(),
                round: *round,
                detail: detail.clone(),
            },
        }
    }

    /// 诊断页那一行：结论 + 说明文字。只是 [`Self::summary`] 之后转手调
    /// `ProxyAuthSummary::line`，**本模块不再自己写一份文案**。
    ///
    /// W164 收拾的就是「同一件事在两个 crate 里各写一句话」：
    /// `http_connect` 抛的「本机无法协商」与这里说的「是代理不接受当前
    /// 用户」曾经互相矛盾。文案现在只有一份，住在 rmc-core；那张表还多
    /// 了一根 W38 要的轴（`connect`），十格因此变成二十格。
    pub fn line(&self, connect: ConnectOutcome) -> ProxyAuthLine {
        self.summary().line(connect)
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

/// **本次连接**的协商状态。每次 [`Inner::begin_connection`] 整个换一个
/// [`Default`]，所以这里的每一位都只描述当前这一条 TCP 连接。
#[derive(Default)]
struct Negotiation {
    context: Option<Box<dyn SspiContext>>,
    /// 本次连接已经推进过几段。
    round: usize,
    /// 最后一段 token 已经发出去了（[`SspiStep::Token`] 带 `last`），
    /// 本机这边没有东西可发了，就等代理裁决。
    ///
    /// 有了它，"最后一段发完之后代理又要了一次"才能被如实说成"代理
    /// 不接受当前用户"；没有它的话，那次调用会径直落到上下文的
    /// `step` 上，换回一句内部行话（W31）。
    ///
    /// 这一位在修复轮 1 里**永远撞不上**（W45）：那时"裸的 407"先被
    /// 当成"新一轮开始"，`*neg = Negotiation::default()` 把它一起清掉
    /// 了。修不了是因为当时没有连接身份可用——见模块文档。
    concluded: bool,
    /// 本次连接**已经建过**上下文了（不论它现在还在不在）。
    ///
    /// 这一位就是"一次连接尝试最多建一个安全上下文"这条约束的载体：
    /// 置真发生在调用工厂**之前**，所以连"工厂失败之后在同一条连接里
    /// 再试一次"都发生不了。清零只发生在 [`Inner::begin_connection`]，
    /// 也就是只发生在连接边界上。
    started: bool,
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
        // **只读 `outcome` 这一把短锁**（W33）。原来的版本顺手打印了一个
        // `in_flight`，代价是要去取 `negotiation` 那把锁——而拆成两把锁
        // 的全部理由就是"诊断页读结局时不该被一次正在进行的协商挡住"：
        // 首段 Negotiate 可能真的去联系域控，那把锁会被 `spawn_blocking`
        // 长时间持有。`last_outcome()` 守住了这条纪律，`Debug` 又把口子
        // 开回来了——而 `Debug` 恰恰是最容易被顺手写进日志的那一个。
        //
        // 这个类型结构上就拿不到 token：`AuthOutcome` 按设计不带任何一段
        // token 或 challenge 原文，所以打印结局是安全的。
        f.debug_struct("SspiProxyAuthenticator")
            .field("outcome", &*lock(&self.inner.outcome))
            .finish_non_exhaustive()
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

    /// 一次新的连接尝试开始了：把上一次连接留下的一切丢掉。
    ///
    /// **无条件**——这就是 W2 那条硬约束（每次连接尝试一个全新的安全
    /// 上下文）的全部实现。丢掉旧的上下文会触发它的 `Drop`（Windows 上
    /// 就是 `DeleteSecurityContext` + `FreeCredentialsHandle`）。
    ///
    /// 不动 `outcome`：`last_outcome()` 的语义是"最近一次协商的结局"，
    /// 重连的那一刻正是现场工程师最需要看到上一次为什么没通过的时候。
    fn begin_connection(&self) {
        *lock(&self.negotiation) = Negotiation::default();
    }

    /// 推进一段协商。**整个函数都跑在 `spawn_blocking` 的阻塞线程上**
    /// ——`InitializeSecurityContextW` 是同步调用，首段可能真的去向域控
    /// 取 Kerberos 票，耗时不可预期。
    fn advance(
        &self,
        package: SspiPackage,
        challenge: Option<Zeroizing<Vec<u8>>>,
    ) -> Option<Zeroizing<String>> {
        let mut neg = lock(&self.negotiation);

        // 最后一段 token 已经发出去了，代理却又回了一个 407：本机这边
        // 的协商已经走完，没有东西可发。这才是"凭据格式没问题，是代理
        // 不接受当前用户"在真实 Windows 上的到达路径（W31）——不把这一
        // 格拦在这里，这次调用会落到上下文的 `step` 上，换回一句内部
        // 行话。
        //
        // **这一支能不能撞上，全靠上面那句 `begin_connection`**（W45）：
        // 在它出现之前，裸的 407 先被当成"新一轮开始"把 `concluded`
        // 一起清掉了，这一支永远是死代码。现在 `concluded` 只可能在
        // 同一条连接里为真，所以它可以排在最前面。
        if neg.concluded {
            let rounds = neg.round;
            // 丢掉上下文（触发 Drop：DeleteSecurityContext +
            // FreeCredentialsHandle），这次协商到此为止。**不清
            // `started`**：这条连接已经建过上下文了，不许再开第二个。
            neg.context = None;
            neg.concluded = false;
            self.set_outcome(AuthOutcome::Completed { package, rounds });
            return None;
        }

        if !neg.started {
            // 本次连接的第一段。先置位再建——这样连"工厂失败之后在同一条
            // 连接里再试一次"都发生不了。
            neg.started = true;

            // 一条连接的**第一个** 407 就带着 challenge：本机这边还一个
            // 字节都没发过，而真实 SSPI 的首段不接受服务端 token，新建
            // 一个上下文再把它当首段输入喂进去只会换回一个看不懂的错误码。
            if challenge.is_some() {
                self.set_outcome(AuthOutcome::ChallengeWithoutNegotiation);
                return None;
            }

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

        // 上下文已经被上一段的 `Done`/`Failed` 清掉了，代理却还在要求
        // 认证：状态对不上，这条连接上没有东西可谈了。
        if neg.context.is_none() {
            self.set_outcome(AuthOutcome::ChallengeWithoutNegotiation);
            return None;
        }

        // 已经发过至少一段、上下文还活着，代理却回了一个**不带
        // challenge** 的 407。SSPI 的下一段要的就是服务端那一段 token，
        // 没有它谈不下去。这里既不能把 `None` 喂给一个谈到一半的上下文
        // （真实 SSPI 只会换回一个看不懂的状态码），也**不能**像修复轮 1
        // 之前那样把它当成"新一轮开始"去重建上下文——那正是同一次
        // CONNECT 里白建四个上下文的来源（W40/W45）。
        if neg.round > 0 && challenge.is_none() {
            let round = neg.round;
            neg.context = None;
            self.set_outcome(AuthOutcome::Failed {
                package,
                round,
                detail: "代理在协商途中不再给出 challenge，这一段没法接着谈".into(),
            });
            return None;
        }

        neg.round += 1;
        let round = neg.round;
        let step = match neg.context.as_mut() {
            Some(ctx) => ctx.step(challenge.as_ref().map(|c| c.as_slice())),
            None => unreachable!("上一行刚确认过上下文存在"),
        };

        match step {
            SspiStep::Token { token, last } => {
                neg.concluded = last;
                self.set_outcome(if last {
                    AuthOutcome::FinalTokenIssued {
                        package,
                        rounds: round,
                    }
                } else {
                    AuthOutcome::TokenIssued { package, round }
                });
                // 编码进一个会被抹掉的缓冲，**并且就这么交出去**：
                // `next_token` 的返回类型本身就是 `Zeroizing<String>`
                // （W36），不再需要在边界上抄一份普通 `String`。
                Some(Zeroizing::new(b64().encode(token.as_slice())))
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
    async fn begin_connection(&self) {
        // 跟 `next_token` 一样搬到阻塞线程上（W16 的形状）。`negotiation`
        // 那把锁可能正被一次 SSPI 调用长时间攥着：`http_connect` 的
        // future 被上层取消（Supervisor 的连接超时）并不会让已经跑起来的
        // `spawn_blocking` 任务停下，它还会握着锁直到域控回话。在异步执行
        // 线程上直接去抢这把锁，会把整个事件循环连同 `tokio::time::timeout`
        // 自己一起堵住。见 `begin_connection_does_not_starve_the_async_runtime`。
        let inner = Arc::clone(&self.inner);
        if let Err(e) = tokio::task::spawn_blocking(move || inner.begin_connection()).await {
            // 这里到不了：`begin_connection` 只取一把用 `into_inner` 接住
            // 中毒的锁、再赋一个 `Default`，没有可以 panic 的地方。真的
            // 崩了也不能把连接尝试带崩——协商器会在下一次连接边界上重来。
            tracing::error!("SSPI 连接边界的阻塞任务崩溃：{e}");
        }
    }

    /// W173：诊断页要的那句话经这条出去。**只取 `outcome` 那把短锁**
    /// （跟 [`SspiProxyAuthenticator::last_outcome`] 一样），不碰
    /// `negotiation`——那把锁可能正被一次去找域控的 SSPI 调用攥着，而
    /// 这个方法是 Supervisor 在广播事件时同步调的。
    ///
    /// 转抄只有一处（[`AuthOutcome::summary`]），这里不重写任何映射。
    fn auth_summary(&self) -> ProxyAuthSummary {
        self.last_outcome().summary()
    }

    async fn next_token(&self, scheme: &str, challenge: Option<&str>) -> Option<Zeroizing<String>> {
        let Some(package) = SspiPackage::from_http_scheme(scheme) else {
            // 截断（W32）：这一段字节来自代理响应头，没有任何长度约束。
            self.inner
                .set_outcome(AuthOutcome::UnsupportedScheme(bounded_scheme(scheme)));
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

        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.advance(package, decoded))
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
    use rmc_core::diagnostic::Verdict;

    /// 一个结局的 `Debug` 加上它的诊断行，拼成一串拿去查禁字。
    fn rendered_with_line(o: &AuthOutcome) -> String {
        format!("{o:?} {}", o.line(ConnectOutcome::Failed).detail)
    }
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

    /// `next_token` 的返回值 → `Option<String>`，只为让断言写得下去
    /// （`Option<Zeroizing<String>>::as_deref()` 给的是 `Option<&String>`，
    /// 跟字面量比不了）。传进来的那个 `Zeroizing` 在这里就被 drop 掉、
    /// 照常抹零。
    fn token_text(t: Option<Zeroizing<String>>) -> Option<String> {
        t.map(|t| t.as_str().to_string())
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

    /// 这个假上下文怎么收尾。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Ending {
        /// 第三次调用时 SSPI 说"没有更多 token 了"（`SspiStep::Done`）。
        Completed,
        /// 第三次调用时 SSPI 报错。
        ///
        /// 这两种结局折成同一个 `None` 返回给 `http_connect`，但诊断上
        /// 必须分得开。
        Failed,
        /// **第二段就是最后一段**：token 带 `last = true`（W31）。
        ///
        /// 这才是真实 Windows 上的形状——NTLM 的第二段与 Kerberos 的单段
        /// 都是带着要发的 token 收工的，根本走不到 `SspiStep::Done`。
        FinalOnSecondLeg,
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
                (1, None) => SspiStep::Token {
                    token: Zeroizing::new(NEGOTIATE_MSG.to_vec()),
                    last: false,
                },
                (1, Some(_)) => SspiStep::Failed("首轮不该带 challenge".into()),
                (2, Some(bytes)) if bytes == CHALLENGE_MSG => SspiStep::Token {
                    token: Zeroizing::new(AUTHENTICATE_MSG.to_vec()),
                    last: self.ending == Ending::FinalOnSecondLeg,
                },
                (2, Some(_)) => SspiStep::Failed("第二轮收到的不是 Type-2 challenge".into()),
                (2, None) => SspiStep::Failed("第二轮缺少 challenge".into()),
                _ => match self.ending {
                    Ending::Completed => SspiStep::Done,
                    Ending::Failed => SspiStep::Failed("代理不接受这次协商".into()),
                    // 走不到：`FinalOnSecondLeg` 的第二段之后，协商器
                    // 自己就把这次协商收掉了，不会再 `step` 第三次。
                    // 这一支一旦真的被跑到，测试里那条"legs 只有两条"
                    // 的断言会先失败。
                    // 这一句刻意抄 `imp.rs` 那道"已经走完"守卫的措辞：
                    // 下面那条测试要断言的正是"它不许出现在诊断行里"。
                    Ending::FinalOnSecondLeg => {
                        SspiStep::Failed("协商在这个上下文里已经走完，不能再往前推进".into())
                    }
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
                token_text(a.next_token(scheme, None).await).as_deref(),
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
            token_text(a.next_token("Negotiate", None).await).as_deref(),
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
            token_text(a.next_token("Negotiate", Some(CHALLENGE_B64)).await).as_deref(),
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
        // 改红（M2）：把 `advance` 里 `if !neg.started` 那道守卫拿掉、
        // 每一段都重建上下文——第二段会落到一个全新的上下文（ctx_id=1、
        // round=1），既对不上 `built().len() == 1`，挑剔的假上下文也会
        // 判"首轮不该带 challenge"。
        let (a, h) = scripted(endpoint(), Ending::Completed);
        a.begin_connection().await;
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
        // 连接绑定的，第二条连接必须从头协商。
        //
        // 名字里的"challengeless call"仍然准确——第二条连接的第一次调用
        // 就是不带 challenge 的那一次，它确实跑在一个全新的上下文上；
        // 变的是**凭什么知道这是新连接**：修复轮 2 之前靠
        // `challenge == None` 推断，现在由 `begin_connection` 明说（W45）。
        //
        // 改红（M10b，要忠实复现 brief 的语义，四处一起改）：给 **`Inner`**
        // 加一个 `spent: AtomicBool`；`if !neg.started` 换成
        // `if !neg.started && !self.spent.load(..)`；`SspiStep::Done` 与
        // `SspiStep::Failed` 两支在清掉上下文之后 `self.spent.store(true)`。
        //
        // 标记必须挂在 `Inner` 上，挂在 `Negotiation` 里**这条测试不会红**
        // （M10 实测 79 条全绿）——因为 `begin_connection` 整个换掉
        // `Negotiation`，顺手就把它清了。这正是这次重构的收益：
        // "跨连接残留的状态"现在得专门找个地方放，放不进按连接重置的那
        // 一格里。这就是 brief 原文
        // `Option<Option<Box<dyn SspiContext>>>` 的两层语义：外层建过了
        // 就不再建，内层用尽了就永远是 None。改完这条测试的第二条连接
        // 首段返回 None，`unwrap()` 直接 panic。
        // ——只把 `begin_connection` 的重置改成"上下文还在就不重置"
        // （M1）是**骗得过**这条的（协商收尾时上下文已经被清掉，于是
        // 照样会重建），那种改法由
        // `a_reconnect_after_a_successful_negotiation_starts_a_fresh_context`
        // 接住。实测两种改法各自只被其中一边抓到，三条缺一不可。
        let (a, h) = scripted(endpoint(), Ending::Completed);

        // 第一条连接：两段 token，第三次调用时 SSPI 说没有更多 token。
        a.begin_connection().await;
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
        a.begin_connection().await;
        assert_eq!(
            token_text(a.next_token("Negotiate", None).await).as_deref(),
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
        // 改红（M1）：把 `Inner::begin_connection` 的无条件重置换成
        // `if neg.context.is_none() { *neg = Negotiation::default(); }`
        // ——上一条连接那个用了一半的上下文会被留下来，第二条连接的首段
        // 撞上"协商途中代理不再给 challenge"那一支，返回 None，
        // `unwrap()` 直接 panic。（这条改法**骗不过**这条测试，但骗得过
        // 上面那两条：那两条里第一条连接已经走完、上下文已经被清掉了。
        // 三条测试合起来才把生命周期这件事围严。）
        let (a, h) = scripted(endpoint(), Ending::Completed);

        // 第一条连接：两段 token 之后代理放行，协商器这边上下文还活着。
        a.begin_connection().await;
        a.next_token("Negotiate", None).await.unwrap();
        a.next_token("Negotiate", Some(CHALLENGE_B64))
            .await
            .unwrap();
        assert!(matches!(
            a.last_outcome(),
            AuthOutcome::TokenIssued { round: 2, .. }
        ));

        // 断线重连：必须从一个全新的上下文重新开始。
        a.begin_connection().await;
        assert_eq!(
            token_text(a.next_token("Negotiate", None).await).as_deref(),
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
        // 改红（M10b）：同
        // `a_challengeless_call_starts_a_fresh_context_for_the_next_connection`
        // 那条注释里的 `spent` 标记改法（挂在 `Inner` 上），已实测变红。
        let (a, h) = scripted(endpoint(), Ending::Failed);
        a.begin_connection().await;
        a.next_token("Negotiate", None).await.unwrap();
        a.next_token("Negotiate", Some(CHALLENGE_B64))
            .await
            .unwrap();
        assert!(a
            .next_token("Negotiate", Some(CHALLENGE_B64))
            .await
            .is_none());
        assert!(matches!(a.last_outcome(), AuthOutcome::Failed { .. }));

        a.begin_connection().await;
        assert_eq!(
            token_text(a.next_token("Negotiate", None).await).as_deref(),
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
        a.begin_connection().await;
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
        // 一正一反成对：`next_token` 的 `Option<_>` 把"协商正常
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
        let done_line = done.last_outcome().line(ConnectOutcome::Failed);
        let failed_line = failed.last_outcome().line(ConnectOutcome::Failed);
        assert_ne!(done_line.detail, failed_line.detail);
        assert_eq!(done_line.verdict, Verdict::Fail);
        assert_eq!(failed_line.verdict, Verdict::Fail);
    }

    #[tokio::test]
    async fn a_token_that_was_issued_is_not_reported_as_a_pass() {
        // 协商器只知道自己发出了什么，"代理接受了"这件事只有拿到 200
        // 的 `http_connect` 知道。所以 `TokenIssued` 本身不是结论：
        // CONNECT 没建立时它是 `Fail`，建立了才是 `Pass`。
        //
        // W158 之后本模块只剩转抄，判断整体在 `rmc_core::diagnostic`；
        // 完整的二十格由那边的
        // `every_summary_and_connect_pair_has_its_own_verdict_and_its_own_words`
        // 守着（W30/W38）。这一条钉的是**转手之后两根轴还在**。
        //
        // 改红：把 `AuthOutcome::line` 的 `connect` 参数丢掉、写死成
        // `ConnectOutcome::Established`——第一条断言变红。
        let (a, _) = scripted(endpoint(), Ending::Completed);
        a.next_token("Negotiate", None).await.unwrap();
        assert!(matches!(
            a.last_outcome(),
            AuthOutcome::TokenIssued { round: 1, .. }
        ));
        assert_eq!(
            a.last_outcome().line(ConnectOutcome::Failed).verdict,
            Verdict::Fail,
            "协商还没走完 CONNECT 就断了——W38 当初缺的正是这一格"
        );
        assert_eq!(
            a.last_outcome().line(ConnectOutcome::Established).verdict,
            Verdict::Pass,
            "同一个结局配上「CONNECT 建立了」必须给出不同的结论"
        );
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

    #[tokio::test]
    async fn a_factory_that_failed_is_not_called_again_within_the_same_connection() {
        // ★ 「一次连接尝试最多建一个安全上下文」这条约束的另一半：工厂
        // **失败**之后，同一条连接里不许再调一次工厂。域机器上每调一次
        // 都是一次 `AcquireCredentialsHandleW`，机器不在域里时那是一次
        // 注定失败、却可能真的去找域控的往返。
        //
        // 载体是 `advance` 里 `neg.started = true;` 的**位置**：它排在
        // 调用工厂**之前**，所以「工厂失败之后在同一条连接里再试一次」
        // 连写都写不出来。清零只发生在 `Inner::begin_connection`，也就
        // 是只发生在连接边界上。
        //
        // 改红（P3）：把 `neg.started = true;` 从工厂调用之前挪到工厂
        // 成功之后（`Some(ctx) => { neg.context = Some(ctx); neg.started
        // = true; }`）——第二次调用会再进一次那一支，工厂被调两次。
        //
        // 这条约束此前只靠**调用方的行为**成立（`http_connect` 拿到
        // `None` 就立刻报 `ProxyAuthFailed` 退出，同一条连接里不存在
        // 「工厂失败之后的下一次调用」），协商器这边没有回归保护。
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let a = SspiProxyAuthenticator::new(endpoint(), move |_: SspiPackage, _: &str| {
            counted.fetch_add(1, Ordering::SeqCst);
            None
        });

        a.begin_connection().await;
        assert!(a.next_token("Negotiate", None).await.is_none());
        assert_eq!(
            a.last_outcome(),
            AuthOutcome::ContextUnavailable(SspiPackage::Negotiate)
        );

        // 同一条连接里代理又要了一次：不许再去建第二个上下文。
        assert!(a.next_token("Negotiate", None).await.is_none());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "同一条连接尝试里工厂只该被调用一次"
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
        a.begin_connection().await;
        assert!(a.next_token("Negotiate", None).await.is_none());
        // 那次 panic 是在握着 `negotiation` 锁的时候发生的，锁已经中毒；
        // 连接边界这一步同样要能从中毒的锁里把状态拿回来，否则重连的第一
        // 件事就先炸了。
        a.begin_connection().await;
        assert_eq!(
            token_text(a.next_token("Negotiate", None).await).as_deref(),
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
        let step = SspiStep::Token {
            token: Zeroizing::new(AUTHENTICATE_MSG.to_vec()),
            last: true,
        };
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
        let issued = rendered_with_line(&a.last_outcome());
        assert!(!issued.contains(NEGOTIATE_B64), "{issued}");
        assert!(!issued.contains("SECRET"), "{issued}");

        assert!(a
            .next_token("Negotiate", Some("!!SECRET-CHALLENGE!!"))
            .await
            .is_none());
        let bad = rendered_with_line(&a.last_outcome());
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

    // ================= W29：状态码 + token → 这一段算什么 =============

    /// 把一个 [`SspiStep`] 压成一个好断言的标签。
    fn shape(step: &SspiStep) -> &'static str {
        match step {
            SspiStep::Token { last: false, .. } => "token(还要继续)",
            SspiStep::Token { last: true, .. } => "token(最后一段)",
            SspiStep::Done => "done",
            SspiStep::Failed(_) => "failed",
        }
    }

    #[test]
    fn a_status_and_a_token_decide_the_step_the_handle_and_the_finished_flag() {
        // ★ W29。这 35 行原本写在 `imp.rs` 的 `match` 里，也就是
        // `#[cfg(windows)]` 那块零覆盖的代码中。复审把 `Continue` 与
        // `Done` 两条 arm 的**函数体整个对调**（语义上是灾难：要继续的
        // 一段被标成结束），实测 zigbuild 绿、clippy 绿、零告警、macOS
        // 62 条一行跑不到——三条防线全部双盲。搬到这一层之后：
        //
        // 改红：把 `step_from` 里 `Continue` 与 `Done` 两条 arm 的函数体
        // 对调——第 1、2、4、5 行同时失败（形状、finished 都对不上）。
        let tok = || Some(Zeroizing::new(b"TOKEN-BYTES".to_vec()));
        let code = SEC_STATUS_CONTINUE_NEEDED;
        /// 一行表：说明、输入的两样东西、期望的三样东西。
        struct Case {
            why: &'static str,
            kind: SspiStatusKind,
            token: Option<Zeroizing<Vec<u8>>>,
            shape: &'static str,
            adopt: bool,
            finished: bool,
        }
        let case = |why, kind, token, shape, adopt, finished| Case {
            why,
            kind,
            token,
            shape,
            adopt,
            finished,
        };
        let cases = [
            // 说明, kind, token, 期望形状, 接管句柄, finished
            case(
                "还要继续，而且给了 token",
                SspiStatusKind::Continue,
                tok(),
                "token(还要继续)",
                true,
                false,
            ),
            case(
                "说还要继续却没给 token：协商推不下去了",
                SspiStatusKind::Continue,
                None,
                "failed",
                true,
                true,
            ),
            case(
                "零长输出缓冲等于没给 token",
                SspiStatusKind::Continue,
                Some(Zeroizing::new(Vec::new())),
                "failed",
                true,
                true,
            ),
            case(
                "谈完了但还带着最后一段 token——真实 NTLM/Kerberos 走这一支",
                SspiStatusKind::Done,
                tok(),
                "token(最后一段)",
                true,
                true,
            ),
            case(
                "谈完了，连最后一段都没有",
                SspiStatusKind::Done,
                None,
                "done",
                true,
                true,
            ),
            case(
                "失败：不接管句柄",
                SspiStatusKind::Failed,
                None,
                "failed",
                false,
                true,
            ),
            case(
                "失败时哪怕 SSPI 写了一段 token，也不接管句柄",
                SspiStatusKind::Failed,
                tok(),
                "failed",
                false,
                true,
            ),
        ];
        assert_eq!(cases.len(), 7);
        for c in cases {
            let d = step_from(c.kind, c.token, SspiPackage::Negotiate, code);
            assert_eq!(shape(&d.step), c.shape, "{}", c.why);
            assert_eq!(d.adopt_context, c.adopt, "{}", c.why);
            assert_eq!(d.finished, c.finished, "{}", c.why);
        }
    }

    #[test]
    fn the_failure_texts_name_the_cause_and_never_carry_the_token() {
        // "要求继续却没给 token" 要带上包名与原始状态码，否则现场只能
        // 看到一句"协商失败"。
        //
        // 改红：把那句 `format!` 换成一个不带 `code` 的固定串。
        let d = step_from(
            SspiStatusKind::Continue,
            None,
            SspiPackage::Ntlm,
            SEC_STATUS_CONTINUE_NEEDED,
        );
        let SspiStep::Failed(why) = &d.step else {
            panic!("应当是 Failed：{:?}", d.step);
        };
        assert!(why.contains("NTLM"), "{why}");
        assert!(why.contains("0x00090312"), "{why}");

        // 失败那一支的说明来自 `describe_sspi_status`，不是一句空话。
        let d = step_from(
            SspiStatusKind::Failed,
            Some(Zeroizing::new(b"SECRET-TOKEN".to_vec())),
            SspiPackage::Negotiate,
            SEC_STATUS_LOGON_DENIED,
        );
        let SspiStep::Failed(why) = &d.step else {
            panic!("应当是 Failed：{:?}", d.step);
        };
        assert_eq!(why, &describe_sspi_status(SEC_STATUS_LOGON_DENIED));
        // 一正一反：token 的字节绝不能顺着失败文案漏出去。
        assert!(!why.contains("SECRET"), "{why}");
        assert!(!format!("{:?}", d.step).contains("SECRET"), "{:?}", d.step);
    }

    // ================= W31：最后一段 token =================

    #[tokio::test]
    async fn the_final_leg_is_reported_apart_from_the_middle_ones() {
        // ★ W31。NTLM 的第二段与 Kerberos 的单段都是**带着要发的 token
        // 收工**的，于是在改之前，真实 Windows 上绝大多数协商的收尾都落
        // 在 `TokenIssued` 上，跟"还要再谈一轮"分不开。
        //
        // 改红：把 `advance` 里 `neg.concluded = last;` 与那个
        // `if last { FinalTokenIssued } else { TokenIssued }` 换回无条件
        // 的 `TokenIssued`——倒数第二条断言失败。
        let (a, h) = scripted(endpoint(), Ending::FinalOnSecondLeg);
        a.next_token("Negotiate", None).await.unwrap();
        assert!(matches!(
            a.last_outcome(),
            AuthOutcome::TokenIssued { round: 1, .. }
        ));

        // 最后一段 token **仍然要发出去**，代理靠它放行。
        assert_eq!(
            token_text(a.next_token("Negotiate", Some(CHALLENGE_B64)).await).as_deref(),
            Some(AUTHENTICATE_B64)
        );
        assert_eq!(
            a.last_outcome(),
            AuthOutcome::FinalTokenIssued {
                package: SspiPackage::Negotiate,
                rounds: 2
            }
        );
        // 本机这边收工了，代理接不接受只有 CONNECT 知道——所以这一格
        // 的结论**由 CONNECT 决定**，不由协商器单方面给。
        assert_eq!(
            a.last_outcome().line(ConnectOutcome::Established).verdict,
            Verdict::Pass
        );
        assert_eq!(
            a.last_outcome().line(ConnectOutcome::Failed).verdict,
            Verdict::Fail
        );
        assert_eq!(h.legs().len(), 2);
    }

    #[tokio::test]
    async fn a_proxy_that_asks_again_after_the_final_token_is_refusing_the_user() {
        // ★ W31 的正题：这是"凭据格式没问题，是代理不接受当前用户"在
        // 真实 Windows 上的到达路径。改之前它挂在 `AuthOutcome::Completed`
        // 上，而那一格只有"SSPI 给了 Done 且没有输出 token"才到得了——
        // NTLM 与 Kerberos 都到不了。现场真正会看到的是一句
        // `Failed(协商在这个上下文里已经走完……)` 的内部行话。
        //
        // 改红：把 `advance` 里 `if neg.concluded { ... }` 整块删掉——
        // 这次调用会落到上下文的 `step` 上，结局变成 `Failed`，文案里是
        // 那句内部行话。
        let (a, h) = scripted(endpoint(), Ending::FinalOnSecondLeg);
        a.next_token("Negotiate", None).await.unwrap();
        a.next_token("Negotiate", Some(CHALLENGE_B64))
            .await
            .unwrap();

        // 代理又回了一个 407：它看过凭据了，不接受。
        assert!(a
            .next_token("Negotiate", Some(CHALLENGE_B64))
            .await
            .is_none());
        assert_eq!(
            a.last_outcome(),
            AuthOutcome::Completed {
                package: SspiPackage::Negotiate,
                rounds: 2
            }
        );
        let l = a.last_outcome().line(ConnectOutcome::Failed);
        assert_eq!(l.verdict, Verdict::Fail);
        assert!(l.detail.contains("不接受当前用户"), "{}", l.detail);
        assert!(
            !l.detail.contains("这个上下文里已经走完"),
            "不能把内部行话推给现场工程师：{}",
            l.detail
        );
        assert_eq!(
            h.legs().len(),
            2,
            "最后一段发完之后不该再去打扰那个已经收工的上下文"
        );
    }

    #[tokio::test]
    async fn a_bare_407_in_the_middle_of_a_negotiation_does_not_restart_it() {
        // ★ W45/W40。Type-1 发出去之后代理回了一个**不带 challenge** 的
        // 407：协商没法往下走（SSPI 的下一段要的就是服务端那一段 token）。
        //
        // 修复轮 1 会把它当成"新一轮开始"，在**同一次 CONNECT 里**再建一
        // 个完整的安全上下文，然后一路建到 `MAX_ROUNDS` 为止。域机器上每
        // 建一个就是一次 `AcquireCredentialsHandleW` ＋一次
        // `InitializeSecurityContextW`，都可能去找域控。
        //
        // 改红：在 `advance` 里把这一支删掉——要么工厂被第二次调用
        // （`built().len()` 变成 2），要么 `None` 被喂给谈到一半的上下文
        // （挑剔的假上下文判"第二轮缺少 challenge"，结局文案对不上）。
        let (a, h) = scripted(endpoint(), Ending::Completed);
        a.begin_connection().await;
        a.next_token("Negotiate", None).await.unwrap();

        assert!(a.next_token("Negotiate", None).await.is_none());
        assert_eq!(h.built().len(), 1, "不许在同一次连接里重开第二个上下文");
        assert_eq!(h.legs().len(), 1, "不许把空输入喂给谈到一半的上下文");
        let outcome = a.last_outcome();
        assert!(
            matches!(
                &outcome,
                AuthOutcome::Failed {
                    package: SspiPackage::Negotiate,
                    round: 1,
                    detail
                } if detail.contains("不再给出 challenge")
            ),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn a_reconnect_after_the_final_token_starts_a_fresh_context() {
        // 生命周期那三条测试的第四个场景：第一条连接**认证成功**（最后
        // 一段发完代理就回了 200），几小时后断线重连。`concluded` 这个
        // 新状态位必须跟着 `Negotiation::default()` 一起被清掉，否则重连
        // 的首段会撞上"最后一段已发出"那一支，直接报 `Completed`。
        //
        // 改红：把 `Inner::begin_connection` 里的
        // `*lock(&self.negotiation) = Negotiation::default();` 换成只清
        // `context`（`neg.context = None; neg.round = 0; neg.started =
        // false;`，留下 `concluded`）——重连的首段撞上 `concluded` 那一支
        // 直接报 `Completed` 并返回 None，
        // `unwrap()` 当场 panic。
        let (a, h) = scripted(endpoint(), Ending::FinalOnSecondLeg);
        a.begin_connection().await;
        a.next_token("Negotiate", None).await.unwrap();
        a.next_token("Negotiate", Some(CHALLENGE_B64))
            .await
            .unwrap();
        assert!(matches!(
            a.last_outcome(),
            AuthOutcome::FinalTokenIssued { rounds: 2, .. }
        ));

        a.begin_connection().await;
        assert_eq!(
            token_text(a.next_token("Negotiate", None).await).as_deref(),
            Some(NEGOTIATE_B64),
            "重连必须换一个新上下文"
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

    // ============ W158：AuthOutcome → ProxyAuthSummary 的转抄 ============

    /// 十个 [`AuthOutcome`] 各自转抄成**自己**那一个 `ProxyAuthSummary`，
    /// 载荷一个不丢。
    ///
    /// # 这条测试替掉了什么
    ///
    /// 它接替的是 W30 那张
    /// `every_outcome_gives_the_diagnostic_line_its_own_verdict_and_its_own_words`。
    /// 判断与文案按 W158 整体搬去了 `rmc_core::diagnostic`（理由见
    /// [`AuthOutcome::summary`] 的文档：写在这边的话，消费它的诊断页只能
    /// 住在 rmc-app 的 `#[cfg(windows)]` 里，而那一层按构造测不到）。
    /// 那张表在 rmc-core 里不但原样保住，还多了一根 W38 要的 `connect`
    /// 轴，十格变二十格。留在这边的只有「转抄」这一件事。
    ///
    /// # 为什么这张表也写成定长数组
    ///
    /// 跟原来一样：长度取 `AuthOutcome::VARIANTS`（声明宏从变体列表数
    /// 出来），少一格就是 `error[E0308]: expected an array with a size
    /// of N`，**编译不过**，而不是绿着骗人。
    ///
    /// # 改实现的哪一行会让它红
    ///
    /// - `summary()` 里任意两支的目标变体对调 → 变体名那条断言红；
    /// - `ContextUnavailable` 的 `package` 写死成 `"Negotiate"` →
    ///   NTLM 那一格的载荷断言红；
    /// - `round: *round` 写成 `round: 0` → 载荷那条红；
    /// - 给 `AuthOutcome` 加一个变体不动表 → 编译不过。
    #[test]
    fn every_auth_outcome_transcribes_into_its_own_summary() {
        let cases: [(AuthOutcome, ProxyAuthSummary); AuthOutcome::VARIANTS] = [
            (AuthOutcome::NotAttempted, ProxyAuthSummary::NotAttempted),
            (
                AuthOutcome::UnsupportedScheme("Basic".into()),
                ProxyAuthSummary::UnsupportedScheme("Basic".into()),
            ),
            (
                AuthOutcome::UnknownProxyEndpoint,
                ProxyAuthSummary::UnknownProxyEndpoint,
            ),
            (
                AuthOutcome::MalformedChallenge,
                ProxyAuthSummary::MalformedChallenge,
            ),
            (
                AuthOutcome::ChallengeWithoutNegotiation,
                ProxyAuthSummary::ChallengeWithoutNegotiation,
            ),
            (
                AuthOutcome::ContextUnavailable(SspiPackage::Ntlm),
                ProxyAuthSummary::ContextUnavailable {
                    package: "NTLM".into(),
                },
            ),
            (
                AuthOutcome::TokenIssued {
                    package: SspiPackage::Negotiate,
                    round: 1,
                },
                ProxyAuthSummary::TokenIssued {
                    package: "Negotiate".into(),
                    round: 1,
                },
            ),
            (
                AuthOutcome::FinalTokenIssued {
                    package: SspiPackage::Ntlm,
                    rounds: 2,
                },
                ProxyAuthSummary::FinalTokenIssued {
                    package: "NTLM".into(),
                    rounds: 2,
                },
            ),
            (
                AuthOutcome::Completed {
                    package: SspiPackage::Negotiate,
                    rounds: 3,
                },
                ProxyAuthSummary::Completed {
                    package: "Negotiate".into(),
                    rounds: 3,
                },
            ),
            (
                AuthOutcome::Failed {
                    package: SspiPackage::Negotiate,
                    round: 2,
                    detail: "域拒绝了这次登录（SEC_E_LOGON_DENIED）".into(),
                },
                ProxyAuthSummary::Failed {
                    package: "Negotiate".into(),
                    round: 2,
                    detail: "域拒绝了这次登录（SEC_E_LOGON_DENIED）".into(),
                },
            ),
        ];

        // 数组长度由编译器钉住；这里把**是哪些**变体对上，数量对而某一格
        // 写了两遍会在这里说出漏的是谁。
        let listed: std::collections::BTreeSet<&str> =
            cases.iter().map(|(o, _)| o.variant_name()).collect();
        let declared: std::collections::BTreeSet<&str> =
            AuthOutcome::VARIANT_NAMES.iter().copied().collect();
        assert_eq!(
            listed,
            declared,
            "表里漏了这些变体：{:?}",
            declared.difference(&listed).collect::<Vec<_>>()
        );

        // 十个结局必须落到十个**不同**的摘要变体上。少了这一条，把
        // `summary()` 整个写成 `ProxyAuthSummary::NotAttempted` 也只会让
        // 下面那堆 `assert_eq!` 红，而红出来的信息看不出是「映射塌成一格」。
        let mirrored: std::collections::BTreeSet<&str> =
            cases.iter().map(|(_, want)| want.variant_name()).collect();
        assert_eq!(
            mirrored.len(),
            AuthOutcome::VARIANTS,
            "十个结局没有映射到十个不同的摘要变体：{mirrored:?}"
        );

        for (outcome, want) in &cases {
            let got = outcome.summary();
            assert_eq!(
                got.variant_name(),
                want.variant_name(),
                "{} 转抄成了 {}",
                outcome.variant_name(),
                got.variant_name()
            );
            assert_eq!(
                &got,
                want,
                "{} 的载荷没有原样带过去",
                outcome.variant_name()
            );
        }
    }

    // ================= W32：scheme 名的长度上限 =================

    #[tokio::test]
    async fn an_absurdly_long_scheme_never_reaches_the_diagnostic_line_intact() {
        // ★ W32。`UnsupportedScheme` 收的是代理响应头里未加长度约束的
        // 字节（`read_response` 按第一个空白切 scheme，整行上限 16KB），
        // 而它直接进诊断行与 `Debug`。仓库已有规范与现成测试：
        // `knownhosts::tests::damaged_line_error_message_is_bounded_in_length`
        // 要求 < 1000 字节。
        //
        // 改红：把 `bounded_scheme(scheme)` 换回 `scheme.to_string()`。
        let junk = "x".repeat(20_000);
        let a = SspiProxyAuthenticator::new(endpoint(), |_: SspiPackage, _: &str| {
            panic!("不支持的 scheme 不该创建上下文")
        });
        assert!(a.next_token(&junk, None).await.is_none());

        let outcome = a.last_outcome();
        let text = outcome.line(ConnectOutcome::Failed).detail;
        assert!(text.len() < 1000, "诊断行没有被截断：{} 字节", text.len());
        assert!(
            format!("{outcome:?}").len() < 1000,
            "Debug 没有被截断：{} 字节",
            format!("{outcome:?}").len()
        );
        assert!(text.contains("xxxx"), "至少要保留可读的一部分：{text}");
    }

    #[tokio::test]
    async fn control_bytes_in_a_scheme_are_escaped_before_they_reach_a_diagnostic() {
        // W32 的另一半（同 `knownhosts` 那条 R31 的成对测试）：这是一个
        // 公开 trait 的实现，调用方传什么进来不由本模块决定。
        let a = SspiProxyAuthenticator::new(endpoint(), |_: SspiPackage, _: &str| {
            panic!("不支持的 scheme 不该创建上下文")
        });
        assert!(a.next_token("Neg\u{0}otiate", None).await.is_none());
        let rendered = rendered_with_line(&a.last_outcome());
        assert!(
            !rendered.contains('\u{0}'),
            "NUL 被原样塞进了诊断文案：{rendered:?}"
        );
        assert!(
            rendered.contains("Neg"),
            "至少要保留可读的一部分：{rendered}"
        );
    }

    // ================= W33：SPN 的两处边界 =================

    #[test]
    fn a_proxy_host_that_is_only_a_dot_yields_no_spn() {
        // `HostPort::new(".", 8080)` 是**合法**的 `HostPort`——`valid_host`
        // 放行只由 `.` 组成的串（它不是空的、字符集也允许），而
        // `spn_for_proxy` 去掉尾点之后拿到的是空主机名。宁可返回 `None`
        // 让结局记成 `UnknownProxyEndpoint`，也不要拿一个 `HTTP/` 去换
        // 一个看不懂的 SSPI 错误码。
        //
        // 改红：把 `if host.is_empty() { return None; }` 删掉——会拼出
        // `HTTP/`。
        let only_a_dot = HostPort::new(".", 8080).expect("这个主机名是合法的——这正是要点");
        assert_eq!(spn_for_proxy(&only_a_dot), None);

        // 一正一反：尾点是 FQDN 的合法写法，去掉之后还有东西就照常出 SPN。
        assert_eq!(
            spn_for_proxy(&HostPort::new("proxy.company.com.", 8080).unwrap()).as_deref(),
            Some("HTTP/proxy.company.com")
        );
    }

    #[tokio::test]
    async fn a_proxy_without_a_usable_spn_is_reported_as_an_unknown_endpoint() {
        // 上一条的下游：拼不出 SPN 时，工厂一次都不该被调用。
        let a = SspiProxyAuthenticator::new(
            Arc::new(FixedEndpoint(Some(HostPort::new(".", 8080).unwrap())))
                as Arc<dyn ProxyEndpoint>,
            |_: SspiPackage, _: &str| panic!("拼不出 SPN 时不该建上下文"),
        );
        assert!(a.next_token("Negotiate", None).await.is_none());
        assert_eq!(a.last_outcome(), AuthOutcome::UnknownProxyEndpoint);
    }

    #[test]
    fn an_ip_literal_proxy_still_yields_an_spn() {
        // 代理配成 IP 字面量时会拼出 `HTTP/10.1.2.3`——对 Kerberos 基本
        // 没有意义（AD 里几乎不会有人给 IP 注册 SPN）。**这里故意不拦**：
        // Negotiate 拿不到票会自己回落 NTLM，而 NTLM 根本不看 SPN；拦掉
        // 等于把一台本来能用 NTLM 连上的机器变成连不上。Kerberos 那一段
        // 失败时诊断页会如实显示 SEC_E_TARGET_UNKNOWN。
        //
        // 这条测试钉的是"行为是这样，而且是想清楚之后这样的"，不是
        // "这样最好"。
        assert_eq!(
            spn_for_proxy(&"10.1.2.3:8080".parse().unwrap()).as_deref(),
            Some("HTTP/10.1.2.3")
        );
    }

    // ========= W33/W46：Debug 与连接边界都不许碰长持有的那把锁 =========

    /// 进了 `step` 就在 `entered` 上发一声——**那一刻 `negotiation` 那把
    /// 锁必然已经被 `advance` 拿在手里**——然后攥着锁睡 `hold` 那么久。
    struct LockHoldingContext {
        entered: Option<tokio::sync::oneshot::Sender<()>>,
        hold: Duration,
    }

    impl SspiContext for LockHoldingContext {
        fn step(&mut self, _input: Option<&[u8]>) -> SspiStep {
            if let Some(tx) = self.entered.take() {
                let _ = tx.send(());
            }
            std::thread::sleep(self.hold);
            SspiStep::Done
        }
    }

    /// 起一个协商器，让它的首段协商在 `step` 里攥着 `negotiation` 那把锁
    /// 不放 `hold` 那么久。**函数返回时锁一定已经拿住了**——靠的是上下文
    /// 亲口说"我进了 step"，不是 sleep 赌一个够长的时间。
    ///
    /// W46：上一版这里是 `sleep(80ms)`，失效方向是**假绿**——机器一忙，
    /// 协商还没抢到锁，被测的那次渲染/边界调用就畅通无阻地过去了，测试
    /// 照样绿，而它本来要证明的事一次都没被证明过。握手换成
    /// `oneshot` 之后，"锁已经被拿住"是事实，不是赌来的。
    ///
    /// `hold` 这一边**仍然是时间**，但方向是安全的：机器越慢，锁被攥得
    /// 越久，被测那一侧越容易超时——失效方向是假红，不是假绿。
    async fn with_the_negotiation_lock_held(
        hold: Duration,
    ) -> (
        Arc<SspiProxyAuthenticator<SspiContextFactory>>,
        tokio::task::JoinHandle<Option<Zeroizing<String>>>,
    ) {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let entered = Mutex::new(Some(entered_tx));
        let a = Arc::new(SspiProxyAuthenticator::new(
            endpoint(),
            Box::new(move |_: SspiPackage, _: &str| {
                Some(Box::new(LockHoldingContext {
                    entered: entered.lock().unwrap().take(),
                    hold,
                }) as Box<dyn SspiContext>)
            }) as SspiContextFactory,
        ));
        let running = Arc::clone(&a);
        let handle = tokio::spawn(async move { running.next_token("Negotiate", None).await });
        entered_rx.await.expect("首段协商没能进到 step 里");
        (a, handle)
    }

    #[tokio::test]
    async fn the_debug_rendering_does_not_wait_for_a_negotiation_in_flight() {
        // 拆成 `negotiation` / `outcome` 两把锁的全部理由就是"诊断页读
        // 结局时不该被一次正在进行的协商挡住"——首段 Negotiate 可能真的
        // 去联系域控，那把锁会被 `spawn_blocking` 长时间持有。
        // `last_outcome()` 守住了，`Debug` 原来又把口子开回来了，而
        // `Debug` 恰恰是最容易被顺手写进日志的那一个。
        //
        // 改红：把 `impl Debug` 里的 `.field("in_flight",
        // &lock(&self.inner.negotiation).context.is_some())` 加回来——
        // 这次渲染会被在途协商挡满 600ms，`timeout` 先到。
        let (a, handle) = with_the_negotiation_lock_held(Duration::from_millis(600)).await;

        let rendering = Arc::clone(&a);
        let rendered = tokio::time::timeout(
            Duration::from_millis(200),
            tokio::task::spawn_blocking(move || format!("{rendering:?}")),
        )
        .await
        .expect("诊断页读结局不该等一次正在进行的协商")
        .unwrap();
        assert!(rendered.contains("outcome"), "{rendered}");

        let _ = handle.await;
    }

    #[tokio::test]
    async fn begin_connection_does_not_starve_the_async_runtime() {
        // 连接边界要取的也是 `negotiation` 那把锁，而它可能正被一次
        // **已经被取消**的连接尝试留下的 SSPI 调用攥着：`spawn_blocking`
        // 的任务不会因为调用方的 future 被丢掉而停下，它会一直握着锁直到
        // 域控回话。在异步执行线程上直接去抢，会把整个事件循环连同
        // `tokio::time::timeout` 自己一起堵住——跟 W16 在 Task 2 立的
        // 那条形状是同一件事。
        //
        // 改红：把 `begin_connection` 里的 `spawn_blocking` 去掉、直接
        // `self.inner.begin_connection()`——这条会从"超时"变成等满
        // 500ms 才返回，`is_err()` 断言失败。
        let (a, handle) = with_the_negotiation_lock_held(Duration::from_millis(500)).await;
        let boundary = tokio::time::timeout(Duration::from_millis(50), a.begin_connection()).await;
        assert!(boundary.is_err(), "连接边界不该占用调用方的异步执行线程");
        let _ = handle.await;
    }

    // ============ W45：走完整 http_connect 链路的端到端探针 ============

    const BARE_407: &str =
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\n\r\n";
    const OK_200: &str = "HTTP/1.1 200 Connection established\r\n\r\n";

    /// 带 token68 的 407（代理把 Type-2 challenge 挂在上面）。
    fn challenge_407() -> String {
        format!(
            "HTTP/1.1 407 Proxy Authentication Required\r\n\
             Proxy-Authenticate: Negotiate {CHALLENGE_B64}\r\n\r\n"
        )
    }

    /// duplex 另一端的一台**假代理**：逐条读 CONNECT 请求、按剧本回应答，
    /// 并记下每一条请求里的 `Proxy-Authorization`（没有就是 `None`）。
    /// 剧本用完就关连接。
    async fn fake_proxy(
        mut sock: tokio::io::DuplexStream,
        replies: Vec<String>,
        seen: Arc<Mutex<Vec<Option<String>>>>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for reply in replies {
            let mut req = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                match sock.read(&mut byte).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => req.push(byte[0]),
                }
                if req.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&req).to_string();
            let auth = text.lines().find_map(|l| {
                let (name, value) = l.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("proxy-authorization")
                    .then(|| value.trim().to_string())
            });
            seen.lock().unwrap().push(auth);
            if sock.write_all(reply.as_bytes()).await.is_err() {
                return;
            }
        }
    }

    /// 端到端探针：真实的 [`SspiProxyAuthenticator`]、真实的
    /// `http_connect`、一台 duplex 上的假代理。返回 CONNECT 的结果与代理
    /// 逐条看到的 `Proxy-Authorization`（`seen.len()` 就是实际发了几次
    /// CONNECT）。
    async fn connect_through_proxy(
        auth: &SspiProxyAuthenticator<SspiContextFactory>,
        replies: &[&str],
    ) -> (rmc_core::Result<()>, Vec<Option<String>>) {
        let (mut client, server) = tokio::io::duplex(8192);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let proxy = tokio::spawn(fake_proxy(
            server,
            replies.iter().map(|r| (*r).to_string()).collect(),
            Arc::clone(&seen),
        ));
        let target: HostPort = "gateway.company.com:443".parse().unwrap();
        let outcome = rmc_core::transport::connect::http_connect(&mut client, &target, auth).await;
        drop(client);
        let _ = proxy.await;
        let seen = seen.lock().unwrap().clone();
        (outcome, seen)
    }

    /// 两种拒绝形状共用的断言：**3 次 CONNECT、1 个安全上下文、2 段协商**，
    /// 结局是 `Completed`，诊断行说的是"代理不接受当前用户"。
    fn assert_refused_after_two_legs(
        outcome: rmc_core::Result<()>,
        seen: &[Option<String>],
        a: &SspiProxyAuthenticator<SspiContextFactory>,
        h: &Harness,
    ) {
        let err = outcome.unwrap_err();
        assert!(
            matches!(err, rmc_core::Error::ProxyAuthFailed(_)),
            "CONNECT 应当以代理认证失败告终：{err}"
        );
        assert_eq!(
            seen,
            [
                None,
                Some(format!("Negotiate {NEGOTIATE_B64}")),
                Some(format!("Negotiate {AUTHENTICATE_B64}")),
            ],
            "CONNECT 应当只发三次：无凭据一次、Type-1 一次、Type-3 一次"
        );
        assert_eq!(h.built().len(), 1, "一次连接尝试只该建一个安全上下文");
        assert_eq!(h.legs().len(), 2, "只该推进两段协商");
        assert_eq!(
            a.last_outcome(),
            AuthOutcome::Completed {
                package: SspiPackage::Negotiate,
                rounds: 2
            }
        );
        let l = a.last_outcome().line(ConnectOutcome::Failed);
        assert_eq!(l.verdict, Verdict::Fail);
        assert!(l.detail.contains("不接受当前用户"), "{}", l.detail);
        assert!(
            !l.detail.contains("协商还要继续"),
            "CONNECT 已经确定失败了，不能对现场工程师说协商还要继续：{}",
            l.detail
        );
    }

    #[tokio::test]
    async fn a_407_carrying_a_token68_after_the_final_leg_is_a_refusal() {
        // 形状 A：代理拒绝时回的 407 **带着** token68。这一格在修复轮 1
        // 就已经是对的，留成常驻测试是为了跟形状 B 成对——两种真实形状
        // 必须给出同一个结论。
        let (a, h) = scripted(endpoint(), Ending::FinalOnSecondLeg);
        let refusal = challenge_407();
        // 备满 MAX_ROUNDS 条应答：万一哪天又退回"裸 407 算新一轮"的老
        // 样子，这里断言的是**实际发生了几次 CONNECT**，而不是让协商撞上
        // EOF 换回一个看不出所以然的 Tcp 错误。
        let replies = [BARE_407, &refusal, &refusal, &refusal, &refusal];
        let (outcome, seen) = connect_through_proxy(&a, &replies).await;
        assert_refused_after_two_legs(outcome, &seen, &a, &h);
    }

    #[tokio::test]
    async fn a_bare_407_after_the_final_leg_is_a_refusal_too() {
        // ★ 形状 B，W45 的正题：代理拒绝时回的 407 是**裸的**
        // `Proxy-Authenticate: Negotiate`——NTLM 拒绝 Type-3 之后的标准
        // 写法，Negotiate 也常见。
        //
        // 修复轮 1 的实测：`TokenIssued { round: 1 }`、诊断是"协商还要
        // 继续"（而 CONNECT 已经确定失败）、**5 次 CONNECT、4 个完整的
        // 安全上下文**——域机器上就是 4 次 `AcquireCredentialsHandleW`
        // ＋ 4 次 `InitializeSecurityContextW`，每一次都可能去找域控。
        // 机理是裸 407 ⇒ token68 为 None ⇒ 被当成"新一轮开始"，
        // `*neg = Negotiation::default()` 把 `concluded` 一起清掉，
        // `Completed` 那一支永远撞不上。
        //
        // 改红：把 `http_connect` 里的 `auth.begin_connection().await;`
        // 删掉，再把 `advance` 的 `if !neg.started` 换回
        // `if challenge.is_none()`——就是修复轮 1 的那份代码。
        let (a, h) = scripted(endpoint(), Ending::FinalOnSecondLeg);
        let challenge = challenge_407();
        let replies = [BARE_407, &challenge, BARE_407, BARE_407, BARE_407];
        let (outcome, seen) = connect_through_proxy(&a, &replies).await;
        assert_refused_after_two_legs(outcome, &seen, &a, &h);
    }

    #[tokio::test]
    async fn a_second_connect_attempt_negotiates_from_scratch_end_to_end() {
        // ★ W2 的端到端那一半：第一条连接被代理拒了，Supervisor 重连，
        // 第二条连接必须从一个**全新的**安全上下文重新协商（Negotiate 与
        // NTLM 都是连接绑定的，接着用上一条连接那个，服务端会认成另一个
        // 客户端）。
        //
        // 改红：把 `http_connect` 里的 `auth.begin_connection().await;`
        // 删掉——第二条连接的第一个裸 407 会撞上"协商途中代理不再给
        // challenge"那一支，`http_connect` 报 ProxyAuthFailed，200 永远
        // 等不到。
        let (a, h) = scripted(endpoint(), Ending::FinalOnSecondLeg);
        let challenge = challenge_407();

        let replies = [BARE_407, &challenge, BARE_407, BARE_407, BARE_407];
        let (first, _) = connect_through_proxy(&a, &replies).await;
        assert!(first.is_err());

        // 第二条连接：同样两段，这一次代理放行。
        let replies = [BARE_407, &challenge, OK_200];
        let (second, seen) = connect_through_proxy(&a, &replies).await;
        second.expect("重连之后必须能重新协商并打通隧道");
        assert_eq!(
            seen,
            [
                None,
                Some(format!("Negotiate {NEGOTIATE_B64}")),
                Some(format!("Negotiate {AUTHENTICATE_B64}")),
            ]
        );
        assert_eq!(h.built().len(), 2, "两条连接各自一个上下文");
        assert_eq!(
            h.legs().last().unwrap().ctx_id,
            1,
            "第二条连接必须跑在新建的那个上下文上"
        );
        assert_eq!(
            a.last_outcome(),
            AuthOutcome::FinalTokenIssued {
                package: SspiPackage::Negotiate,
                rounds: 2
            }
        );
    }

    // =================================================================
    // W173：诊断页要的那句话，经 `ProxyAuthenticator::auth_summary` 出去
    // =================================================================

    /// **经 `dyn ProxyAuthenticator` 拿到的结局，跟 `last_outcome()` 说的
    /// 是同一件事。**
    ///
    /// 断的是哪一根线：`AuthOutcome::summary()` 那张转抄表有自己的穷尽
    /// 测试，rmc-core 那边 `Transport::last_proxy()` 会去调
    /// `auth_summary()`，**中间这一个 `impl` 两头都没人守**。把
    /// `auth_summary` 的实现删掉，trait 上的默认实现会接手、恒定返回
    /// `NotAttempted`——诊断页上「代理认证」那一行于是永远写着"代理没有
    /// 要求认证"，哪怕这次连接就是卡在代理认证上。那种情况下
    /// **`cargo test --workspace` 一条都不红**，所以有这条。
    ///
    /// 刻意经 `&dyn ProxyAuthenticator` 调用：直接写 `a.auth_summary()`
    /// 在固有方法与 trait 方法之间解析得到同一份，证明不了"默认实现被
    /// 盖掉了"。
    #[tokio::test]
    async fn the_summary_reaches_the_core_through_the_trait_object() {
        let a = SspiProxyAuthenticator::new(endpoint(), |_: SspiPackage, _: &str| None);
        let obj: &dyn ProxyAuthenticator = &a;

        // 反向自证：还没被要求过认证时，两边都说"没协商过"。
        assert_eq!(obj.auth_summary(), ProxyAuthSummary::NotAttempted);
        assert_eq!(a.last_outcome().summary(), ProxyAuthSummary::NotAttempted);

        // 走一次本机不做的认证方式，结局离开 `NotAttempted`。
        obj.begin_connection().await;
        assert!(obj.next_token("Basic", None).await.is_none());

        assert_eq!(
            obj.auth_summary(),
            ProxyAuthSummary::UnsupportedScheme("Basic".into()),
            "trait 上的默认实现没被盖掉，诊断页会永远说「代理没有要求认证」"
        );
        assert_eq!(
            obj.auth_summary(),
            a.last_outcome().summary(),
            "两个出口对不上"
        );
    }
}
