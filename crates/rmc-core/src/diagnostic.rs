//! 诊断页「代理认证」那一行的**平台中立**判断与文案。
//!
//! # 为什么这个类型住在 rmc-core，而不是 rmc-win（W158）
//!
//! `rmc-win` 是 rmc-app 的 **`cfg(windows)` 专属依赖**
//! （`crates/rmc-app/Cargo.toml` 的 `[target.'cfg(windows)'.dependencies]`）。
//! 于是历史裁决 W38 要求的那张「CONNECT 结果 × `last_outcome()`」完整映射
//! 如果写在 rmc-app 里，就只能写在 `#[cfg(windows)]` 里——而那一层在本项目
//! 的闸门下**按构造检测不到任何还能编译的语义改动**：闸门 5 是
//! `cargo zigbuild`（只编译），闸门 6 是 `cargo-zigbuild clippy`（只静态
//! 检查），**两道都不跑测试**。Task 5 已经用八枪实测过这一点，连把
//! `Box::leak` 换成悬垂栈指针都六道全绿。
//!
//! 所以这张表搬到这里：
//!
//! - **rmc-core**（本模块）：[`ProxyAuthSummary`] 这个平台中立的枚举，
//!   以及「结局 × CONNECT 结果 → 诊断行」那张表。macOS 上 `cargo test`
//!   每一次都跑到。
//! - **rmc-win**：只剩一次转抄——`AuthOutcome::summary()` 把自己映射成
//!   [`ProxyAuthSummary`]。rmc-win 的纯逻辑层在 macOS 上也编译、也测，
//!   那条转抄因此同样跑得到（`sspi.rs` 的
//!   `every_auth_outcome_transcribes_into_its_own_summary`）。
//! - **rmc-app**：`diag::rows` 直接调 [`ProxyAuthSummary::line`]，不认识
//!   `AuthOutcome`，也不需要认识。
//!
//! # 为什么文案在这里而不是在界面 crate 里
//!
//! 跟 [`crate::wording`] 与 [`crate::preflight::ALL_STEPS`] 同一个理由
//! （W125）：**rmc-core 的用户可见字符串就是界面文案的一部分**，禁用词
//! 扫描只有在这一层才看得见它们。把这几句话搬到 rmc-app 去，就等于让
//! rmc-win 那边留下一份说着相近意思的副本，两份迟早漂移——W164 要收拾的
//! 正是这种漂移。

use crate::addr::HostPort;

/// 诊断页一行的结论。
///
/// **不是 `Option<bool>`。** `Option<bool>` 在这个项目里已经是第五次
/// 被点名的形状（`resolve()`、`next_token()`、`load()`、`validate()`）：
/// 读的人无从知道 `None` 是「还没轮到」还是「查了但没结论」，也无从知道
/// `Some(false)` 是「失败」还是「不适用」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// 这一步过了。
    Pass,
    /// 这一步失败了。界面上要标红。
    Fail,
    /// **还没有结论**：这一步没跑，或者结论不在这一层。
    Undecided,
}

impl Verdict {
    /// 这一行要不要标红。
    ///
    /// 做成方法而不是 `DiagRow` 上的一个 `highlight: bool` 字段：字段可以
    /// 跟 `verdict` 写得不一致（构造的地方少写一个取反就够了），而没有
    /// 任何东西看得出来。方法只有一个真相来源。
    pub fn highlight(self) -> bool {
        matches!(self, Verdict::Fail)
    }
}

/// 经代理的那次 HTTP CONNECT 成没成。
///
/// 这是 W38 那张表的第二根轴。少了它，协商器只知道「自己发出了什么」——
/// 「代理接受了」这件事只有拿到 200 的 `http_connect` 知道，两边合起来
/// 才是诊断页上那一行的结论。W38 当初点名的缺格正是
/// 「CONNECT 失败 + [`ProxyAuthSummary::TokenIssued`]」，也就是现场
/// 最常见的那一种失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// CONNECT 拿到了 200，隧道已经穿过代理。
    Established,
    /// CONNECT 没有建立。
    Failed,
}

/// 这次连接**实际经过了什么**：直连，还是某一台代理。
///
/// # W173：界面不许自己去查代理，这条信息由内核送上来
///
/// `Transport::effective_proxy` 被文档标成「供预检与界面显示使用」，但
/// rmc-win 的 `ProxyEndpointRecorder` 上写明了它的代价：界面每重画一帧
/// 就查一次，会在一次协商进行到一半时改写协商器用来拼 SPN 的那一格，
/// 而**没有任何测试会因此变红**。rmc-app 那边有一道源码扫描
/// （`this_crate_never_polls_the_transport_for_the_current_proxy`）把
/// 「界面自己去查」整条路封死了，那么界面要显示的代理就必须有另一条
/// 来路——就是这个类型，经 [`crate::state::TunnelEvent::Proxy`] 送上去。
///
/// # 为什么不是 `Option<HostPort>` + 一个 `ConnectOutcome`
///
/// 直连时**根本没有 CONNECT 这回事**。压成一对字段，构造的地方就必须给
/// 「直连时的 CONNECT 结果」编一个值出来，而界面拿到那个编出来的值会
/// 照样画进「代理 CONNECT」那一行。这是本项目同一个缺陷类的第七次，
/// 解法跟前六次一样：**带类型的出口**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyObservation {
    /// 这次判定直连，没有经过任何代理。
    Direct,
    /// 这次经过了这台代理。
    Via {
        endpoint: HostPort,
        /// 经这台代理的那次 HTTP CONNECT 成没成。
        connect: ConnectOutcome,
        /// 代理认证协商的结局。平台中立，来自
        /// [`crate::platform::ProxyAuthenticator::auth_summary`]。
        auth: ProxyAuthSummary,
    },
}

/// 诊断页上「代理认证」那一行的**行首文字**。
///
/// 做成常量是为了让 `transport::connect` 的错误文案能指向它，而
/// rmc-app 的测试又能断言诊断页真的画着这个名字的一行（W164）。
/// 有人把行名改了而没改错误文案，那条指路就成了死指针——
/// `rmc_app::diag` 的 `the_error_text_points_at_a_row_the_page_really_draws`
/// 会变红。
pub const PROXY_AUTH_ROW: &str = "代理认证";

/// 诊断页上「代理认证」那一行的内容。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAuthLine {
    pub verdict: Verdict,
    pub detail: String,
}

/// 声明 [`ProxyAuthSummary`]，顺带数出变体个数。
///
/// 手法与 rmc-win 的 `declare_auth_outcome!` 相同，理由也相同：让
/// 「表漏了一格」从一条会绿的测试变成 `error[E0308]: expected an array
/// with a size of N`。`std::mem::variant_count` 至今仍是 unstable，只能
/// 让宏从变体列表里数。
///
/// **刻意没有把 rmc-win 那个宏提出来共用**：那要么让 rmc-core 导出一个
/// 只为测试存在的 `#[macro_export]`（污染 rmc-core 的公开面），要么让
/// rmc-win 反过来依赖一个宏的展开细节。两个宏各三十行、各自钉住自己那个
/// 枚举，比一个跨 crate 的宏便宜。代价写在这里：往任何一个枚举里加变体
/// 都要记得另一个也加——而那正是
/// `every_auth_outcome_transcribes_into_its_own_summary` 守的事。
macro_rules! declare_proxy_auth_summary {
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
            /// 全部变体的名字，按声明顺序。由声明宏生成。
            pub const VARIANT_NAMES: &'static [&'static str] = &[$(stringify!($variant)),*];

            /// 变体总数。诊断表的长度必须是它的两倍（两个 CONNECT 结果各一格）。
            pub const VARIANTS: usize = Self::VARIANT_NAMES.len();

            /// 这是哪一个变体。只用来把断言失败的信息说清楚，不参与判断。
            pub fn variant_name(&self) -> &'static str {
                match self {
                    $( Self::$variant { .. } => stringify!($variant) ),*
                }
            }
        }
    };
}

declare_proxy_auth_summary! {
    /// 一次（或一段）代理认证协商的结局，**平台中立**。
    ///
    /// 这是 `rmc_win::sspi::AuthOutcome` 的镜像：变体一一对应，只是把
    /// `SspiPackage` 换成了它的 `package_name()`（一个 `&'static str`
    /// 拷成的 `String`），好让 rmc-core 不必认识任何 Windows 概念。
    ///
    /// **不带任何一段 token、任何一个凭据**，跟被镜像的那一个一样。
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub enum ProxyAuthSummary {
        /// 这个进程还没被任何代理要求过认证。
        #[default]
        NotAttempted,
        /// 代理要求的认证方式本机不做（Basic/Digest）。带的是方式名，
        /// 不是任何凭据，且来源侧已经截断过（rmc-win 的 `bounded_scheme`）。
        UnsupportedScheme(String),
        /// 不知道当前经过哪个代理，SPN 构造不出来。
        UnknownProxyEndpoint,
        /// 代理给的 challenge 不是合法 base64。**不带原文**。
        MalformedChallenge,
        /// 收到 challenge，但本机这边没有正在进行的协商。
        ChallengeWithoutNegotiation,
        /// 建不出安全上下文：机器不在域里、包不可用、当前用户没有凭据。
        ContextUnavailable {
            /// 安全包名，形如 `Negotiate` / `NTLM`。
            package: String,
        },
        /// 已经发出第 `round` 段 token，而且协商还要继续。
        TokenIssued { package: String, round: usize },
        /// **最后一段** token 已经发出（共 `rounds` 段），等代理裁决。
        FinalTokenIssued { package: String, rounds: usize },
        /// 本机这边的协商已经走完，没有 token 可发了。
        Completed { package: String, rounds: usize },
        /// 协商失败。`detail` 只有状态码与原因。
        Failed {
            package: String,
            round: usize,
            detail: String,
        },
    }
}

fn line(verdict: Verdict, detail: impl Into<String>) -> ProxyAuthLine {
    ProxyAuthLine {
        verdict,
        detail: detail.into(),
    }
}

/// 一句「协商没成」的话，配上 CONNECT 的结果。
///
/// CONNECT **已经建立**而协商结局却是个失败，这不是矛盾、也不是 bug：
/// `last_outcome()` 报的是这个进程最近一次协商的结局，而
/// `begin_connection()` 每条新连接才清一次状态。所以这种组合的真相是
/// 「这条记录来自更早的一次尝试」，必须如实说出来，不能假装没看见——
/// 假装没看见就会让现场工程师对着一条已经连上的链路排查一个早就过去的
/// 故障。
fn stale_if_connected(base: String, connect: ConnectOutcome) -> ProxyAuthLine {
    match connect {
        ConnectOutcome::Failed => line(Verdict::Fail, base),
        ConnectOutcome::Established => line(
            Verdict::Fail,
            format!("{base}；但本次 CONNECT 已经建立，这条结局来自同一进程更早的一次尝试"),
        ),
    }
}

impl ProxyAuthSummary {
    /// 诊断页「代理认证」那一行：结论 + 说明文字。
    ///
    /// # W38：`connect` 这根轴不能省
    ///
    /// 协商器只知道自己发出了什么。「代理接受了」这件事只有拿到 200 的
    /// `http_connect` 知道。所以
    /// [`ProxyAuthSummary::TokenIssued`] / [`ProxyAuthSummary::FinalTokenIssued`]
    /// 这两格**本身不是结论**，必须跟 CONNECT 的结果合起来才是。W38 当初
    /// 点名缺的那一格正是「CONNECT 失败 + `TokenIssued`」——现场最常见的
    /// 那一种失败。
    ///
    /// 全部 `VARIANTS * 2` 格由
    /// `every_summary_and_connect_pair_has_its_own_verdict_and_its_own_words`
    /// 逐格钉住，表写成定长数组，少一格就编译不过。
    pub fn line(&self, connect: ConnectOutcome) -> ProxyAuthLine {
        use ConnectOutcome::{Established, Failed};
        match (self, connect) {
            // --- 没被要求过认证 ---
            (Self::NotAttempted, Established) => {
                line(Verdict::Pass, "代理没有要求认证，CONNECT 直接建立")
            }
            (Self::NotAttempted, Failed) => line(
                Verdict::Undecided,
                "代理没有要求认证；这次没连上跟代理认证无关",
            ),

            // --- 协商还在半路 ---
            (Self::TokenIssued { package, round }, Established) => line(
                Verdict::Pass,
                format!("{package} 协商发到第 {round} 段时代理放行，CONNECT 已建立"),
            ),
            // ★ W38 当初缺的就是这一格。
            (Self::TokenIssued { package, round }, Failed) => line(
                Verdict::Fail,
                format!(
                    "已向代理发出第 {round} 段 {package} token，协商还没走完，\
                     CONNECT 就没了——多半是代理或链路在协商途中断开"
                ),
            ),

            // --- 最后一段已发出 ---
            (Self::FinalTokenIssued { package, rounds }, Established) => line(
                Verdict::Pass,
                format!("{package} 协商 {rounds} 段走完，代理放行，CONNECT 已建立"),
            ),
            (Self::FinalTokenIssued { package, rounds }, Failed) => line(
                Verdict::Fail,
                format!(
                    "{package} 协商的最后一段 token 已发出（共 {rounds} 段），\
                     代理仍不放行——凭据格式没问题，是代理不接受当前用户"
                ),
            ),

            // --- 下面七格是「协商这一步自己就没成」，CONNECT 那根轴只
            //     决定要不要补一句「这条记录已经过期了」。---
            (Self::UnsupportedScheme(scheme), c) => stale_if_connected(
                format!("代理要求 {scheme} 认证，本机只做 Negotiate 与 NTLM"),
                c,
            ),
            (Self::UnknownProxyEndpoint, c) => stale_if_connected(
                "代理要求认证，但当前链路没有记录到代理地址，无法构造 SPN".to_string(),
                c,
            ),
            (Self::MalformedChallenge, c) => stale_if_connected(
                "代理返回的 challenge 不是合法的 base64，协商无法继续".to_string(),
                c,
            ),
            (Self::ChallengeWithoutNegotiation, c) => stale_if_connected(
                "代理在没有在途协商的情况下送来 challenge，协商状态不一致".to_string(),
                c,
            ),
            (Self::ContextUnavailable { package }, c) => stale_if_connected(
                format!("无法建立 {package} 安全上下文，请确认本机已加入域且当前用户已登录"),
                c,
            ),
            (Self::Completed { package, rounds }, c) => stale_if_connected(
                format!(
                    "{package} 协商在 {rounds} 段之后走完，代理仍要求认证——\
                     凭据格式没问题，是代理不接受当前用户"
                ),
                c,
            ),
            (
                Self::Failed {
                    package,
                    round,
                    detail,
                },
                c,
            ) => stale_if_connected(format!("{package} 协商在第 {round} 段失败：{detail}"), c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn a_verdict_highlights_only_when_it_failed() {
        assert!(Verdict::Fail.highlight());
        assert!(!Verdict::Pass.highlight());
        assert!(
            !Verdict::Undecided.highlight(),
            "「还没轮到」被标红，等于在没跑过预检的机器上报一屏假故障"
        );
    }

    /// W38 的那张表，两根轴都在：`VARIANTS` 个结局 × 两个 CONNECT 结果。
    ///
    /// # 为什么写成定长数组
    ///
    /// 上一版（rmc-win 的 `AuthOutcome::diagnostic`）的表只有一根轴，而且
    /// 长度靠 `AuthOutcome::VARIANTS` 钉住。这里把长度写成
    /// `ProxyAuthSummary::VARIANTS * 2`：往枚举里加一个变体，这张表立刻
    /// `error[E0308]: expected an array with a size of N`，**编译不过**，
    /// 而不是绿着骗人。
    ///
    /// # 改实现的哪一行会让它红
    ///
    /// - 把 `TokenIssued + Failed` 那一格的 `Verdict::Fail` 改成
    ///   `Verdict::Undecided`（也就是退回 W38 之前「协商器不下结论」的
    ///   写法）→ 该格的 verdict 对不上；
    /// - 把 `stale_if_connected` 里 `Established` 那一支的附言删掉 →
    ///   「二十句话两两不同」那条红（七个失败结局的两格会各自撞上）；
    /// - 任意一格的文案清空 → 关键词那条红；
    /// - 给 `ProxyAuthSummary` 加一个变体不动表 → 编译不过。
    #[test]
    fn every_summary_and_connect_pair_has_its_own_verdict_and_its_own_words() {
        let neg = || "Negotiate".to_string();
        let cases: [(ProxyAuthSummary, ConnectOutcome, Verdict, &str);
            ProxyAuthSummary::VARIANTS * 2] = [
            (
                ProxyAuthSummary::NotAttempted,
                ConnectOutcome::Established,
                Verdict::Pass,
                "代理没有要求认证",
            ),
            (
                ProxyAuthSummary::NotAttempted,
                ConnectOutcome::Failed,
                Verdict::Undecided,
                "跟代理认证无关",
            ),
            (
                ProxyAuthSummary::UnsupportedScheme("Basic".into()),
                ConnectOutcome::Established,
                Verdict::Fail,
                "更早的一次尝试",
            ),
            (
                ProxyAuthSummary::UnsupportedScheme("Basic".into()),
                ConnectOutcome::Failed,
                Verdict::Fail,
                "代理要求 Basic 认证",
            ),
            (
                ProxyAuthSummary::UnknownProxyEndpoint,
                ConnectOutcome::Established,
                Verdict::Fail,
                "更早的一次尝试",
            ),
            (
                ProxyAuthSummary::UnknownProxyEndpoint,
                ConnectOutcome::Failed,
                Verdict::Fail,
                "无法构造 SPN",
            ),
            (
                ProxyAuthSummary::MalformedChallenge,
                ConnectOutcome::Established,
                Verdict::Fail,
                "更早的一次尝试",
            ),
            (
                ProxyAuthSummary::MalformedChallenge,
                ConnectOutcome::Failed,
                Verdict::Fail,
                "base64",
            ),
            (
                ProxyAuthSummary::ChallengeWithoutNegotiation,
                ConnectOutcome::Established,
                Verdict::Fail,
                "更早的一次尝试",
            ),
            (
                ProxyAuthSummary::ChallengeWithoutNegotiation,
                ConnectOutcome::Failed,
                Verdict::Fail,
                "协商状态不一致",
            ),
            (
                ProxyAuthSummary::ContextUnavailable { package: neg() },
                ConnectOutcome::Established,
                Verdict::Fail,
                "更早的一次尝试",
            ),
            (
                ProxyAuthSummary::ContextUnavailable { package: neg() },
                ConnectOutcome::Failed,
                Verdict::Fail,
                "请确认本机已加入域",
            ),
            (
                ProxyAuthSummary::TokenIssued {
                    package: neg(),
                    round: 1,
                },
                ConnectOutcome::Established,
                Verdict::Pass,
                "代理放行",
            ),
            // ★ W38 当初缺的那一格：现场最常见的失败。
            (
                ProxyAuthSummary::TokenIssued {
                    package: neg(),
                    round: 1,
                },
                ConnectOutcome::Failed,
                Verdict::Fail,
                "协商还没走完",
            ),
            (
                ProxyAuthSummary::FinalTokenIssued {
                    package: "NTLM".into(),
                    rounds: 2,
                },
                ConnectOutcome::Established,
                Verdict::Pass,
                "代理放行",
            ),
            (
                ProxyAuthSummary::FinalTokenIssued {
                    package: "NTLM".into(),
                    rounds: 2,
                },
                ConnectOutcome::Failed,
                Verdict::Fail,
                "是代理不接受当前用户",
            ),
            (
                ProxyAuthSummary::Completed {
                    package: neg(),
                    rounds: 3,
                },
                ConnectOutcome::Established,
                Verdict::Fail,
                "更早的一次尝试",
            ),
            (
                ProxyAuthSummary::Completed {
                    package: neg(),
                    rounds: 3,
                },
                ConnectOutcome::Failed,
                Verdict::Fail,
                "代理仍要求认证",
            ),
            (
                ProxyAuthSummary::Failed {
                    package: neg(),
                    round: 2,
                    detail: "域拒绝了这次登录（SEC_E_LOGON_DENIED）".into(),
                },
                ConnectOutcome::Established,
                Verdict::Fail,
                "更早的一次尝试",
            ),
            (
                ProxyAuthSummary::Failed {
                    package: neg(),
                    round: 2,
                    detail: "域拒绝了这次登录（SEC_E_LOGON_DENIED）".into(),
                },
                ConnectOutcome::Failed,
                Verdict::Fail,
                "SEC_E_LOGON_DENIED",
            ),
        ];

        // 数组长度已经由编译器钉住。这里再把**是哪些变体**对上——数量对
        // 而某一格写了两遍、另一格没写，会在这里当场说出漏的是谁。
        let listed: BTreeSet<&str> = cases.iter().map(|(s, _, _, _)| s.variant_name()).collect();
        let declared: BTreeSet<&str> = ProxyAuthSummary::VARIANT_NAMES.iter().copied().collect();
        assert_eq!(
            listed,
            declared,
            "表里漏了这些变体：{:?}",
            declared.difference(&listed).collect::<Vec<_>>()
        );
        // 两根轴都要真的被走到：每个变体恰好出现两次。
        for name in ProxyAuthSummary::VARIANT_NAMES {
            let n = cases
                .iter()
                .filter(|(s, _, _, _)| s.variant_name() == *name)
                .count();
            assert_eq!(
                n, 2,
                "{name} 在表里出现了 {n} 次，应当是两次（两个 CONNECT 结果各一次）"
            );
        }

        for (summary, connect, want, keyword) in &cases {
            let got = summary.line(*connect);
            assert_eq!(
                got.verdict,
                *want,
                "{} × {connect:?} 的结论不对：{got:?}",
                summary.variant_name()
            );
            assert!(
                got.detail.contains(keyword),
                "{} × {connect:?} 的说明里没有「{keyword}」：{}",
                summary.variant_name(),
                got.detail
            );
        }

        // 二十句话两两不同：两格给出同一句话，等于现场工程师看到的还是
        // 同一条信息，这根轴就白加了。
        let texts: BTreeSet<String> = cases.iter().map(|(s, c, _, _)| s.line(*c).detail).collect();
        assert_eq!(texts.len(), cases.len(), "有两格给出了同一句话");
    }

    /// 结局里带的字串来自代理响应头，长度不受我们控制；诊断行必须有界。
    ///
    /// 规范见 `knownhosts::tests::damaged_line_error_message_is_bounded_in_length`。
    /// **这一条守的是「本模块不会把已经截断过的东西再放大」**——真正的
    /// 截断在 rmc-win 的 `bounded_scheme` 里，那边有自己的测试。
    #[test]
    fn a_line_does_not_blow_up_a_bounded_scheme_any_further() {
        let scheme = "x".repeat(900);
        let l = ProxyAuthSummary::UnsupportedScheme(scheme.clone()).line(ConnectOutcome::Failed);
        assert!(l.detail.contains("xxxx"), "至少要保留可读的一部分");
        assert!(
            l.detail.len() < scheme.len() + 200,
            "文案在 scheme 之外还加了 {} 字节",
            l.detail.len() - scheme.len()
        );
    }
}
