//! 托盘提示与系统通知——**全部判断**都在这里。
//!
//! 只在真正需要现场人员知道时弹通知：远程会话起止、一体机不可达、连接
//! 失败。重连抖动不弹（现场网络抖一下很常见，弹通知是骚扰）。
//!
//! # 两层划分
//!
//! 这个模块一行 `#[cfg]` 都没有。Win32 那一半在
//! [`rmc_win::tray`]——它只认识「一段文本」「一张 RGBA 图」，不认识
//! [`Model`]，也就不可能在里面藏一条判断。
//!
//! 理由是 Task 5 那八枪：`#[cfg(windows)]` 那一层里**任何还能编译的语义
//! 改动，本项目的六道闸门按构造检测不到**（闸门 5 只编译、闸门 6 只静态
//! 检查，两道都不跑测试）。所以颜色、文案、截断、要不要弹，一律挤到这
//! 一层来，在这台 macOS 上被真的跑到。
//!
//! # W193：出口带类型
//!
//! brief 给的是 `notification_for(..) -> Option<(String, String)>`。
//! 两个裸 `String` 的元组**说不出哪个是标题哪个是正文**（写反了照样
//! 编译、照样弹，只是标题栏上是一整段说明），而 `Option` 又把「没什么
//! 值得通知」与「有变化但按策略压住了」压平。
//!
//! 这是同一个缺陷类在本项目里的**第七次**（前六次：Task 2 的
//! `resolve()`、Task 3 的 `next_token()`、Task 4 的 `load()`、Task 8 的
//! `validate()`、Task 9 的 `advice_for()`、Task 10 的 `parse_line()` /
//! `tail()`）。六次的解法都是带类型的出口，这次也一样：
//! [`Notification`] 具名字段、[`Notify`] 三个变体。
//!
//! brief 的 `sessions_delta: i64` 同样压平：它把「开了几个」与「关了
//! 几个」压成一个数，而通知文案要分开说——**同一拍里一开一关会算成 0**，
//! 什么都不弹。改成 [`SessionDelta`] 两个计数，由
//! [`SessionDelta::between`] 按会话 id 算出来。

use crate::model::Model;
use crate::WINDOW_TITLE;
use rmc_core::state::{RemoteSessionInfo, State};

/// 托盘图标的边长，像素。跟 [`rmc_win::tray::ICON_SIDE`] 是同一个数，
/// 下面有一条编译期断言钉着。
pub const ICON_SIDE: usize = 16;

const _: () = assert!(
    ICON_SIDE == rmc_win::tray::ICON_SIDE,
    "图标边长跟 Win32 那一侧对不上，CreateIcon 会读到缓冲之外"
);

/// 悬停提示最多几个 UTF-16 码元。
///
/// `NOTIFYICONDATAW::szTip` 是 `[u16; 128]`，末尾要留一个 NUL，所以是
/// 127。[`rmc_win::tray::wide`] 自己也会兜底截断（那是内存安全的最后
/// 一道），但**在这一层截**才能带上省略号，让用户看得出后面还有字。
pub const TOOLTIP_LIMIT: usize = rmc_win::tray::TIP_CAP - 1;

/// 托盘图标的颜色：就是状态卡上那个圆点的颜色。
///
/// # W194：**一个来源**，不另写一张表
///
/// [`Model::status_card`] 已经对 `State` 的每一个变体给过颜色了，而
/// `model.rs` 有一条穷尽的表驱动测试守着它。在这里另写一个
/// `match state { .. }` 等于造第二份真相：两张表分叉之后，托盘是橙的而
/// 窗口里是绿的，没有任何东西看得出来。
///
/// brief 的测试只碰了 `Idle` 与 `Connected { degraded: true }` 两格。
/// 本模块的 [`tests::the_tray_has_a_colour_and_a_tooltip_for_every_state`]
/// 走**全部八种显示分支**，而且是定长表——少一格编译不过。
pub fn icon_color(model: &Model) -> iced::Color {
    model.status_card().dot
}

/// 悬停提示：产品名 + 状态标题 + 状态副标题。
///
/// 三行合一行（中间用换行），因为通知区的提示气泡是多行的，而副标题
/// 正是「现在到底怎么了」那句话——只写标题的话，`Failed` 状态下托盘上
/// 只有「连接失败」四个字，用户还得把窗口翻出来才知道失败在哪儿。
///
/// 产品名用 [`WINDOW_TITLE`]，不另起一个英文名：需求硬禁令只禁
/// Gateway/网关，但多一个名字就是多一处要同步的文案。
pub fn tooltip(model: &Model) -> String {
    let c = model.status_card();
    clamp_utf16(
        &format!("{WINDOW_TITLE} — {}\n{}", c.title, c.subtitle),
        TOOLTIP_LIMIT,
    )
}

/// 截到最多 `limit` 个 UTF-16 码元，截过就在结尾加一个省略号。
///
/// 按 `char` 走，所以永远不会把一个字符（更不会把一个代理对）切一半。
fn clamp_utf16(text: &str, limit: usize) -> String {
    if text.encode_utf16().count() <= limit {
        return text.to_string();
    }
    // 省略号自己占一个码元，所以有效额度是 limit - 1。
    let budget = limit.saturating_sub(1);
    let mut out = String::new();
    let mut used = 0usize;
    for ch in text.chars() {
        let w = ch.len_utf16();
        if used + w > budget {
            break;
        }
        out.push(ch);
        used += w;
    }
    out.push('…');
    out
}

/// 一张 [`ICON_SIDE`] 见方的实心圆点，RGBA、逐行从上到下。
///
/// 圆点画在纯逻辑层（brief 把它放在 `#[cfg(windows)]` 里）：这里每一个
/// 像素都是算出来的，而算错的表现是「Windows 上托盘图标是个方块」或者
/// 「整张图透明」——两样在闸门 5/6 下都看不见。
pub fn icon_rgba(c: iced::Color) -> Vec<u8> {
    let side = ICON_SIDE;
    let mut out = Vec::with_capacity(side * side * 4);
    let center = (side as f32 - 1.0) / 2.0;
    // 半径留一个像素的余量，免得圆贴着边框。
    let radius = center - 1.0;
    let (r, g, b) = (channel(c.r), channel(c.g), channel(c.b));
    for y in 0..side {
        for x in 0..side {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            if dx * dx + dy * dy <= radius * radius {
                out.extend_from_slice(&[r, g, b, 0xff]);
            } else {
                out.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    out
}

/// 0.0-1.0 的一个通道变成 0-255。**先夹再乘**：`iced::Color` 的字段是
/// 裸 `f32`，`as u8` 对越界值是静默饱和/未定义方向的转换。
fn channel(v: f32) -> u8 {
    (v.clamp(0.0, 1.0) * 255.0).round() as u8
}

/// 远程会话数在这一拍里的变化。
///
/// **不是一个 `i64`**（W193）：brief 的 `sessions_delta` 把「开了几个」
/// 与「关了几个」压成一个数，于是同一拍里一开一关变成 0，两条都不弹；
/// 而这恰恰是现场最要紧的一拍（上一个工程师断开、下一个接进来）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionDelta {
    pub opened: u32,
    pub closed: u32,
}

impl SessionDelta {
    /// 两份会话列表之间的差。**按会话 id 比，不是比个数**——个数相同
    /// 而 id 全换了，是「一个断开、一个接入」，不是「什么都没发生」。
    pub fn between(prev: &[RemoteSessionInfo], next: &[RemoteSessionInfo]) -> Self {
        let before: std::collections::BTreeSet<u64> = prev.iter().map(|s| s.id).collect();
        let after: std::collections::BTreeSet<u64> = next.iter().map(|s| s.id).collect();
        Self {
            opened: after.difference(&before).count() as u32,
            closed: before.difference(&after).count() as u32,
        }
    }

    pub fn is_quiet(&self) -> bool {
        self.opened == 0 && self.closed == 0
    }
}

/// 一条要弹给现场人员的通知。
///
/// 具名字段，不是 `(String, String)`（W193）：两个裸 `String` 说不出
/// 哪个是标题、哪个是正文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub title: String,
    pub body: String,
}

/// 「这一拍要不要弹通知」的结论。
///
/// 三个变体，不是一个 `Option`（W193）：
///
/// - [`Notify::Nothing`]：没有任何值得说的变化（绝大多数拍）；
/// - [`Notify::Suppressed`]：**有**变化，但按策略刻意不弹——日志里
///   因此说得出「为什么没弹」，而不是跟「什么都没发生」混在一起；
/// - [`Notify::Show`]：弹这一条。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notify {
    Nothing,
    Suppressed { reason: &'static str },
    Show(Notification),
}

impl Notify {
    /// 要弹的那一条，`None` 表示这一拍不弹。给调用方用的便利出口——
    /// 它从变体里取值，所以**跟 [`Notify`] 结构上不可能分叉**。
    pub fn to_show(&self) -> Option<&Notification> {
        match self {
            Notify::Show(n) => Some(n),
            _ => None,
        }
    }
}

/// 压住重连通知的理由。现场网络抖一下很常见。
const BACKOFF_IS_TOO_NOISY: &str = "正在重连，网络抖动很常见，不打扰现场人员";

/// 这一拍要不要弹通知、弹什么。
///
/// 优先级：**会话起止 > 状态变化**。会话起止是现场人员最关心的一件事
/// （有人正在连他的设备），而状态变化那几条里最要紧的两条
/// （一体机不可达、连接失败）不会跟会话变化同时发生。
pub fn notification_for(prev: &State, next: &State, sessions: SessionDelta) -> Notify {
    if !sessions.is_quiet() {
        return Notify::Show(Notification {
            title: "远程维护".to_string(),
            body: session_body(sessions),
        });
    }

    match (prev, next) {
        // 隧道还在，但一体机连不上了。这是现场唯一需要动手的一条。
        (State::Connected { degraded: false }, State::Connected { degraded: true }) => {
            Notify::Show(Notification {
                title: "一体机不可达".to_string(),
                body: "隧道正常，但连不上一体机，请检查设备与网段".to_string(),
            })
        }
        (State::Connected { degraded: true }, State::Connected { degraded: false }) => {
            Notify::Show(Notification {
                title: "一体机已恢复".to_string(),
                body: "一体机重新可达，远程维护照常".to_string(),
            })
        }
        // 刚刚失败。`message` 原样来自 rmc-core，已经过 W125 那一轮的
        // 文案清理。**从 Failed 到 Failed 不再弹**：那是同一次失败。
        (p, State::Failed { message, .. }) if !matches!(p, State::Failed { .. }) => {
            Notify::Show(Notification {
                title: "远程维护失败".to_string(),
                body: message.clone(),
            })
        }
        // 退避重连：刻意不弹，但说得出为什么。
        (_, State::Backoff { .. }) => Notify::Suppressed {
            reason: BACKOFF_IS_TOO_NOISY,
        },
        _ => Notify::Nothing,
    }
}

/// 会话起止那条通知的正文。开与关**分开说**，同一拍里两样都有就说两句。
fn session_body(d: SessionDelta) -> String {
    match (d.opened, d.closed) {
        (0, 0) => String::new(),
        (n, 0) => format!("{n} 个远程会话已接入一体机"),
        (0, m) => format!("{m} 个远程会话已结束"),
        (n, m) => format!("{n} 个远程会话已接入一体机，另有 {m} 个已结束"),
    }
}

// =====================================================================
// 出口
// =====================================================================

/// 托盘的出口。Windows 上是真的通知区图标，别的平台上没有。
///
/// 收的是**已经算好的值**（一段提示文本、一个颜色、一条通知），
/// 实现里一条判断都不许有——判断全在本模块上面那些纯函数里。
pub trait TraySink: std::fmt::Debug {
    /// 换图标颜色与悬停提示。
    fn show_status(&self, tooltip: &str, color: iced::Color);
    /// 弹一条通知。
    fn show_notification(&self, n: &Notification);
}

/// 造一个托盘。
///
/// 写成**函数指针**而不是直接在 [`crate::App`] 里调一次
/// `wiring::open_tray()`：函数指针能在测试里换成一个假的，于是
/// 「`program()` 的 boot 真的把托盘装进了 `App`」这件事在 macOS 上是
/// 可观测的（见 `lib.rs` 的
/// `booting_the_program_installs_the_tray_the_factory_gives_it`）。
/// 否则那一根线跟 W177 那两枪一样，七道闸门全绿。
pub type TrayFactory = fn() -> Option<Box<dyn TraySink>>;

/// 这台机器上没有托盘。非 Windows 的 [`crate::wiring::open_tray`] 就是它，
/// 测试里也用它当「没托盘」那一档。
pub fn no_tray() -> Option<Box<dyn TraySink>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::color;
    use rmc_core::error::ErrorClass;
    use std::time::{Duration, SystemTime};

    fn model_in(s: State) -> Model {
        let mut m = Model::default();
        m.apply(rmc_core::state::TunnelEvent::State(s));
        m
    }

    fn session(id: u64) -> RemoteSessionInfo {
        RemoteSessionInfo {
            id,
            opened_at: SystemTime::UNIX_EPOCH,
            to_appliance: 0,
            from_appliance: 0,
        }
    }

    // ================= W194：八种显示分支，一格都不许漏 =================

    /// `State` 的**每一个**显示分支各一格。
    ///
    /// # 为什么这张表能证明自己没漏
    ///
    /// `case_index` 是一个**穷尽的 `match`**，没有 `_ =>` 兜底：往
    /// `State` 加一个变体，它当场编译不过；而表写成定长数组
    /// `[(State, Color, &str); CASES]`，少一格是
    /// `error[E0308]: expected an array with a size of 8`，同样编译不过。
    /// 形状照 Task 9 的 `row_palette` 那张表。
    ///
    /// brief 的两条测试只碰了 `Idle` 与 `Connected { degraded: true }`。
    ///
    /// 改红：把 `icon_color` 改成 `color::IDLE`（恒定灰）——托盘永远
    /// 不变色，这条当场红六格。
    #[test]
    fn the_tray_has_a_colour_and_a_tooltip_for_every_state() {
        const CASES: usize = 8;

        /// 八个显示分支各一格。**穷尽 match**：`State` 加变体就编译不过。
        fn case_index(s: &State) -> usize {
            match s {
                State::Idle => 0,
                State::Preflight => 1,
                State::Connecting => 2,
                State::Connected { degraded: false } => 3,
                State::Connected { degraded: true } => 4,
                State::Backoff { .. } => 5,
                State::Stopping => 6,
                State::Failed { .. } => 7,
            }
        }

        let table: [(State, iced::Color, &str); CASES] = [
            (State::Idle, color::IDLE, "未开启"),
            (State::Preflight, color::PROGRESS, "预检中"),
            (State::Connecting, color::PROGRESS, "正在连接"),
            (
                State::Connected { degraded: false },
                color::CONNECTED,
                "已连接",
            ),
            (
                State::Connected { degraded: true },
                color::DEGRADED,
                "一体机不可达",
            ),
            (
                State::Backoff {
                    attempt: 2,
                    delay: Duration::from_secs(4),
                },
                color::BACKOFF,
                "正在重连 · 第 2 次",
            ),
            (State::Stopping, color::IDLE, "正在停止"),
            (
                State::Failed {
                    class: ErrorClass::Fatal,
                    message: "host key 不一致".into(),
                },
                color::FAILED,
                "连接失败",
            ),
        ];

        // 表自己也要证明一格都没重、一格都没漏。
        let mut seen = [false; CASES];
        for (state, _, _) in &table {
            let i = case_index(state);
            assert!(!seen[i], "第 {i} 格在表里出现了两次");
            seen[i] = true;
        }
        assert!(seen.iter().all(|h| *h), "表里有空格：{seen:?}");

        for (state, want_color, want_title) in table {
            let m = model_in(state.clone());
            assert_eq!(
                icon_color(&m),
                want_color,
                "{state:?} 的托盘颜色不对（跟状态卡上那个圆点必须是同一个）"
            );
            // 状态卡上的圆点与托盘图标**必须**是同一个颜色，这是
            // `icon_color` 只有一个真相来源的全部意义。
            assert_eq!(icon_color(&m), m.status_card().dot);

            let tip = tooltip(&m);
            assert!(
                tip.starts_with(WINDOW_TITLE),
                "{state:?} 的提示没有产品名：{tip}"
            );
            assert!(
                tip.contains(want_title),
                "{state:?} 的提示里没有状态标题「{want_title}」：{tip}"
            );
            // 副标题也得在——只写标题的话 `Failed` 下托盘上只有
            // 「连接失败」四个字。
            assert!(
                tip.contains(&m.status_card().subtitle),
                "{state:?} 的提示漏了副标题：{tip}"
            );
            for banned in crate::BANNED_WORDS {
                assert!(!tip.contains(banned), "{state:?} 的提示含禁用词：{tip}");
            }
        }
    }

    /// 反向自证：上面那条断言里的 `want_title` 真的会因为改错而失配。
    ///
    /// 少了这条，「`tip.contains(want_title)`」在提示恒为某个长串时可能
    /// 碰巧全中——这个项目对 `contains` 的教训就是这个。
    #[test]
    fn a_tooltip_from_another_state_does_not_match() {
        let idle = tooltip(&model_in(State::Idle));
        assert!(!idle.contains("已连接"), "{idle}");
        assert!(!idle.contains("连接失败"), "{idle}");
        let failed = tooltip(&model_in(State::Failed {
            class: ErrorClass::Fatal,
            message: "host key 不一致".into(),
        }));
        assert!(!failed.contains("未开启"), "{failed}");
        assert!(failed.contains("host key"), "{failed}");
    }

    // ================= 提示长度 =================

    /// **长错误文案必须被截住。**
    ///
    /// `szTip` 是 `[u16; 128]`，而 `Failed` 的副标题原样来自 rmc-core 的
    /// 错误文案，长度不是我们能预估的。
    ///
    /// 改红：把 `tooltip` 里的 `clamp_utf16(..)` 换成裸 `format!`——
    /// 第一条断言当场红（`rmc_win::tray::wide` 仍会兜底截断，所以这不是
    /// 内存安全问题，而是「用户看不出后面还有字」）。
    #[test]
    fn a_very_long_status_is_clamped_to_what_the_tray_can_show() {
        let long = "证书校验失败".repeat(80);
        let m = model_in(State::Failed {
            class: ErrorClass::Fatal,
            message: long.clone(),
        });
        let tip = tooltip(&m);

        assert!(
            tip.encode_utf16().count() <= TOOLTIP_LIMIT,
            "提示有 {} 个码元，超过 szTip 放得下的 {TOOLTIP_LIMIT}",
            tip.encode_utf16().count()
        );
        assert!(tip.ends_with('…'), "截断了却没有省略号：{tip}");
        // 反向自证：短的那一份**没有**被截。
        let short = tooltip(&model_in(State::Idle));
        assert!(!short.ends_with('…'), "{short}");
        assert!(short.encode_utf16().count() < TOOLTIP_LIMIT);
        // 截断之后仍然是合法文本，而且开头那段没变。
        assert!(tip.starts_with(WINDOW_TITLE));
    }

    /// 截断不许把一个字符切一半（省略号自己也要算进额度）。
    #[test]
    fn clamping_counts_utf16_units_and_never_splits_a_char() {
        // 表情符号一个占两个码元。10 个 = 20 个码元。
        let text = "\u{1F600}".repeat(10);
        let out = clamp_utf16(&text, 9);
        assert_eq!(out.encode_utf16().count(), 9, "{out}");
        // 8 个额度 = 4 个完整表情，再加一个省略号。
        assert_eq!(out, format!("{}…", "\u{1F600}".repeat(4)));
        // 正好装得下时一个字都不动。
        assert_eq!(clamp_utf16(&text, 20), text);
        assert_eq!(clamp_utf16("abc", 3), "abc");
    }

    /// 提示交给 Win32 之前必须装得进 `szTip`，而且回读得出来。
    ///
    /// 这条把纯逻辑层跟 `rmc_win::tray::wide` 接在一起验一次——两边的
    /// 长度约定（127 vs 128）对不上的话，要么白白少一个字，要么最后一个
    /// 字被 NUL 吃掉。
    #[test]
    fn the_clamped_tooltip_survives_the_win32_buffer() {
        let m = model_in(State::Failed {
            class: ErrorClass::Fatal,
            message: "证书校验失败".repeat(80),
        });
        let tip = tooltip(&m);
        let buf = rmc_win::tray::wide::<{ rmc_win::tray::TIP_CAP }>(&tip);
        let end = buf.iter().position(|&u| u == 0).expect("必须有结尾 NUL");
        assert_eq!(
            String::from_utf16(&buf[..end]).expect("回读必须是合法 UTF-16"),
            tip,
            "提示进了 szTip 之后又被砍掉一截，两边的长度约定对不上"
        );
    }

    // ================= 图标像素 =================

    /// 圆点：中心是那个颜色、四角透明、尺寸对得上。
    ///
    /// 改红：把 `icon_rgba` 里 `<= radius * radius` 改成 `>=`——图案
    /// 整个反过来（中间透明、四周实心）。这条的中心像素断言当场红。
    #[test]
    fn the_icon_is_a_filled_dot_in_the_given_colour() {
        let rgba = icon_rgba(color::CONNECTED);
        assert_eq!(rgba.len(), ICON_SIDE * ICON_SIDE * 4);

        let at = |x: usize, y: usize| {
            let i = (y * ICON_SIDE + x) * 4;
            [rgba[i], rgba[i + 1], rgba[i + 2], rgba[i + 3]]
        };
        let want = [
            channel(color::CONNECTED.r),
            channel(color::CONNECTED.g),
            channel(color::CONNECTED.b),
            0xff,
        ];
        assert_eq!(at(8, 8), want, "圆心不是那个颜色");
        assert_eq!(at(7, 7), want, "圆心附近不是实心的");
        assert_eq!(at(0, 0), [0, 0, 0, 0], "左上角不是透明的");
        assert_eq!(at(15, 15), [0, 0, 0, 0], "右下角不是透明的");

        // 换个颜色就得换出不一样的图——否则上面那些断言可能只是在
        // 测一张恒定的图。
        assert_ne!(icon_rgba(color::FAILED), rgba);
        // 而且真的能交给 Win32 那一侧。
        assert!(rmc_win::tray::icon_bits(&rgba, ICON_SIDE).is_some());
    }

    /// 通道换算：夹在 0-255，不靠 `as u8` 的静默行为。
    #[test]
    fn a_channel_is_clamped_before_it_is_scaled() {
        assert_eq!(channel(0.0), 0);
        assert_eq!(channel(1.0), 255);
        assert_eq!(channel(-1.0), 0);
        assert_eq!(channel(2.0), 255);
        // 四舍五入，不是截断：0xc4 / 255 再乘回去必须还是 0xc4。
        assert_eq!(channel(0xc4 as f32 / 255.0), 0xc4);
    }

    // ================= W193：会话数的差 =================

    /// 按 id 比，不是比个数。
    ///
    /// 改红：把 `SessionDelta::between` 改成按 `len()` 相减——最后那组
    /// 「一开一关」会算成 0/0，当场红。
    #[test]
    fn the_session_delta_counts_ids_not_lengths() {
        let none: Vec<RemoteSessionInfo> = vec![];
        assert_eq!(
            SessionDelta::between(&none, &[session(1)]),
            SessionDelta {
                opened: 1,
                closed: 0
            }
        );
        assert_eq!(
            SessionDelta::between(&[session(1), session(2)], &[session(2)]),
            SessionDelta {
                opened: 0,
                closed: 1
            }
        );
        assert_eq!(
            SessionDelta::between(&[session(1)], &[session(1)]),
            SessionDelta::default()
        );
        assert!(SessionDelta::between(&[session(1)], &[session(1)]).is_quiet());

        // **个数一样，id 全换了**：一个断开、一个接入。brief 那个
        // `i64` 在这一拍上是 0，两条通知都不弹。
        assert_eq!(
            SessionDelta::between(&[session(1)], &[session(2)]),
            SessionDelta {
                opened: 1,
                closed: 1
            }
        );
    }

    // ================= W195：通知文案逐字比对 =================

    /// 会话起止：三种组合各一条，**逐字比对**。
    ///
    /// brief 的断言是 `n.1.contains("远程会话")`。`contains` 在这个项目
    /// 里的教训是「空串上永远为假、长串上很容易碰巧为真」，所以这里
    /// 直接比整条正文——文案改一个字就红，不需要另外配反向变异。
    ///
    /// 改红：把 `session_body` 里 `(n, 0)` 与 `(0, m)` 两支对调——
    /// 「接入」会说成「结束」，现场人员看到的是反的。前两格当场红。
    #[test]
    fn opening_and_closing_sessions_each_get_their_own_words() {
        let connected = State::Connected { degraded: false };

        let opened = notification_for(
            &connected,
            &connected,
            SessionDelta {
                opened: 1,
                closed: 0,
            },
        );
        assert_eq!(
            opened,
            Notify::Show(Notification {
                title: "远程维护".to_string(),
                body: "1 个远程会话已接入一体机".to_string(),
            })
        );

        let closed = notification_for(
            &connected,
            &connected,
            SessionDelta {
                opened: 0,
                closed: 2,
            },
        );
        assert_eq!(
            closed,
            Notify::Show(Notification {
                title: "远程维护".to_string(),
                body: "2 个远程会话已结束".to_string(),
            })
        );

        // 一开一关同一拍：两件事都得说出来。brief 的 `i64` 在这里是 0。
        let both = notification_for(
            &connected,
            &connected,
            SessionDelta {
                opened: 1,
                closed: 1,
            },
        );
        assert_eq!(
            both,
            Notify::Show(Notification {
                title: "远程维护".to_string(),
                body: "1 个远程会话已接入一体机，另有 1 个已结束".to_string(),
            })
        );
    }

    /// 一体机掉线与恢复，两条各说各的，**逐字比对**。
    ///
    /// 改红：把那两支的 `Notification` 对调——「不可达」会在恢复时弹。
    #[test]
    fn losing_and_regaining_the_appliance_each_get_their_own_words() {
        let ok = State::Connected { degraded: false };
        let bad = State::Connected { degraded: true };

        assert_eq!(
            notification_for(&ok, &bad, SessionDelta::default()),
            Notify::Show(Notification {
                title: "一体机不可达".to_string(),
                body: "隧道正常，但连不上一体机，请检查设备与网段".to_string(),
            })
        );
        assert_eq!(
            notification_for(&bad, &ok, SessionDelta::default()),
            Notify::Show(Notification {
                title: "一体机已恢复".to_string(),
                body: "一体机重新可达，远程维护照常".to_string(),
            })
        );
        // 没变就不弹。
        assert_eq!(
            notification_for(&bad, &bad, SessionDelta::default()),
            Notify::Nothing
        );
    }

    /// 失败那一条的正文**原样**是 rmc-core 给的错误文案。
    ///
    /// 逐字比对，不是 `contains("host key")`：那样的话把正文换成
    /// 「host key 出了点问题」也能过，而用户丢掉的正是那句具体说明。
    ///
    /// 改红：把 `message.clone()` 换成一句写死的话。
    #[test]
    fn a_failure_carries_the_cores_own_words() {
        const MSG: &str = "运维服务器的 host key 与本机记录不一致，可能是中间人";
        let failed = State::Failed {
            class: ErrorClass::Fatal,
            message: MSG.to_string(),
        };
        assert_eq!(
            notification_for(&State::Connecting, &failed, SessionDelta::default()),
            Notify::Show(Notification {
                title: "远程维护失败".to_string(),
                body: MSG.to_string(),
            })
        );
        // 同一次失败不弹第二遍。
        assert_eq!(
            notification_for(&failed, &failed, SessionDelta::default()),
            Notify::Nothing
        );
    }

    /// 退避重连**刻意不弹**，而且说得出为什么。
    ///
    /// 这一格正是 W193 里 `Option` 压平掉的那一格：`Suppressed` 跟
    /// `Nothing` 不是一回事。
    ///
    /// 改红：把 `(_, State::Backoff { .. })` 那一支删掉——它会落到
    /// `_ => Notify::Nothing`，第二条断言当场红。
    #[test]
    fn a_reconnect_is_suppressed_on_purpose_not_merely_silent() {
        let n = notification_for(
            &State::Connected { degraded: false },
            &State::Backoff {
                attempt: 1,
                delay: Duration::from_secs(1),
            },
            SessionDelta::default(),
        );
        assert!(n.to_show().is_none(), "重连弹了通知，会骚扰现场人员：{n:?}");
        assert_eq!(
            n,
            Notify::Suppressed {
                reason: BACKOFF_IS_TOO_NOISY
            },
            "重连被静默成了「什么都没发生」，日志里说不出为什么没弹"
        );
        // 而「真的什么都没发生」是另一格。
        assert_eq!(
            notification_for(&State::Idle, &State::Idle, SessionDelta::default()),
            Notify::Nothing
        );
    }

    /// 剩下的那些状态转移一条都不该弹——窗口就在眼前，没必要。
    #[test]
    fn the_ordinary_transitions_say_nothing() {
        for (prev, next) in [
            (State::Idle, State::Preflight),
            (State::Preflight, State::Connecting),
            (State::Connecting, State::Connected { degraded: false }),
            (State::Connected { degraded: false }, State::Stopping),
            (State::Stopping, State::Idle),
        ] {
            assert_eq!(
                notification_for(&prev, &next, SessionDelta::default()),
                Notify::Nothing,
                "{prev:?} → {next:?} 不该弹通知"
            );
        }
    }

    /// 任何一条弹出去的通知都不许含禁用词，也不许是空的。
    ///
    /// 走的是上面几条覆盖到的全部弹出分支。
    #[test]
    fn no_notification_is_empty_or_says_a_banned_word() {
        let ok = State::Connected { degraded: false };
        let bad = State::Connected { degraded: true };
        let one = SessionDelta {
            opened: 1,
            closed: 0,
        };
        let cases = [
            notification_for(&ok, &ok, one),
            notification_for(
                &ok,
                &ok,
                SessionDelta {
                    opened: 0,
                    closed: 1,
                },
            ),
            notification_for(
                &ok,
                &ok,
                SessionDelta {
                    opened: 2,
                    closed: 3,
                },
            ),
            notification_for(&ok, &bad, SessionDelta::default()),
            notification_for(&bad, &ok, SessionDelta::default()),
            notification_for(
                &State::Connecting,
                &State::Failed {
                    class: ErrorClass::Fatal,
                    message: "证书过期".into(),
                },
                SessionDelta::default(),
            ),
        ];
        // 反向自证：这一组里真的每一条都是要弹的。
        assert_eq!(cases.iter().filter(|n| n.to_show().is_some()).count(), 6);

        for n in &cases {
            let n = n.to_show().expect("上面刚数过");
            assert!(!n.title.is_empty(), "{n:?} 的标题是空的");
            assert!(!n.body.is_empty(), "{n:?} 的正文是空的");
            for banned in crate::BANNED_WORDS {
                assert!(!n.title.contains(banned), "{n:?} 的标题含 {banned}");
                assert!(!n.body.contains(banned), "{n:?} 的正文含 {banned}");
            }
            // 通知也要装得进 Win32 的两个定长缓冲，回读得出来。
            for (text, cap) in [
                (&n.title, rmc_win::tray::INFO_TITLE_CAP),
                (&n.body, rmc_win::tray::INFO_CAP),
            ] {
                assert!(
                    text.encode_utf16().count() < cap,
                    "「{text}」装不进 {cap} 个码元的缓冲"
                );
            }
        }
    }

    /// `no_tray` 就是「没有托盘」，不是一个装样子的实现。
    #[test]
    fn the_no_tray_factory_really_gives_nothing() {
        assert!(no_tray().is_none());
        let f: TrayFactory = no_tray;
        assert!(f().is_none());
    }
}
