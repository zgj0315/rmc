//! 配色与尺寸常量。取值来自已定版画板，改动前先改画板。
//!
//! 这个模块里的测试能证明的事只有一件：**这些常量没有被人手滑改过**。
//! 它证明不了"这套配色本身是对的"——对比度是否达标、在高 DPI 屏上是否
//! 好看、色弱用户能否分辨 `DEGRADED` 与 `BACKOFF`，都只能靠人工验收
//! （见 task-6-report.md 的人工验收清单）。别把绿灯读成"配色正确"。

use iced::Color;

/// 固定窗口尺寸，不可最大化。
pub const WINDOW_SIZE: (f32, f32) = (520.0, 720.0);

const fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color {
        r: r as f32 / 255.0,
        g: g as f32 / 255.0,
        b: b as f32 / 255.0,
        a: 1.0,
    }
}

pub mod color {
    use super::rgb;
    use iced::Color;

    /// 未开始：灰。
    pub const IDLE: Color = rgb(0x8a, 0x8a, 0x8a);
    /// 进行中：蓝。
    ///
    /// W105：这个值跟 [`ACCENT`] 完全一样（`#0067c0`），**不是笔误**。
    /// 两者语义不同——`PROGRESS` 是隧道状态机的"进行中"状态色，
    /// `ACCENT` 是控件强调色（选中页签的下划线、主按钮）。Fluent 的
    /// 强调蓝恰好也是进度蓝；哪天品牌色改了，只应该动 `ACCENT`，
    /// `PROGRESS` 要跟着状态色体系走。所以分成两个常量、两条测试各钉
    /// 一遍，而不是写成 `pub const PROGRESS: Color = ACCENT;`。
    pub const PROGRESS: Color = rgb(0x00, 0x67, 0xc0);
    /// 已连通：绿。
    pub const CONNECTED: Color = rgb(0x0f, 0x7b, 0x0f);
    /// 降级运行：橙。
    pub const DEGRADED: Color = rgb(0xb8, 0x56, 0x0f);
    /// 退避重连中：琥珀。
    pub const BACKOFF: Color = rgb(0x9d, 0x5d, 0x00);
    /// 失败：红。
    pub const FAILED: Color = rgb(0xc4, 0x2b, 0x1c);

    /// 控件强调色。见 [`PROGRESS`] 上的说明。
    pub const ACCENT: Color = rgb(0x00, 0x67, 0xc0);
    pub const TEXT: Color = rgb(0x1c, 0x1c, 0x1c);
    pub const TEXT_SUB: Color = rgb(0x6b, 0x6b, 0x6b);
    pub const CARD: Color = rgb(0xff, 0xff, 0xff);
    pub const BORDER: Color = rgb(0xe8, 0xe8, 0xe8);
    pub const WINDOW: Color = rgb(0xf3, 0xf3, 0xf3);
}

/// 状态卡的浅色底：把状态色按 [`TINT_ALPHA`] 的比例叠在白底上。
///
/// 等价于 `white * (1 - K) + base * K`，展开就是 `1 - (1 - base) * K`。
pub const TINT_ALPHA: f32 = 0.08;

/// 状态卡的浅色底，把状态色按 8% 混到白底上。
pub fn tint(base: Color) -> Color {
    Color {
        r: 1.0 - (1.0 - base.r) * TINT_ALPHA,
        g: 1.0 - (1.0 - base.g) * TINT_ALPHA,
        b: 1.0 - (1.0 - base.b) * TINT_ALPHA,
        a: 1.0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Maintain,
    Diagnostics,
    Logs,
}

impl Tab {
    pub fn label(&self) -> &'static str {
        match self {
            Tab::Maintain => "维护",
            Tab::Diagnostics => "诊断",
            Tab::Logs => "日志",
        }
    }

    pub const ALL: [Tab; 3] = [Tab::Maintain, Tab::Diagnostics, Tab::Logs];
}

/// 页签的「选中/未选中」取色。
///
/// W99：这是纯判断，从 [`crate::view::chrome::tabs`] 里抽出来——留在 iced
/// 视图函数里，它在这台 macOS 开发机上就没有任何东西看得见（iced 起不了
/// 真窗口），只能靠人工验收守。见 `lib.rs` 顶部的 crate 级约定。
///
/// 返回 `(文字色, 下划线/边框色)`；未选中时边框透明。
pub fn tab_style(is_active: bool) -> (Color, Color) {
    if is_active {
        (color::TEXT, color::ACCENT)
    } else {
        (color::TEXT_SUB, Color::TRANSPARENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_hex(c: Color) -> String {
        format!(
            "#{:02x}{:02x}{:02x}",
            (c.r * 255.0).round() as u8,
            (c.g * 255.0).round() as u8,
            (c.b * 255.0).round() as u8
        )
    }

    #[test]
    fn window_is_fixed_at_the_agreed_size() {
        assert_eq!(WINDOW_SIZE, (520.0, 720.0));
    }

    #[test]
    fn state_colors_match_the_approved_palette() {
        assert_eq!(to_hex(color::IDLE), "#8a8a8a");
        assert_eq!(to_hex(color::PROGRESS), "#0067c0");
        assert_eq!(to_hex(color::CONNECTED), "#0f7b0f");
        assert_eq!(to_hex(color::DEGRADED), "#b8560f");
        assert_eq!(to_hex(color::BACKOFF), "#9d5d00");
        assert_eq!(to_hex(color::FAILED), "#c42b1c");
    }

    #[test]
    fn chrome_colors_match_the_approved_palette() {
        assert_eq!(to_hex(color::TEXT), "#1c1c1c");
        assert_eq!(to_hex(color::TEXT_SUB), "#6b6b6b");
        assert_eq!(to_hex(color::CARD), "#ffffff");
        assert_eq!(to_hex(color::BORDER), "#e8e8e8");
        assert_eq!(to_hex(color::WINDOW), "#f3f3f3");
    }

    #[test]
    fn accent_is_the_fluent_blue() {
        assert_eq!(to_hex(color::ACCENT), "#0067c0");
    }

    /// W98：brief 原本那条 `tint_is_lighter_than_its_base_and_keeps_the_hue_direction`
    /// 对任何 K 都恒绿——`1-(1-b)*K` 展开是 `(1-K) + K*b`，只要 `K ∈ (0,1)`
    /// 就必然 `≥ b` 且 `≥ 1-K`，把 K 从 0.08 改成 0.02 或 0.15 它照样通过。
    /// 这条改成钉住 K 的**实际效果**：六个状态色各自 tint 后的确切十六进制。
    /// K 一旦变动，六条断言一起红。
    #[test]
    fn tint_at_8_percent_produces_the_exact_card_backgrounds() {
        assert_eq!(TINT_ALPHA, 0.08);
        assert_eq!(to_hex(tint(color::IDLE)), "#f6f6f6");
        assert_eq!(to_hex(tint(color::PROGRESS)), "#ebf3fa");
        assert_eq!(to_hex(tint(color::CONNECTED)), "#ecf4ec");
        assert_eq!(to_hex(tint(color::DEGRADED)), "#f9f1ec");
        assert_eq!(to_hex(tint(color::BACKOFF)), "#f7f2eb");
        assert_eq!(to_hex(tint(color::FAILED)), "#faeeed");
    }

    #[test]
    fn tint_is_lighter_than_its_base_but_not_pure_white() {
        for base in [
            color::IDLE,
            color::PROGRESS,
            color::CONNECTED,
            color::DEGRADED,
            color::BACKOFF,
            color::FAILED,
        ] {
            let t = tint(base);
            assert!(t.r >= base.r && t.g >= base.g && t.b >= base.b, "{base:?}");
            // 必须仍然看得出是有颜色的，不能被冲成纯白——至少有一个通道
            // 明显低于 1.0。阈值取 0.975：K=0.08 时最淡的 `IDLE` 也只到
            // 0.9647（#f6），而 K 一旦缩到 0.02，六个颜色最深的通道也才
            // 0.9804（#fa），这条立刻红。
            let darkest = t.r.min(t.g).min(t.b);
            assert!(
                darkest < 0.975,
                "tint 太淡，跟白卡片分不开：{} ({base:?})",
                to_hex(t)
            );
        }
    }

    /// W98：brief 那条测试名里写了 "keeps the hue direction"，却一个字都没测。
    /// 这里真的测：tint 是单调映射，三个通道的**相对大小顺序**必须原样保留
    /// ——绿底 tint 完还得是绿的，不能变成偏红。把 `tint` 里的 `r`/`g`
    /// 写串（复制粘贴最容易犯的错）这条立刻红。
    #[test]
    fn tint_keeps_the_hue_direction_of_its_base() {
        fn order(c: Color) -> [std::cmp::Ordering; 3] {
            [
                c.r.partial_cmp(&c.g).unwrap(),
                c.g.partial_cmp(&c.b).unwrap(),
                c.r.partial_cmp(&c.b).unwrap(),
            ]
        }
        for base in [
            color::IDLE,
            color::PROGRESS,
            color::CONNECTED,
            color::DEGRADED,
            color::BACKOFF,
            color::FAILED,
        ] {
            assert_eq!(
                order(tint(base)),
                order(base),
                "通道顺序变了，色相翻了：{base:?} -> {:?}",
                tint(base)
            );
        }
        // 再钉两个具体方向，免得上面那条在"全部相等"的退化情况下空转。
        let green = tint(color::CONNECTED);
        assert!(green.g > green.r && green.r == green.b, "绿底应当仍偏绿");
        let blue = tint(color::PROGRESS);
        assert!(blue.b > blue.g && blue.g > blue.r, "蓝底应当仍偏蓝");
    }

    #[test]
    fn tab_labels_are_the_three_agreed_pages() {
        let labels: Vec<&str> = Tab::ALL.iter().map(|t| t.label()).collect();
        assert_eq!(labels, vec!["维护", "诊断", "日志"]);
    }

    #[test]
    fn tab_all_lists_every_variant_once_in_display_order() {
        assert_eq!(Tab::ALL, [Tab::Maintain, Tab::Diagnostics, Tab::Logs]);
    }

    /// W99：表驱动两格。这段判断原本埋在 `chrome::tabs` 的 iced 视图函数里，
    /// 在这台机器上没有任何东西看得见它。
    #[test]
    fn tab_style_marks_only_the_active_tab() {
        let cases = [
            (true, color::TEXT, color::ACCENT),
            (false, color::TEXT_SUB, Color::TRANSPARENT),
        ];
        for (is_active, want_text, want_border) in cases {
            let (text, border) = tab_style(is_active);
            assert_eq!(text, want_text, "is_active={is_active} 文字色");
            assert_eq!(border, want_border, "is_active={is_active} 边框色");
        }
        // 两格必须真的不同，否则上面的表可以被"两行填一样的值"糊过去。
        assert_ne!(tab_style(true), tab_style(false));
        // 未选中的下划线必须是透明，不是"某种浅色"——否则未选中页签也会
        // 画出一条线。
        assert_eq!(tab_style(false).1.a, 0.0);
        assert_eq!(tab_style(true).1.a, 1.0);
    }
}
