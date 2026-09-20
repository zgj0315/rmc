//! 视图模型。界面的全部判断都在这里，纯函数，跨平台可测。
//!
//! `view/` 之后只做绘制：拿到一份 [`StatusCard`] 就画卡片，拿到一份
//! [`Buttons`] 就摆按钮，不再自己判断「这个状态该是什么颜色」。理由见
//! `lib.rs` 顶部的 crate 级约定——写进 iced 视图函数里的判断，在这台
//! macOS 开发机上一个字都没有东西看得见。
//!
//! # W128：显示口令 / 地址可编辑**不是字段，是从状态派生的**
//!
//! brief 原稿把 `credentials_visible` / `addresses_editable` 存成
//! `Model` 的两个 `pub bool` 字段，由 `apply` 在收到 `TunnelEvent::State`
//! 时顺手写一遍。那是**影子状态**：同一件事有两个来源（`self.state` 与
//! 这两个字段），一旦有第二条写入路径（Task 8 的维护页、Task 10 的表单）
//! 忘了同步，两者就会分叉。
//!
//! 这正是 rmc-core 踩过三次的形状（R71/R75/R78：`ctx.state` 落后于真实
//! 状态，准入判断放过了不该放过的东西），最后靠「准入判断一律改看同步
//! 字段」修掉。这里的后果轻一些（显示错，不是泄漏隧道），但形状一模一样，
//! 而 Task 8/10 确实会往 `Model` 写东西。所以改成方法，只有 `state`
//! 一个来源。
//!
//! **如果产品上需要用户手动切「显示口令」**，那是另一个来源（用户意图，
//! 不是隧道状态），必须用另一个名字（例如 `password_revealed`）另开一个
//! 字段，并且由视图层自己把两者 `&&` 起来；别让两个来源共用一个名字。

use crate::theme::{color, tint};
use rmc_core::preflight::PreflightReport;
use rmc_core::state::{RemoteSessionInfo, State, TunnelEvent};
use rmc_core::supervisor::APPLIANCE_PROBE;
use std::time::SystemTime;

/// 按钮按下去要做的事。标签是给人看的，这个才是给 `update` 看的。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Start,
    Cancel,
    Stop,
    RetryNow,
}

/// 状态卡的全部可画内容。视图层只负责把这四个值摆进控件。
#[derive(Debug, Clone, PartialEq)]
pub struct StatusCard {
    pub dot: iced::Color,
    pub background: iced::Color,
    pub title: String,
    pub subtitle: String,
}

/// 主按钮区。两个位置，都可能没有（`Stopping` 时两个都没有）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Buttons {
    pub primary: Option<(&'static str, Action)>,
    pub secondary: Option<(&'static str, Action)>,
}

/// 界面持有的全部只读事实。**没有一个字段是从 `state` 能推出来的**——
/// 能推出来的都写成方法，见模块文档 W128 一节。
#[derive(Debug, Clone, PartialEq)]
pub struct Model {
    pub state: State,
    pub sessions: Vec<RemoteSessionInfo>,
    pub preflight: Option<PreflightReport>,
    pub host_key: Option<(String, bool)>,
    pub connected_since: Option<SystemTime>,
}

impl Default for Model {
    fn default() -> Self {
        Self {
            state: State::Idle,
            sessions: Vec::new(),
            preflight: None,
            host_key: None,
            connected_since: None,
        }
    }
}

impl Model {
    pub fn apply(&mut self, e: TunnelEvent) {
        match e {
            TunnelEvent::State(s) => {
                // 回到 Idle 就是「这一轮彻底结束了」：会话与计时都作废。
                //
                // 只在 Idle 清，不在 Stopping 清（W129）：Stopping 期间
                // 远程会话可能真的还开着，抢先抹掉是另一个方向的假话。
                // rmc-core 的 `Ctx::stop_everything` 自己会在拆隧道时发一条
                // `RemoteSessions(vec![])`，界面不需要替它猜。
                if matches!(s, State::Idle) {
                    self.sessions.clear();
                    self.connected_since = None;
                }
                self.state = s;
            }
            TunnelEvent::Preflight(r) => self.preflight = Some(r),
            TunnelEvent::RemoteSessions(list) => self.sessions = list,
            TunnelEvent::HostKey {
                fingerprint,
                first_seen,
            } => {
                self.host_key = Some((fingerprint, first_seen));
            }
            TunnelEvent::ConnectedSince(t) => self.connected_since = Some(t),
        }
    }

    /// 地址与账号口令还能不能改。
    ///
    /// 只有「未开启」与「失败」两种状态允许——其余状态下这些值已经被
    /// 一条活着的（或正在建立的）隧道用上了，改了也不会生效，摆出可编辑
    /// 的样子是骗人。
    fn editable(&self) -> bool {
        matches!(self.state, State::Idle | State::Failed { .. })
    }

    /// 凭据区（账号、口令）该不该显示。见模块文档 W128 一节：这是从
    /// `state` 派生的，不是一个可以被别处写坏的字段。
    pub fn credentials_visible(&self) -> bool {
        self.editable()
    }

    /// 地址框该不该可编辑。
    pub fn addresses_editable(&self) -> bool {
        self.editable()
    }

    pub fn status_card(&self) -> StatusCard {
        let (dot, title, subtitle) = match &self.state {
            State::Idle => (
                color::IDLE,
                "未开启".to_string(),
                "远程维护默认关闭，由现场人员确认后开启".to_string(),
            ),
            State::Preflight => (
                color::PROGRESS,
                "预检中".to_string(),
                "正在检查网络可达性".to_string(),
            ),
            State::Connecting => (
                color::PROGRESS,
                "正在连接".to_string(),
                "口令认证与反向端口注册".to_string(),
            ),
            State::Connected { degraded: false } => (
                color::CONNECTED,
                "已连接".to_string(),
                // brief 原稿这里写的是「Gateway 反向端口 127.0.0.1:22001」，
                // 两处都不能照抄：Gateway 是需求禁用词，而反向端口号来自
                // `Config::reverse_port`，本任务的 `Model` 根本没有配置，
                // 写死 22001 是**编造**。等 Task 8 把配置接进来再显示真值。
                "隧道已建立，远程工程师可以接入一体机".to_string(),
            ),
            State::Connected { degraded: true } => (
                color::DEGRADED,
                "一体机不可达".to_string(),
                // 30 这个数字取自 rmc-core 的 `APPLIANCE_PROBE`，不另写一份
                // ——那边改了节奏，这句话跟着变。
                format!(
                    "隧道正常，每 {} 秒重试一体机，恢复后自动转回",
                    APPLIANCE_PROBE.as_secs()
                ),
            ),
            State::Backoff { attempt, delay } => (
                color::BACKOFF,
                format!("正在重连 · 第 {attempt} 次"),
                // 向上取整、最小 1 秒。退避序列带抖动
                // （`backoff.rs`：`base * jitter`，首档 1 秒可以抖到 0.8 秒），
                // 直接 `as_secs()` 会截成 0，界面上出现"0 秒后重试"。
                format!("{} 秒后重试，口令已保留", round_up_secs(*delay)),
            ),
            State::Stopping => (
                color::IDLE,
                "正在停止".to_string(),
                "正在关闭隧道与全部远程会话".to_string(),
            ),
            State::Failed { message, .. } => {
                // rmc-core 的 `Error::to_string()` 原样落在这里。W125 就是
                // 因为这条路径才必须去改 rmc-core 的文案——守它的是
                // `rmc_core::wording` 那几条扫描。
                (color::FAILED, "连接失败".to_string(), message.clone())
            }
        };
        let background = if matches!(self.state, State::Idle) {
            color::CARD
        } else {
            tint(dot)
        };
        StatusCard {
            dot,
            background,
            title,
            subtitle,
        }
    }

    pub fn buttons(&self) -> Buttons {
        match &self.state {
            State::Idle => Buttons {
                primary: Some(("开启远程维护", Action::Start)),
                secondary: None,
            },
            State::Preflight | State::Connecting => Buttons {
                primary: Some(("取消", Action::Cancel)),
                secondary: None,
            },
            State::Connected { .. } => Buttons {
                primary: Some(("停止远程维护", Action::Stop)),
                secondary: None,
            },
            State::Backoff { .. } => Buttons {
                primary: Some(("立即重试", Action::RetryNow)),
                secondary: Some(("停止远程维护", Action::Stop)),
            },
            // 正在停止：没有任何按钮。此时点什么都只会让状态更乱，
            // 而这个状态是短暂的。
            State::Stopping => Buttons::default(),
            State::Failed { .. } => Buttons {
                primary: Some(("重试", Action::RetryNow)),
                secondary: None,
            },
        }
    }

    /// 已连接时长，形如 `01:34:14`。**只有隧道确实还在时才有值**
    /// （`Connected` 与 `Stopping`）。
    ///
    /// 评审抓到的一处文档与行为不符：`connected_since` 只在 `Idle` 被清
    /// （那是对的——断线重连时计时该接着走，不该从零重来），但如果这里
    /// 照旧无条件返回，界面就会在「连接失败」的卡片旁边显示一个还在往上
    /// 涨的「已连接 00:01:30」。那跟编造一个不存在的端口号是同一类
    /// 「显示一句不真的话」。
    ///
    /// **`Stopping` 留在报数那一侧是刻意的**，与 W129 同一个理由：正在
    /// 停止时隧道确实还在、远程会话可能真的还开着，说「已连接」不是假话。
    /// 假话是 `Backoff`（已经断了，在重试）与 `Failed`（根本没连上）。
    ///
    /// 所以字段负责**记着**，这个方法负责**说实话**：重新 `Connected`
    /// 之后接着从原起点算，累计时长不丢。
    pub fn elapsed(&self, now: SystemTime) -> Option<String> {
        if !matches!(self.state, State::Connected { .. } | State::Stopping) {
            return None;
        }
        let since = self.connected_since?;
        let secs = now.duration_since(since).ok()?.as_secs();
        Some(format!(
            "{:02}:{:02}:{:02}",
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60
        ))
    }
}

/// 向上取整到秒，最小 1。见 `status_card` 里 `Backoff` 分支的说明。
fn round_up_secs(d: std::time::Duration) -> u64 {
    let secs = d.as_secs_f64().ceil() as u64;
    secs.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::color;
    use crate::BANNED_WORDS;
    use rmc_core::banned_word_in;
    use rmc_core::error::{Error, ErrorClass};
    use rmc_core::preflight::{PreflightReport, PreflightStep, StepOutcome, STEP_APPLIANCE_TCP};
    use std::time::{Duration, SystemTime};

    fn model_in(state: State) -> Model {
        let mut m = Model::default();
        m.apply(TunnelEvent::State(state));
        m
    }

    // ---------------------------------------------------------------
    // W126：`State` 有七个变体，brief 的颜色表只列了六个（漏了 Stopping）。
    //
    // Task 3 的解法是 macro + 定长数组让「加变体不进表」编译不过；`State`
    // 住在 rmc-core，宏伸不过去，所以改用**测试里的穷尽 match**：rmc-core
    // 将来往 `State` 加变体，`case_index` 直接编译不过；补上一个 `=> 8` 的
    // 分支又会让 `[false; DISPLAY_CASES]` 越界。两道闸。
    // ---------------------------------------------------------------

    /// 显示分支数。`State` 是**七**个变体，但 `Connected { degraded }`
    /// 的两个取值是两条独立的显示分支（颜色、标题、副标题全不同），
    /// 所以表是八行不是七行。
    const DISPLAY_CASES: usize = 8;

    /// 每条显示分支一个槽位。**穷尽 match**，见上面那段说明。
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

    /// 每条显示分支一个代表值。`Failed` 用的是**真的** rmc-core 错误
    /// 文案，不是手打的字符串——brief 原稿那句
    /// `"Gateway host key 与已记录的不一致"` 照抄进来就把违规焊死了。
    fn every_display_case() -> [State; DISPLAY_CASES] {
        [
            State::Idle,
            State::Preflight,
            State::Connecting,
            State::Connected { degraded: false },
            State::Connected { degraded: true },
            State::Backoff {
                attempt: 3,
                delay: Duration::from_secs(5),
            },
            State::Stopping,
            State::Failed {
                class: ErrorClass::Fatal,
                message: host_key_mismatch().to_string(),
            },
        ]
    }

    /// 那条最典型的、会原样画到状态卡副标题上的 rmc-core 错误。
    fn host_key_mismatch() -> Error {
        Error::HostKeyMismatch {
            expected: "SHA256:aaa".into(),
            actual: "SHA256:bbb".into(),
        }
    }

    /// 一张「每条显示分支一行」的表，少一行/多一行都红。
    fn assert_table_covers_every_display_case(states: &[State]) {
        let mut seen = [false; DISPLAY_CASES];
        for s in states {
            let i = case_index(s);
            assert!(!seen[i], "第 {i} 条显示分支在表里出现了两次：{s:?}");
            seen[i] = true;
        }
        for (i, hit) in seen.iter().enumerate() {
            assert!(
                *hit,
                "第 {i} 条显示分支没进表——rmc-core 的 State 加了变体而这张表没跟上"
            );
        }
    }

    #[test]
    fn the_display_case_table_itself_is_exhaustive() {
        // 反向自证：上面那个穷尽性工具本身得是有效的。
        assert_table_covers_every_display_case(&every_display_case());
        assert_eq!(every_display_case().len(), DISPLAY_CASES);
    }

    #[test]
    fn idle_shows_credentials_and_editable_addresses() {
        let m = model_in(State::Idle);
        assert!(m.credentials_visible());
        assert!(m.addresses_editable());
        assert_eq!(m.status_card().title, "未开启");
    }

    #[test]
    fn connected_hides_credentials_and_locks_addresses() {
        let m = model_in(State::Connected { degraded: false });
        assert!(!m.credentials_visible(), "已连接后凭据区必须隐藏");
        assert!(!m.addresses_editable(), "已连接后地址必须锁定");
    }

    /// 八条显示分支各自该不该让人改地址/看口令，逐条钉死。
    ///
    /// 只测 Idle 与 Connected 两格（brief 原稿）是不够的：把判断写成
    /// `matches!(s, State::Idle | State::Failed { .. } | State::Stopping)`
    /// 那两条也全绿。
    #[test]
    fn only_idle_and_failed_let_the_operator_edit_anything() {
        let cases = [
            (State::Idle, true),
            (State::Preflight, false),
            (State::Connecting, false),
            (State::Connected { degraded: false }, false),
            (State::Connected { degraded: true }, false),
            (
                State::Backoff {
                    attempt: 1,
                    delay: Duration::from_secs(1),
                },
                false,
            ),
            (State::Stopping, false),
            (
                State::Failed {
                    class: ErrorClass::Fatal,
                    message: "x".into(),
                },
                true,
            ),
        ];
        assert_table_covers_every_display_case(
            &cases.iter().map(|(s, _)| s.clone()).collect::<Vec<_>>(),
        );
        for (state, want) in cases {
            let m = model_in(state.clone());
            assert_eq!(m.addresses_editable(), want, "{state:?} 的地址可编辑性");
            assert_eq!(m.credentials_visible(), want, "{state:?} 的凭据区可见性");
        }
        // 两格必须真的不同，否则上面的表可以被"全填 true"糊过去。
        assert!(model_in(State::Idle).addresses_editable());
        assert!(!model_in(State::Stopping).addresses_editable());
    }

    /// W128 的回归闸：这两个判断必须**只**看 `state`。
    ///
    /// 把它们改回 `apply` 里写的字段，这条就会红——因为这里根本没走
    /// `apply`，是直接构造的 `Model`。
    #[test]
    fn visibility_is_derived_from_state_not_remembered_from_an_event() {
        let m = Model {
            state: State::Connected { degraded: false },
            ..Model::default()
        };
        assert!(
            !m.credentials_visible(),
            "没经过 apply 也必须算得出来——一旦存成字段，这里会拿到 Default 的 true"
        );
        assert!(!m.addresses_editable());
    }

    /// W126：八条显示分支的颜色，一条不落。
    #[test]
    fn status_colors_follow_the_state() {
        let cases = [
            (State::Idle, color::IDLE),
            (State::Preflight, color::PROGRESS),
            (State::Connecting, color::PROGRESS),
            (State::Connected { degraded: false }, color::CONNECTED),
            (State::Connected { degraded: true }, color::DEGRADED),
            (
                State::Backoff {
                    attempt: 1,
                    delay: Duration::from_secs(1),
                },
                color::BACKOFF,
            ),
            (State::Stopping, color::IDLE),
            (
                State::Failed {
                    class: ErrorClass::Fatal,
                    message: "x".into(),
                },
                color::FAILED,
            ),
        ];
        assert_table_covers_every_display_case(
            &cases.iter().map(|(s, _)| s.clone()).collect::<Vec<_>>(),
        );
        for (state, want) in cases {
            assert_eq!(model_in(state.clone()).status_card().dot, want, "{state:?}");
        }
    }

    /// 卡片底色：Idle 用纯白卡片色，其余一律是状态色的 8% 浅底。
    ///
    /// brief 一个字都没测 `background`——把 `tint(dot)` 改成 `color::CARD`
    /// （八个状态长一个样）原来没有任何东西会红。
    #[test]
    fn card_background_is_white_when_idle_and_a_tint_of_the_dot_otherwise() {
        let idle = model_in(State::Idle).status_card();
        assert_eq!(idle.background, color::CARD);
        for state in every_display_case() {
            let c = model_in(state.clone()).status_card();
            if matches!(state, State::Idle) {
                continue;
            }
            assert_eq!(c.background, tint(c.dot), "{state:?} 的卡片底色");
            assert_ne!(
                c.background, c.dot,
                "{state:?} 的底色跟圆点同色，卡片会糊成一块"
            );
        }
    }

    #[test]
    fn degraded_title_says_tunnel_is_fine_but_appliance_is_not() {
        let c = model_in(State::Connected { degraded: true }).status_card();
        assert_eq!(c.title, "一体机不可达");
        assert!(c.subtitle.contains("隧道正常"), "{}", c.subtitle);
        // 探测节奏必须来自 rmc-core 的 APPLIANCE_PROBE，不另写一份数字。
        assert!(
            c.subtitle
                .contains(&format!("每 {} 秒", APPLIANCE_PROBE.as_secs())),
            "{}",
            c.subtitle
        );
    }

    #[test]
    fn backoff_subtitle_names_the_attempt_and_the_delay() {
        let c = model_in(State::Backoff {
            attempt: 3,
            delay: Duration::from_secs(5),
        })
        .status_card();
        assert!(c.title.contains("第 3 次"), "{}", c.title);
        // brief 原稿写的是 `contains('5')`——那条断言在标题/副标题里任何
        // 位置出现一个 5 就绿（例如把次数印成 5），根本没有在看延迟。
        assert!(c.subtitle.contains("5 秒后重试"), "{}", c.subtitle);
    }

    /// 退避序列带抖动，首档 1 秒可以抖到 0.8 秒；`as_secs()` 会把它截成 0，
    /// 界面上就出现"0 秒后重试"。
    #[test]
    fn a_sub_second_backoff_delay_never_shows_as_zero_seconds() {
        let c = model_in(State::Backoff {
            attempt: 1,
            delay: Duration::from_millis(800),
        })
        .status_card();
        assert!(c.subtitle.contains("1 秒后重试"), "{}", c.subtitle);
        assert!(!c.subtitle.contains("0 秒"), "{}", c.subtitle);
        // 向上取整，不是四舍五入：1.2 秒要说 2 秒，不能说 1 秒。
        assert_eq!(round_up_secs(Duration::from_millis(1200)), 2);
        assert_eq!(round_up_secs(Duration::from_secs(5)), 5);
    }

    #[test]
    fn auth_failure_lands_on_idle_with_a_retype_hint() {
        // core 在认证失败时把状态推回 Idle，界面据此提示重新输入。
        let mut m = Model::default();
        m.apply(TunnelEvent::State(State::Connecting));
        assert!(!m.credentials_visible(), "连接过程中不该显示凭据区");
        m.apply(TunnelEvent::State(State::Idle));
        assert!(m.credentials_visible());
    }

    #[test]
    fn failed_state_shows_the_message_as_subtitle() {
        // 用真的 rmc-core 错误，不手打字符串——手打的那份既不会跟着
        // rmc-core 的文案变，还正好是 brief 把违规焊死的地方。
        let e = host_key_mismatch();
        let c = model_in(State::Failed {
            class: ErrorClass::Fatal,
            message: e.to_string(),
        })
        .status_card();
        assert_eq!(c.subtitle, e.to_string(), "副标题必须是原样的错误文案");
        assert!(c.subtitle.contains("host key"), "{}", c.subtitle);
        assert!(c.subtitle.contains("SHA256:bbb"), "{}", c.subtitle);
    }

    /// W125 在界面这一侧的闸：八条显示分支的状态卡与按钮，一个禁用词都
    /// 不许有。`Failed` 那条喂的是**真的** rmc-core 错误文案，所以
    /// 「rmc-core 改回 Gateway」会让这条一起红。
    #[test]
    fn nothing_the_status_card_says_is_banned() {
        // 反向自证：匹配器真的会对违规文本发火。少了这一步，一旦
        // `banned_word_in` 退化成恒返回 None，下面全是空转。
        assert_eq!(banned_word_in("经 Gateway 转发"), Some("Gateway"));
        assert!(!BANNED_WORDS.is_empty());

        for state in every_display_case() {
            let c = model_in(state.clone()).status_card();
            assert!(!c.title.is_empty(), "{state:?} 的标题是空串");
            assert!(!c.subtitle.is_empty(), "{state:?} 的副标题是空串");
            for text in [&c.title, &c.subtitle] {
                assert_eq!(banned_word_in(text), None, "{state:?} 的状态卡：{text}");
            }
            let b = model_in(state.clone()).buttons();
            for label in [b.primary, b.secondary].into_iter().flatten() {
                assert_eq!(banned_word_in(label.0), None, "{state:?} 的按钮");
            }
        }

        // 再把 rmc-core 三条历史上写着 Gateway 的错误逐条喂进 Failed 走
        // 一遍完整管道。rmc-core 侧的穷尽扫描在 `rmc_core::wording`。
        for e in [
            host_key_mismatch(),
            Error::TlsInvalidCert("unknown issuer".into()),
            Error::KeepaliveTimeout,
        ] {
            let c = model_in(State::Failed {
                class: e.class(),
                message: e.to_string(),
            })
            .status_card();
            assert_eq!(banned_word_in(&c.subtitle), None, "{}", c.subtitle);
        }
    }

    /// W126：按钮也是八条显示分支一条不落，而且**连 `Action` 一起钉**。
    ///
    /// brief 原稿只断言 `.0`（标签）——把 `State::Idle` 的 `Action::Start`
    /// 改成 `Action::Stop`，按钮还是写着"开启远程维护"，点下去却是停止，
    /// 原来没有任何东西会红。
    #[test]
    fn buttons_per_state() {
        let cases: [(State, Buttons); DISPLAY_CASES] = [
            (
                State::Idle,
                Buttons {
                    primary: Some(("开启远程维护", Action::Start)),
                    secondary: None,
                },
            ),
            (
                State::Preflight,
                Buttons {
                    primary: Some(("取消", Action::Cancel)),
                    secondary: None,
                },
            ),
            (
                State::Connecting,
                Buttons {
                    primary: Some(("取消", Action::Cancel)),
                    secondary: None,
                },
            ),
            (
                State::Connected { degraded: false },
                Buttons {
                    primary: Some(("停止远程维护", Action::Stop)),
                    secondary: None,
                },
            ),
            (
                State::Connected { degraded: true },
                Buttons {
                    primary: Some(("停止远程维护", Action::Stop)),
                    secondary: None,
                },
            ),
            (
                State::Backoff {
                    attempt: 1,
                    delay: Duration::from_secs(1),
                },
                Buttons {
                    primary: Some(("立即重试", Action::RetryNow)),
                    secondary: Some(("停止远程维护", Action::Stop)),
                },
            ),
            // 正在停止：两个位置都空。
            (State::Stopping, Buttons::default()),
            (
                State::Failed {
                    class: ErrorClass::Fatal,
                    message: "x".into(),
                },
                Buttons {
                    primary: Some(("重试", Action::RetryNow)),
                    secondary: None,
                },
            ),
        ];
        assert_table_covers_every_display_case(
            &cases.iter().map(|(s, _)| s.clone()).collect::<Vec<_>>(),
        );
        for (state, want) in cases {
            assert_eq!(model_in(state.clone()).buttons(), want, "{state:?}");
        }
        // 反向自证：表里不是清一色的同一份按钮，否则上面那圈断言
        // 可以被"buttons() 恒返回同一个值"糊过去。
        assert_ne!(
            model_in(State::Idle).buttons(),
            model_in(State::Stopping).buttons()
        );
    }

    /// W127：brief 原稿这条是纯粹的「只查不存在」——`status_card()` 返回
    /// 一对空字符串它照样绿。先正向确认卡片上真的有字，再查"剩余"。
    #[test]
    fn no_countdown_anywhere_in_v1() {
        // 会话上限不在 V1，任何状态都不得出现"剩余"。
        for state in every_display_case() {
            let c = model_in(state.clone()).status_card();
            assert!(
                !c.title.is_empty(),
                "{state:?} 的标题是空串，下面两条断言会空转"
            );
            assert!(
                !c.subtitle.is_empty(),
                "{state:?} 的副标题是空串，下面两条断言会空转"
            );
            assert!(!c.subtitle.contains("剩余"), "{state:?} 出现了倒计时");
            assert!(!c.title.contains("剩余"), "{state:?} 出现了倒计时");
        }
    }

    #[test]
    fn sessions_are_replaced_wholesale_by_each_event() {
        let mut m = Model::default();
        m.apply(TunnelEvent::RemoteSessions(vec![session(1), session(2)]));
        assert_eq!(m.sessions.len(), 2);
        m.apply(TunnelEvent::RemoteSessions(vec![session(2)]));
        assert_eq!(m.sessions.len(), 1);
        assert_eq!(m.sessions[0].id, 2, "留下的必须是新事件里那一条");
        m.apply(TunnelEvent::RemoteSessions(vec![]));
        assert!(m.sessions.is_empty());
    }

    fn session(id: u64) -> RemoteSessionInfo {
        RemoteSessionInfo {
            id,
            opened_at: SystemTime::UNIX_EPOCH,
            to_appliance: 0,
            from_appliance: 0,
        }
    }

    #[test]
    fn elapsed_formats_as_hms() {
        let mut m = Model::default();
        let start = SystemTime::UNIX_EPOCH;
        // 这条测的是 HH:MM:SS 的排版，状态只是背景；但 `elapsed` 只在隧道
        // 确实还在时才报数，所以得先真的连上。
        m.apply(TunnelEvent::State(State::Connected { degraded: false }));
        m.apply(TunnelEvent::ConnectedSince(start));
        let now = start + Duration::from_secs(3600 + 34 * 60 + 14);
        assert_eq!(m.elapsed(now).unwrap(), "01:34:14");
        // 三个字段都得各自动起来，不能是"时:分:秒"抄同一个数。
        assert_eq!(
            m.elapsed(start + Duration::from_secs(0)).unwrap(),
            "00:00:00"
        );
        assert_eq!(
            m.elapsed(start + Duration::from_secs(59)).unwrap(),
            "00:00:59"
        );
        assert_eq!(
            m.elapsed(start + Duration::from_secs(60)).unwrap(),
            "00:01:00"
        );
        assert_eq!(
            m.elapsed(start + Duration::from_secs(100 * 3600)).unwrap(),
            "100:00:00",
            "超过两位数的小时不许被截断"
        );
    }

    #[test]
    fn elapsed_is_none_before_connecting() {
        assert!(Model::default().elapsed(SystemTime::now()).is_none());
    }

    /// 计时只在 `Connected` 时对外报数，但**起点不丢**。
    ///
    /// 改红：把 `elapsed` 开头那个 `matches!(self.state, Connected)` 守卫
    /// 删掉——`Backoff`/`Failed` 两格会各自报出一个还在涨的「已连接」。
    #[test]
    fn elapsed_speaks_only_while_connected_but_remembers_the_start() {
        let start = SystemTime::UNIX_EPOCH;
        let now = start + Duration::from_secs(90);
        let mut m = Model::default();
        m.apply(TunnelEvent::State(State::Connected { degraded: false }));
        m.apply(TunnelEvent::ConnectedSince(start));
        assert_eq!(m.elapsed(now).unwrap(), "00:01:30");

        for s in [
            State::Backoff {
                attempt: 1,
                delay: Duration::from_secs(1),
            },
            State::Failed {
                class: ErrorClass::Fatal,
                message: "x".into(),
            },
        ] {
            m.apply(TunnelEvent::State(s.clone()));
            assert!(
                m.elapsed(now).is_none(),
                "{s:?} 时不该还报「已连接」：{:?}",
                m.elapsed(now)
            );
        }

        // Stopping 是另一侧：隧道还在、会话可能真的还开着，报数不是假话。
        // 这一格由 `stopping_keeps_showing_what_is_still_open_until_idle`
        // 正面守着，这里只确认守卫没把它一起收走。
        m.apply(TunnelEvent::State(State::Connected { degraded: false }));
        m.apply(TunnelEvent::State(State::Stopping));
        assert!(m.elapsed(now).is_some(), "Stopping 时隧道还在，该照报");

        // 重新连上：接着从原起点算，不从零重来。
        m.apply(TunnelEvent::State(State::Connected { degraded: true }));
        assert_eq!(m.elapsed(now).unwrap(), "00:01:30", "重连后计时起点丢了");
    }

    /// 笔记本的时钟被往回拨（或 NTP 校时）时 `duration_since` 会失败，
    /// 界面宁可不显示，也不要显示一个负数或者巨大的数。
    #[test]
    fn elapsed_is_none_when_the_clock_went_backwards() {
        let mut m = Model::default();
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        m.apply(TunnelEvent::ConnectedSince(start));
        assert!(m.elapsed(start - Duration::from_secs(1)).is_none());
    }

    #[test]
    fn host_key_first_seen_is_recorded_for_the_diagnostics_page() {
        let mut m = Model::default();
        m.apply(TunnelEvent::HostKey {
            fingerprint: "SHA256:aaa".into(),
            first_seen: true,
        });
        assert_eq!(m.host_key, Some(("SHA256:aaa".to_string(), true)));

        // `first_seen = false` 这一格也得走一遍：只测 true 的话，把
        // `first_seen` 写死成 `true`（诊断页于是永远说"首次记录"）不会红。
        m.apply(TunnelEvent::HostKey {
            fingerprint: "SHA256:bbb".into(),
            first_seen: false,
        });
        assert_eq!(m.host_key, Some(("SHA256:bbb".to_string(), false)));
    }

    /// 预检报告是诊断页（Task 9）唯一的数据来源。brief 一个字都没测它——
    /// 把 `TunnelEvent::Preflight(_)` 那条分支改成 `{}`（整个丢掉报告），
    /// 原来没有任何东西会红。
    #[test]
    fn the_preflight_report_is_kept_for_the_diagnostics_page() {
        let mut m = Model::default();
        assert!(m.preflight.is_none());
        let report = PreflightReport {
            steps: vec![PreflightStep {
                name: STEP_APPLIANCE_TCP,
                outcome: StepOutcome::Pass {
                    detail: "8ms".into(),
                },
            }],
        };
        m.apply(TunnelEvent::Preflight(report.clone()));
        assert_eq!(m.preflight.as_ref(), Some(&report));

        // 新的一份要整份换掉，不是往里追加。
        let empty = PreflightReport { steps: vec![] };
        m.apply(TunnelEvent::Preflight(empty.clone()));
        assert_eq!(m.preflight.as_ref(), Some(&empty));
    }

    /// W129：brief 原稿这条名字叫 stopping，`apply` 的却是 `State::Idle`。
    /// 改名，测它真正测的那件事。Stopping 那一格见下一条。
    #[test]
    fn idle_clears_sessions_and_elapsed() {
        let mut m = connected_with_one_session();
        m.apply(TunnelEvent::State(State::Idle));
        assert!(m.sessions.is_empty());
        assert!(m.elapsed(SystemTime::now()).is_none());
    }

    /// W129 的另一半：Stopping 期间**不**抢着抹掉会话与计时。
    ///
    /// 这是刻意的，不是漏了：拆隧道的那几百毫秒里远程会话可能真的还开着，
    /// 抢先清空是另一个方向的假话；而 rmc-core 的 `Ctx::stop_everything`
    /// 自己会在拆隧道时发一条 `RemoteSessions(vec![])`，界面不需要替它猜。
    /// 把 `apply` 里那个 `matches!(s, State::Idle)` 改成
    /// `matches!(s, State::Idle | State::Stopping)`，这条会红。
    #[test]
    fn stopping_keeps_showing_what_is_still_open_until_idle() {
        let mut m = connected_with_one_session();
        m.apply(TunnelEvent::State(State::Stopping));
        assert_eq!(m.sessions.len(), 1, "正在停止时会话可能还开着，别抢着抹掉");
        assert!(m
            .elapsed(SystemTime::UNIX_EPOCH + Duration::from_secs(5))
            .is_some());

        // 真正到 Idle 才清干净。
        m.apply(TunnelEvent::State(State::Idle));
        assert!(m.sessions.is_empty());
        assert!(m.elapsed(SystemTime::now()).is_none());
    }

    fn connected_with_one_session() -> Model {
        let mut m = Model::default();
        m.apply(TunnelEvent::State(State::Connected { degraded: false }));
        m.apply(TunnelEvent::ConnectedSince(SystemTime::UNIX_EPOCH));
        m.apply(TunnelEvent::RemoteSessions(vec![session(1)]));
        m
    }
}
