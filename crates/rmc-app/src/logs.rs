//! 日志页的数据。默认显示最近 [`TAIL_LIMIT`] 条，四个筛选标签各带计数。
//!
//! 这里没有一个 `iced::Element`：跟 `theme`/`model`/`diag` 一样，日志页的
//! 全部判断在这里，视图只负责把结果摆进控件（见 crate 根的模块文档）。
//!
//! # 读的是审计日志，不是 `tracing` 的输出
//!
//! `main()` 里那份 `tracing_subscriber` 写的是 stdout，发布态（`windows
//! _subsystem = "windows"`）根本没人接。日志页读的是 `rmc_core::audit`
//! 按天滚动写在 `log_dir` 下的 `rmc-YYYY-MM-DD.log`——也就是诊断包里
//! `logs/` 那几个文件的同一份东西。文件名怎么拼由
//! [`rmc_core::audit::current_path_in`] 说了算，这里不另写一份。
//!
//! # W174：两个出口都带类型，一个都不许压平
//!
//! 这是本项目同一个缺陷类的第六次。前五次是 Task 2 的 `resolve()`、
//! Task 3 的 `next_token()`、Task 4 的 `load()`、Task 8 的 `validate()`、
//! Task 9 的 `advice_for()`，五次的解法都一样：**带类型的出口**。
//!
//! - [`parse_line`] 不返回 `Option`。`None` 会把「这行根本不是本产品写的
//!   日志」（文件被人往里粘了点别的东西）与「是日志但格式坏了」（写到
//!   一半断电、等级字段被改过）压成同一件事，而这两件事在界面上该说的
//!   话完全不同。
//! - [`tail`] 不返回 `Vec`。`Vec::new()` 会把「日志目录读不了」与「今天
//!   还没写过日志」压成同一个空列表——**而日志页正是用户出问题时唯一
//!   会去看的地方**。一个权限不对的日志目录在界面上长得跟"一切正常，
//!   只是还没有日志"一模一样，是这一页能犯的最糟的错。

use std::path::Path;

/// 页面默认显示的条数上限。画板底部那行字（「最近 200 条 · …」）用的
/// 就是它，不另写一份数字。
pub const TAIL_LIMIT: usize = 200;

// =====================================================================
// 等级
// =====================================================================

/// 一条日志的等级。**只有三格**——这是 `rmc_core::audit::Level` 的镜像，
/// 那边写进文件的就是 `INFO`/`WARN`/`ERROR` 三种。
///
/// 跟 [`LogFilter`] 是**两个类型**，不是一个。brief 原稿把「全部」也做成
/// 了等级的一个变体，于是 `LogLine { level: LogFilter::All }` 这种毫无
/// 意义的值在类型上完全构造得出来，而界面会老老实实把它画成一行等级是
/// 「全部」的日志。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// 等级总数。
    ///
    /// **W175 的落点**：[`Self::ALL`] 与 [`LogFilter::ALL`] 的长度都从它
    /// 算出来，加一个变体而不改这个数字，两个数组字面量会**编译不过**
    /// （`expected an array with a size of 3`）——不是某条测试变红，是
    /// 根本编译不了。Task 9 的 `declare_proxy_auth_summary!` 是同一个
    /// 手法，这里只有三格，不值得再上一个宏。
    pub const COUNT: usize = 3;

    /// 全部等级，按严重度递增。
    pub const ALL: [LogLevel; Self::COUNT] = [LogLevel::Info, LogLevel::Warn, LogLevel::Error];

    /// 日志文件里写的那个词。跟 `rmc_core::audit::Level::as_str` 对齐——
    /// 那边是写入侧，这里是读取侧，两边必须认同一套词，
    /// [`tests::every_level_this_page_knows_is_a_level_the_audit_log_writes`]
    /// 守这条。
    pub fn tag(self) -> &'static str {
        match self {
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }

    /// 筛选标签上的中文名。
    pub fn label(self) -> &'static str {
        match self {
            LogLevel::Info => "信息",
            LogLevel::Warn => "警告",
            LogLevel::Error => "错误",
        }
    }

    /// 从文件里那个词认回来。**大小写敏感**：审计日志是我们自己写的，
    /// 一定是大写；放宽会让一行别的什么东西被当成日志收进来。
    pub fn from_tag(tag: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.tag() == tag)
    }
}

// =====================================================================
// 一行
// =====================================================================

/// 日志页上的一行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// 只有时分秒（`11:12:44`）。日期在文件名上，一屏里重复 200 遍没有
    /// 意义；时区偏移量同理（同一个文件里恒定相同）。
    pub time: String,
    pub level: LogLevel,
    pub message: String,
}

/// 这一行为什么没能变成 [`LogLine`]。
///
/// W174：**不是 `Option`**。见模块文档。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineReject {
    /// 空行（或只有空白）。每个日志文件末尾都有一个，不是毛病，
    /// 也不该被算进"读不懂的行数"。
    Blank,
    /// 行首那一段不是时间戳——这行根本不是本产品写的日志。有人往目录里
    /// 放了别的 `rmc-*.log`，或者把别的东西粘了进来。
    NotALogLine,
    /// 是日志的形状，但某处坏了。这一类**值得在界面上说一句**：它意味着
    /// 日志文件本身出了问题（写到一半断电、被别的程序改过）。
    Malformed(Malformed),
}

/// 坏在哪儿。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// 有时间戳，但后面没有等级与正文了。
    Truncated,
    /// `T` 后面那段不是时分秒。
    BadTime,
    /// 等级字段不是 `INFO`/`WARN`/`ERROR` 里的任何一个。
    UnknownLevel,
    /// 有等级，但正文是空的。
    EmptyMessage,
}

/// 解析 `rmc_core::audit` 写出的一行。
///
/// 真实格式带时区偏移量（`line_for` 把 `±HH:MM` 显式写进时间戳，那是
/// R87 的裁定）：
///
/// ```text
/// 2026-09-13T11:12:44+08:00 INFO 预检通过，开始连接运维服务器
/// ```
///
/// **brief 给的样例没有偏移量**，照它写出来的实现会让界面上每一行都显示
/// `11:12:44+08:00`。两种都认。
pub fn parse_line(raw: &str) -> Result<LogLine, LineReject> {
    if raw.trim().is_empty() {
        return Err(LineReject::Blank);
    }
    let mut parts = raw.trim_end().splitn(3, ' ');
    let stamp = parts.next().unwrap_or_default();

    // 先判"这到底是不是一行日志"，再判"它坏在哪儿"——顺序反过来的话，
    // 一行随便什么文字会被判成 `Malformed`，界面上就会报一条并不存在的
    // "日志文件损坏"。
    let Some((_date, rest)) = stamp.split_once('T') else {
        return Err(LineReject::NotALogLine);
    };
    // 偏移量（`+08:00` / `-05:00` / `Z`）不上屏：同一个文件里它恒定相同。
    let time = match rest.find(['+', '-', 'Z']) {
        Some(cut) => &rest[..cut],
        None => rest,
    };
    if time.is_empty() || !time.chars().all(|c| c.is_ascii_digit() || c == ':') {
        return Err(LineReject::Malformed(Malformed::BadTime));
    }

    let Some(tag) = parts.next() else {
        return Err(LineReject::Malformed(Malformed::Truncated));
    };
    let Some(level) = LogLevel::from_tag(tag) else {
        return Err(LineReject::Malformed(Malformed::UnknownLevel));
    };
    let message = parts.next().unwrap_or_default().trim();
    if message.is_empty() {
        return Err(LineReject::Malformed(Malformed::EmptyMessage));
    }

    Ok(LogLine {
        time: time.to_string(),
        level,
        message: message.to_string(),
    })
}

// =====================================================================
// 读文件
// =====================================================================

/// 读一份日志文件的结局。
///
/// W174：**不是 `Vec<LogLine>`**。见模块文档——「日志目录读不了」与
/// 「今天还没写过日志」必须在界面上长得不一样。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogTail {
    /// 文件还不在。今天还没有任何一条审计记录被写下来——**不是错误**，
    /// 刚装好、还没点过「开启远程维护」的机器就是这样。
    NotWrittenYet,
    /// 文件在（或者目录在），但读不出来：权限不对、被别的进程独占、
    /// 路径被一个目录占住。带的是 `io::Error` 的说明。
    Unreadable(String),
    /// 读到了。
    Lines {
        lines: Vec<LogLine>,
        /// 读不懂、被丢掉的行数（**不含空行**）。不为零时界面上要说一句：
        /// 它意味着这份日志文件本身有问题。
        skipped: usize,
    },
}

impl LogTail {
    /// 能画出来的那些行。三种结局下都能问，前两种是空的。
    pub fn lines(&self) -> &[LogLine] {
        match self {
            Self::NotWrittenYet | Self::Unreadable(_) => &[],
            Self::Lines { lines, .. } => lines,
        }
    }

    /// 列表为空（或有坏行）时该顶在页面上的那句话，`None` 表示没什么要
    /// 说的。
    ///
    /// 这是 W174 在界面上的落地：三种结局各说各的话。写成方法而不是让
    /// 视图自己 `match`，理由见 crate 根的模块文档——视图里的判断在这台
    /// 机器上没有任何东西看得见。
    pub fn notice(&self) -> Option<String> {
        match self {
            Self::NotWrittenYet => Some("今天还没有日志。开启一次远程维护就会有记录。".into()),
            Self::Unreadable(detail) => Some(format!(
                "日志读不出来：{detail}。请确认这个目录仍然可读，再重开客户端。"
            )),
            Self::Lines { lines, skipped } => match (lines.is_empty(), *skipped) {
                (true, 0) => Some("今天还没有日志。开启一次远程维护就会有记录。".into()),
                (true, n) => Some(format!("这份日志里的 {n} 行都读不懂，文件可能已经损坏。")),
                (false, 0) => None,
                (false, n) => Some(format!("有 {n} 行读不懂，已跳过；文件可能被改过。")),
            },
        }
    }
}

/// 读取 `path` 末尾至多 `limit` 条日志。
///
/// **整份读进来再切尾**：审计日志按天滚动，一天的量在现场是几百行级别，
/// 为省这点内存去做反向分块读，换来的是一个会在多字节字符中间切断的
/// 边界条件——而这份文件里全是中文。
pub fn tail(path: &Path, limit: usize) -> LogTail {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return LogTail::NotWrittenYet,
        Err(e) => return LogTail::Unreadable(e.to_string()),
    };

    let mut lines = Vec::new();
    let mut skipped = 0usize;
    for raw in text.lines() {
        match parse_line(raw) {
            Ok(l) => lines.push(l),
            // 空行不算"读不懂"：文件末尾那一个永远在。
            Err(LineReject::Blank) => {}
            Err(_) => skipped += 1,
        }
    }
    let start = lines.len().saturating_sub(limit);
    lines.drain(..start);
    LogTail::Lines { lines, skipped }
}

// =====================================================================
// 计数与筛选
// =====================================================================

/// 四个筛选标签。
///
/// W175：长度从 [`LogLevel::COUNT`] 算出来，加一个等级而不往这里加一格
/// **编译不过**。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogFilter {
    /// 不筛等级。
    All,
    /// 只看这一个等级。
    Only(LogLevel),
}

impl LogFilter {
    /// 四个标签，从左到右。
    pub const ALL: [LogFilter; LogLevel::COUNT + 1] = [
        LogFilter::All,
        LogFilter::Only(LogLevel::Info),
        LogFilter::Only(LogLevel::Warn),
        LogFilter::Only(LogLevel::Error),
    ];

    /// 标签上的字。
    pub fn label(self) -> &'static str {
        match self {
            LogFilter::All => "全部",
            LogFilter::Only(l) => l.label(),
        }
    }

    /// 这一行要不要留下。
    pub fn admits(self, level: LogLevel) -> bool {
        match self {
            LogFilter::All => true,
            LogFilter::Only(want) => want == level,
        }
    }
}

impl Default for LogFilter {
    fn default() -> Self {
        Self::All
    }
}

/// 四个标签各自的计数。
///
/// # W175：为什么不是 `[usize; 4]`
///
/// brief 原稿是一个**按位置索引的裸数组**，`c[2] += 1` 是警告、
/// `c[3] += 1` 是错误。把这两行对调，编译照过、界面照画，只是警告的数字
/// 跑到了错误那一格上——而现场看日志页的第一眼看的就是"有几条错误"。
///
/// 具名字段之后，唯一还能写错的地方收进了 [`Self::slot`] 那一个穷尽
/// `match`，而 [`tests::each_level_lands_in_its_own_slot`] 逐格钉住它。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LevelCounts {
    pub total: usize,
    pub info: usize,
    pub warn: usize,
    pub error: usize,
}

impl LevelCounts {
    /// 某个等级那一格。**穷尽 `match`，没有兜底**。
    fn slot(&mut self, level: LogLevel) -> &mut usize {
        match level {
            LogLevel::Info => &mut self.info,
            LogLevel::Warn => &mut self.warn,
            LogLevel::Error => &mut self.error,
        }
    }

    /// 某个标签上该显示的数字。
    pub fn of(&self, filter: LogFilter) -> usize {
        match filter {
            LogFilter::All => self.total,
            LogFilter::Only(LogLevel::Info) => self.info,
            LogFilter::Only(LogLevel::Warn) => self.warn,
            LogFilter::Only(LogLevel::Error) => self.error,
        }
    }
}

/// 四个标签的计数。
pub fn counts(lines: &[LogLine]) -> LevelCounts {
    let mut c = LevelCounts {
        total: lines.len(),
        ..LevelCounts::default()
    };
    for l in lines {
        *c.slot(l.level) += 1;
    }
    c
}

/// 按等级与搜索词筛。搜索**大小写不敏感**，只查正文。
pub fn filter<'a>(lines: &'a [LogLine], f: LogFilter, query: &str) -> Vec<&'a LogLine> {
    let q = query.trim().to_lowercase();
    lines
        .iter()
        .filter(|l| f.admits(l.level))
        .filter(|l| q.is_empty() || l.message.to_lowercase().contains(&q))
        .collect()
}

/// 页面底部那一行：「最近 200 条 · rmc-2026-09-13.log · 保留 30 天」。
///
/// 三个数字全都不是写死的：条数是 [`TAIL_LIMIT`]，保留天数是
/// `rmc_core::audit::RETENTION_DAYS`（清理逻辑的同一份常量），文件名由
/// 调用方从 [`rmc_core::audit::current_path_in`] 取。
pub fn footer(file_name: &str) -> String {
    format!(
        "最近 {TAIL_LIMIT} 条 · {file_name} · 保留 {} 天",
        rmc_core::audit::RETENTION_DAYS
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
2026-09-13T11:12:44+08:00 INFO 预检通过，开始连接运维服务器
2026-09-13T11:12:45+08:00 INFO TLS 1.3 握手完成
2026-09-13T11:14:02+08:00 WARN 一体机首包延迟 480 ms
2026-09-13T11:52:31+08:00 ERROR 运维服务器连接被重置
2026-09-13T11:52:33+08:00 WARN 反向端口 22001 仍被占用
";

    fn lines() -> Vec<LogLine> {
        SAMPLE.lines().filter_map(|l| parse_line(l).ok()).collect()
    }

    // ================= 解析 =================

    #[test]
    fn parses_time_level_and_message() {
        let l = parse_line("2026-09-13T11:12:44+08:00 INFO 预检通过").unwrap();
        assert_eq!(l.time, "11:12:44");
        assert_eq!(l.level, LogLevel::Info);
        assert_eq!(l.message, "预检通过");
    }

    /// **时区偏移量不上屏。**
    ///
    /// brief 给的样例时间戳没有偏移量，而 `rmc_core::audit::line_for`
    /// 写出来的每一行都有（R87 的裁定：退化到 UTC 时要能从日志本身看
    /// 出来）。照 brief 写的实现在真实日志上会让每一行都显示
    /// `11:12:44+08:00`，一屏 200 行全是这个尾巴。
    ///
    /// 改红：把 `rest.find(['+', '-', 'Z'])` 那一段删掉。
    #[test]
    fn the_timezone_offset_never_reaches_the_screen() {
        for (raw, want) in [
            ("2026-09-13T11:12:44+08:00 INFO x", "11:12:44"),
            ("2026-09-13T11:12:44-05:30 INFO x", "11:12:44"),
            ("2026-09-13T11:12:44Z INFO x", "11:12:44"),
            // 不带偏移量的也照认。
            ("2026-09-13T11:12:44 INFO x", "11:12:44"),
            ("2026-09-13T1:1:1 INFO x", "1:1:1"),
        ] {
            assert_eq!(parse_line(raw).unwrap().time, want, "{raw}");
        }
    }

    #[test]
    fn parses_all_three_levels() {
        for level in LogLevel::ALL {
            let raw = format!("2026-09-13T1:1:1 {} x", level.tag());
            assert_eq!(parse_line(&raw).unwrap().level, level, "{raw}");
        }
    }

    /// **W174：三类拒绝各是各的，不许压成一个 `None`。**
    ///
    /// 这张表就是那个「带类型的出口」的全部价值：把返回类型换回
    /// `Option<LogLine>`，这条编译不过；把 `NotALogLine` 那一支改成
    /// `Malformed(BadTime)`（也就是"随便一行文字也算日志损坏"），
    /// 第二组断言红——而界面会对着一个粘进来的 README 报"日志文件
    /// 可能已损坏"。
    #[test]
    fn every_kind_of_bad_line_is_rejected_for_its_own_reason() {
        let cases = [
            ("", LineReject::Blank),
            ("   ", LineReject::Blank),
            ("no timestamp here", LineReject::NotALogLine),
            ("随便一行中文", LineReject::NotALogLine),
            (
                "2026-09-13T11:12:44+08:00",
                LineReject::Malformed(Malformed::Truncated),
            ),
            (
                "2026-09-13Txx:yy INFO 正文",
                LineReject::Malformed(Malformed::BadTime),
            ),
            (
                "2026-09-13T11:12:44 TRACE 正文",
                LineReject::Malformed(Malformed::UnknownLevel),
            ),
            (
                "2026-09-13T11:12:44 INFO    ",
                LineReject::Malformed(Malformed::EmptyMessage),
            ),
        ];
        for (raw, want) in &cases {
            assert_eq!(parse_line(raw), Err(want.clone()), "「{raw}」");
        }

        // 反向自证：这张表里真的出现了每一种拒绝，不是八行都落在同一格。
        let kinds: std::collections::BTreeSet<String> = cases
            .iter()
            .map(|(_, r)| format!("{r:?}"))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(kinds.len(), 2 + 4, "{kinds:?}");
    }

    /// 读取侧认得的那三个词，就是写入侧写下去的那三个。
    ///
    /// 改红：把 `LogLevel::Error` 的 `tag()` 写成 `"ERR"`（画板上那一列
    /// 画的正是 `ERR`，很容易顺手写进来）——这条立刻红，而真实日志里
    /// 每一条 `ERROR` 都会被当成"等级不认识"丢掉，错误计数恒为 0。
    #[test]
    fn every_level_this_page_knows_is_a_level_the_audit_log_writes() {
        use rmc_core::audit::Level;
        let written: Vec<String> = [Level::Info, Level::Warn, Level::Error]
            .iter()
            .map(|l| {
                // 写入侧没有公开的 `as_str`，从它真的写出来的一行里取。
                let dir = tempfile::tempdir().expect("建临时目录");
                let a = rmc_core::audit::Audit::open(dir.path().to_path_buf()).unwrap();
                a.record(*l, "取一行样本");
                let text = std::fs::read_to_string(a.current_path()).unwrap();
                text.split_whitespace().nth(1).unwrap().to_string()
            })
            .collect();
        let known: Vec<String> = LogLevel::ALL.iter().map(|l| l.tag().to_string()).collect();
        assert_eq!(known, written, "读取侧与写入侧对等级的叫法不一致");
    }

    /// 审计日志真的写出来的一行，这一页真的读得懂。
    ///
    /// 上面那条只比了等级那个词，这条走完整条路：`audit` 写一行 →
    /// [`tail`] 读回来 → 内容对得上。少了它，时间戳格式变了
    /// （比如哪天 `line_for` 改用 `Z`）不会有任何东西红。
    #[test]
    fn a_line_the_audit_log_really_wrote_is_read_back_intact() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let a = rmc_core::audit::Audit::open(dir.path().to_path_buf()).unwrap();
        a.record(rmc_core::audit::Level::Warn, "反向端口 22001 仍被占用");

        let got = tail(&rmc_core::audit::current_path_in(dir.path()), TAIL_LIMIT);
        match &got {
            LogTail::Lines { lines, skipped } => {
                assert_eq!(*skipped, 0, "自己写的日志自己读不懂：{got:?}");
                assert_eq!(lines.len(), 1);
                assert_eq!(lines[0].level, LogLevel::Warn);
                assert_eq!(lines[0].message, "反向端口 22001 仍被占用");
                // 时分秒，不带日期也不带偏移量。
                assert_eq!(lines[0].time.matches(':').count(), 2, "{:?}", lines[0].time);
                assert!(!lines[0].time.contains('+'), "{:?}", lines[0].time);
            }
            other => panic!("{other:?}"),
        }
    }

    // ================= 计数 =================

    /// **每个等级都落在自己那一格里。**
    ///
    /// W175：这条是那张表的全部理由。把 [`LevelCounts::slot`] 里
    /// `Warn` 与 `Error` 两支对调（复制粘贴最容易犯的错），编译照过、
    /// 界面照画——这条当场红，而且能说出是哪一格错了。
    #[test]
    fn each_level_lands_in_its_own_slot() {
        for level in LogLevel::ALL {
            let lines: Vec<LogLine> = (0..3)
                .map(|i| LogLine {
                    time: "11:00:00".into(),
                    level,
                    message: format!("第 {i} 行"),
                })
                .collect();
            let c = counts(&lines);
            assert_eq!(c.total, 3, "{level:?}");
            assert_eq!(
                c.of(LogFilter::Only(level)),
                3,
                "{level:?} 那一格没有收到自己的三行：{c:?}"
            );
            // 其余两格必须是 0——少了这一半，两格对调仍然全绿。
            for other in LogLevel::ALL.into_iter().filter(|o| *o != level) {
                assert_eq!(
                    c.of(LogFilter::Only(other)),
                    0,
                    "{level:?} 的行跑到了 {other:?} 那一格：{c:?}"
                );
            }
        }
    }

    #[test]
    fn counts_cover_all_four_chips() {
        let c = counts(&lines());
        assert_eq!(c.of(LogFilter::All), 5);
        assert_eq!(c.of(LogFilter::Only(LogLevel::Info)), 2);
        assert_eq!(c.of(LogFilter::Only(LogLevel::Warn)), 2);
        assert_eq!(c.of(LogFilter::Only(LogLevel::Error)), 1);
        // 四个标签一个不漏地都有一个数字可显示。
        assert_eq!(LogFilter::ALL.len(), LogLevel::COUNT + 1);
        assert_eq!(
            LogFilter::ALL.iter().map(|f| c.of(*f)).sum::<usize>(),
            5 + 5,
            "「全部」那一格应当恰好等于其余三格之和"
        );
    }

    #[test]
    fn the_four_chip_labels_are_the_agreed_words() {
        let labels: Vec<&str> = LogFilter::ALL.iter().map(|f| f.label()).collect();
        assert_eq!(labels, vec!["全部", "信息", "警告", "错误"]);
    }

    // ================= 筛选 =================

    #[test]
    fn filter_all_returns_everything() {
        assert_eq!(filter(&lines(), LogFilter::All, "").len(), 5);
    }

    #[test]
    fn filter_by_level() {
        let l = lines();
        assert_eq!(filter(&l, LogFilter::Only(LogLevel::Warn), "").len(), 2);
        assert_eq!(filter(&l, LogFilter::Only(LogLevel::Error), "").len(), 1);
    }

    #[test]
    fn filter_by_query_is_case_insensitive_substring() {
        let l = lines();
        assert_eq!(filter(&l, LogFilter::All, "tls").len(), 1);
        assert_eq!(filter(&l, LogFilter::All, "TLS").len(), 1);
        assert_eq!(filter(&l, LogFilter::All, "端口").len(), 1);
        assert_eq!(filter(&l, LogFilter::All, "  端口  ").len(), 1);
    }

    #[test]
    fn filter_combines_level_and_query() {
        let l = lines();
        assert_eq!(filter(&l, LogFilter::Only(LogLevel::Warn), "端口").len(), 1);
        assert_eq!(filter(&l, LogFilter::Only(LogLevel::Info), "端口").len(), 0);
    }

    /// 搜索只查正文，不查时间与等级。
    ///
    /// 不是洁癖：查等级会让搜 `error` 的人得到一堆等级是 ERROR 但正文
    /// 里没有这个词的行，而那正是"我要找的是哪条出错了"的反面。等级
    /// 该用上面那四个标签筛。
    #[test]
    fn the_search_box_looks_at_the_message_only() {
        let l = lines();
        assert_eq!(filter(&l, LogFilter::All, "11:12").len(), 0, "搜到了时间");
        assert_eq!(filter(&l, LogFilter::All, "WARN").len(), 0, "搜到了等级");
        // 反向自证：这两个词确实出现在数据里（只是不在正文里）。
        assert!(l.iter().any(|x| x.time.starts_with("11:12")));
        assert!(l.iter().any(|x| x.level == LogLevel::Warn));
    }

    // ================= 读文件 =================

    #[test]
    fn tail_returns_the_last_lines_in_order_and_caps_at_the_limit() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let path = dir.path().join("rmc-2026-09-13.log");
        let many: String = (0..500)
            .map(|i| format!("2026-09-13T11:00:00+08:00 INFO 第 {i} 行\n"))
            .collect();
        std::fs::write(&path, many).unwrap();

        let got = tail(&path, TAIL_LIMIT);
        let lines = got.lines();
        assert_eq!(lines.len(), 200);
        assert_eq!(lines.first().unwrap().message, "第 300 行");
        assert_eq!(lines.last().unwrap().message, "第 499 行");
        assert!(got.notice().is_none(), "一切正常时不该顶一句话：{got:?}");
    }

    /// **W174 的主断言：三种结局在界面上长得不一样。**
    ///
    /// 改红：把 `tail` 的返回类型换回 `Vec<LogLine>`（也就是 brief 的
    /// 原稿），这条编译不过；把 `Err(e) => LogTail::Unreadable(..)` 那一支
    /// 改成 `LogTail::NotWrittenYet`（"读不了就当没有"），第二组断言红。
    ///
    /// 目录权限那条路在 CI 的 root 环境下不可靠，所以这里用另一种**必然
    /// 不是 NotFound** 的 IO 错误：把一个**目录**当日志文件去读。
    #[test]
    fn a_log_that_cannot_be_read_never_looks_like_a_log_that_is_not_there_yet() {
        let dir = tempfile::tempdir().expect("建临时目录");

        let missing = tail(&dir.path().join("rmc-2099-01-01.log"), TAIL_LIMIT);
        assert_eq!(missing, LogTail::NotWrittenYet);

        // 路径被一个目录占住：读它必然失败，而且不是 NotFound。
        let occupied = dir.path().join("rmc-2026-09-13.log");
        std::fs::create_dir(&occupied).unwrap();
        let unreadable = tail(&occupied, TAIL_LIMIT);
        assert!(
            matches!(unreadable, LogTail::Unreadable(_)),
            "读不出来的日志被当成了「还没有日志」：{unreadable:?}"
        );

        // 两者在界面上说的话必须不一样——这才是这个类型存在的理由。
        let a = missing.notice().expect("还没有日志也要说一句");
        let b = unreadable.notice().expect("读不出来更要说一句");
        assert_ne!(a, b);
        assert!(b.contains("读不出来"), "{b}");
        // 而且两者都不是"静悄悄一片空白"。
        assert!(missing.lines().is_empty() && unreadable.lines().is_empty());
    }

    /// 坏行被跳过，而且**数得出来**、在界面上说得出来。
    #[test]
    fn broken_lines_are_counted_and_reported_but_do_not_hide_the_good_ones() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let path = dir.path().join("rmc-2026-09-13.log");
        std::fs::write(
            &path,
            "2026-09-13T11:00:00+08:00 INFO 好的一行\n\
             2026-09-13T11:00:01+08:00 TRACE 等级不认识\n\
             \n\
             2026-09-13T11:00:02+08:00 WARN 另一行好的\n",
        )
        .unwrap();

        match tail(&path, TAIL_LIMIT) {
            LogTail::Lines { lines, skipped } => {
                assert_eq!(lines.len(), 2, "好行被坏行连累了");
                assert_eq!(skipped, 1, "空行不该算进读不懂的行数");
            }
            other => panic!("{other:?}"),
        }
        let notice = tail(&path, TAIL_LIMIT).notice().expect("有坏行就该说一句");
        assert!(notice.contains('1'), "{notice}");
    }

    // ================= 底部那一行 =================

    #[test]
    fn the_footer_names_the_limit_the_file_and_the_retention() {
        let line = footer("rmc-2026-09-13.log");
        assert!(line.contains("200"), "{line}");
        assert!(line.contains("rmc-2026-09-13.log"), "{line}");
        assert!(
            line.contains(&rmc_core::audit::RETENTION_DAYS.to_string()),
            "保留天数没有来自 audit::RETENTION_DAYS：{line}"
        );
        for banned in crate::BANNED_WORDS {
            assert!(!line.contains(banned), "{line}");
        }
    }
}
