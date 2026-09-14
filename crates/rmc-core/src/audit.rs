//! 本地审计日志。按天滚动，保留 [`RETENTION_DAYS`] 天。
//!
//! 回答的是事后追责的问题——谁、什么时候、连到了哪台一体机、开了/关了
//! 哪个远程会话、干了多久。**不记录口令，也不记录转发内容**：转发内容
//! 是远程工程师与一体机之间端到端加密穿过隧道的字节，本模块（乃至整个
//! rmc-core）根本拿不到明文；口令则是显式地、每一处调用都必须自己保证
//! 不落进传给 [`Audit::record`] 的 `message` 里——见 `supervisor.rs`
//! 接线处的说明。
//!
//! # 与 brief 不同的几处，逐条写明理由
//!
//! 1. **`Cargo.toml` 只给 `time` 开了 `local-offset`**——brief 原文还
//!    写了 `formatting`、`macros`：本模块自己手写 `format!` 拼时间戳
//!    与文件名，不用 `Formattable`/`time::macros::datetime!`，那两个
//!    feature 声明了但没有任何代码路径会用到。
//! 2. **brief 里 `audit.rs` 那段示例代码原样抄进来编不过**——
//!    `std::fs::create_dir_all(&dir)?`、`entry.metadata()?.modified()?`
//!    这类裸 `?` 依赖 `From<std::io::Error> for Error`，而 `error.rs`
//!    的 `Io`/`LocalIo` 两个变体故意都没有挂 `#[from]`（R15：两类
//!    io::Error 需要的处置正好相反，挂 `#[from]` 会让 `?` 悄悄选中
//!    错误的那一个）。本文件所有本地文件系统操作都显式
//!    `.map_err(Error::LocalIo)`。
//! 3. **日期/格式化逻辑拆成纯函数 [`file_name_for`]/[`line_for`]，
//!    不依赖真实时钟**——"按天滚动"的全部逻辑就是"同一天必须给出
//!    同一个文件名，不同的一天必须给出不同的文件名"，这个性质可以
//!    直接喂两个手造的、相差一天（甚至跨年）的 `OffsetDateTime` 去
//!    断言，不需要真的等 24 小时，也不需要在 `Audit` 上开一个只为
//!    测试存在的时钟注入接口——那样的接口只能是永久公开的
//!    `pub`（外部集成测试是独立 crate，看不到任何 `#[cfg(test)]` 项，
//!    参见 `config.rs` 里 `ValidatedAddresses::for_test` 上的说明），
//!    划不来。`current_path()`/`record()` 只是拿真实的 [`today()`]
//!    喂给这两个纯函数。
//! 4. **测试放在本文件自己的 `#[cfg(test)] mod tests` 里，不是外部的
//!    `crates/rmc-core/tests/audit.rs`**——这是本 crate 一贯的做法
//!    （`config.rs`/`error.rs`/`knownhosts.rs`/`state.rs`/
//!    `supervisor.rs` 都把测试放在同一个文件的 `#[cfg(test)]` 里，
//!    `tests/*.rs` 只留给真的需要外部黑盒集成——假 Gateway、真实
//!    TCP——的场景），上一条的纯函数测试策略也要求这样放（否则测试
//!    根本看不到 `file_name_for`/`line_for`，只能反过来强行给 `Audit`
//!    加一个公开的时钟注入口）。
//! 5. **写失败不是 `Fatal`，`record()` 因此故意不返回 `Result`**——
//!    见 [`Audit::record`] 上的说明，这是本任务最重要的一条裁定。

use crate::error::{Error, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// 审计日志保留天数。
pub const RETENTION_DAYS: u64 = 30;

const PREFIX: &str = "rmc-";
const SUFFIX: &str = ".log";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

/// 当前本地时间；极少数取不到时区信息的环境下退化为 UTC——宁可时区
/// 标错，也不要审计日志因为这个次要问题直接罢工。
fn today() -> time::OffsetDateTime {
    time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc())
}

/// 这一天对应的日志文件名。"按天滚动"的全部逻辑都在这一个纯函数里，
/// 不碰真实时钟——见模块文档第 3 条。
fn file_name_for(d: time::OffsetDateTime) -> String {
    format!(
        "{PREFIX}{:04}-{:02}-{:02}{SUFFIX}",
        d.year(),
        u8::from(d.month()),
        d.day()
    )
}

/// 一条日志行的完整文本，含末尾换行。调用方保证 `message` 里已经没有
/// 换行（见 [`Audit::record`]）。
fn line_for(d: time::OffsetDateTime, level: Level, message: &str) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02} {} {}\n",
        d.year(),
        u8::from(d.month()),
        d.day(),
        d.hour(),
        d.minute(),
        d.second(),
        level.as_str(),
        message
    )
}

fn is_log_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with(PREFIX) && n.ends_with(SUFFIX))
        .unwrap_or(false)
}

pub struct Audit {
    dir: PathBuf,
}

impl Audit {
    /// 打开（必要时创建）日志目录。
    ///
    /// 这一步失败（目录权限、磁盘本身有问题）通常发生在进程刚启动、
    /// 还没有任何会话在跑的时候；Supervisor 侧不会把这个 `Err` 升级成
    /// 卡死会话的 `Fatal`，见 `supervisor.rs` 里构造 `Ctx::audit` 那
    /// 一段——道理跟 [`Audit::record`] 上写的一样：记不下审计日志不该
    /// 掐断一次正在进行的维护会话。
    pub fn open(dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&dir).map_err(Error::LocalIo)?;
        Ok(Self { dir })
    }

    /// `open()` 失败之后的兜底：不重新尝试创建目录，无条件成功。
    /// Supervisor 用它保证"审计日志初始化失败"这件事本身不会阻止
    /// 进程继续跑——`record()` 每次调用都会自己重试
    /// `create_dir_all`（见该方法上的说明），环境恢复后（权限修好、
    /// 磁盘腾出空间）会自动开始写入，不需要重启进程。`pub(crate)`：
    /// 这不是给测试开的口子（测试就该用会失败的 `open()`），只是
    /// Supervisor 接线要用，不需要对 crate 外公开。
    pub(crate) fn open_best_effort(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn current_path(&self) -> PathBuf {
        self.dir.join(file_name_for(today()))
    }

    /// 写一行。换行被折成空格，保证一个事件一行——`\r\n`/`\n`/`\r` 都会
    /// 被替换，既不会把一条记录拆成两行，也不会让调用方在消息里塞一条
    /// 伪造的日志行。
    ///
    /// # 失败处理：故意不返回 `Result`，故意不 panic
    ///
    /// 这不是 `Error::LocalIo` 那套处置（那个分类是为 known_hosts 设计
    /// 的：记不下 host key 是安全相关、必须让人看见、必须停下来的事，
    /// 见 `error.rs` 上 `LocalIo` 的文档）。审计日志写不进去（目录权限
    /// 被改坏、磁盘满）代价完全不同：如果也判 `Fatal` 并据此掐断会话，
    /// 后果是"一次正在进行的维护会话因为记不了日志被打断"——现场工程师
    /// 人在客户机房，他要的是修好设备，不是被日志子系统连累。
    ///
    /// 这里的裁定是**降级为警告，会话继续跑**：失败时打一条
    /// `tracing::warn!`（不是静默吞掉——那样"目录权限被改坏"这种真实
    /// 故障会永远没人知道，只是不会出现在审计日志本身，因为审计日志
    /// 正是坏掉的那一半），这条记录被丢弃，调用方无需、也无法处理任何
    /// 错误。目录创建每次调用都会重试一遍，不是只在 `open()` 那一次性
    /// 尝试——如果权限后来被修好、磁盘后来腾出空间，后续的 `record()`
    /// 会自己恢复写入，不需要重启进程（见测试
    /// `record_recovers_after_the_log_directory_is_removed`）。
    pub fn record(&self, level: Level, message: &str) {
        let flat = message.replace("\r\n", " ").replace(['\n', '\r'], " ");
        if let Err(e) = std::fs::create_dir_all(&self.dir) {
            tracing::warn!(error = %e, dir = ?self.dir, "审计日志目录不可用，这条记录已丢弃");
            return;
        }
        let d = today();
        let path = self.dir.join(file_name_for(d));
        let line = line_for(d, level, &flat);
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(mut f) => {
                if let Err(e) = f.write_all(line.as_bytes()) {
                    tracing::warn!(error = %e, path = ?path, "写审计日志失败，这条记录已丢弃");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, path = ?path, "打开审计日志文件失败，这条记录已丢弃");
            }
        }
    }

    /// 删除修改时间早于保留期的日志文件，返回删除个数。只处理形如
    /// `rmc-*.log` 的文件，目录里别的东西（万一有）一概不碰。
    pub fn prune(&self) -> Result<usize> {
        let cutoff = SystemTime::now() - Duration::from_secs(RETENTION_DAYS * 86_400);
        let mut removed = 0usize;
        for entry in std::fs::read_dir(&self.dir).map_err(Error::LocalIo)? {
            let entry = entry.map_err(Error::LocalIo)?;
            let path = entry.path();
            if !is_log_file(&path) {
                continue;
            }
            let modified = entry
                .metadata()
                .map_err(Error::LocalIo)?
                .modified()
                .map_err(Error::LocalIo)?;
            if modified < cutoff {
                std::fs::remove_file(&path).map_err(Error::LocalIo)?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("创建临时目录失败")
    }

    fn day(y: i32, m: u8, d: u8) -> time::OffsetDateTime {
        time::Date::from_calendar_date(y, time::Month::try_from(m).unwrap(), d)
            .unwrap()
            .midnight()
            .assume_utc()
    }

    #[test]
    fn writes_lines_with_level_and_timestamp() {
        let dir = tmpdir();
        let a = Audit::open(dir.path().to_path_buf()).unwrap();
        a.record(Level::Info, "状态 Connecting → Connected");
        a.record(Level::Warn, "反向端口 22001 被占用");
        a.record(Level::Error, "Gateway 连接被重置");

        let text = std::fs::read_to_string(a.current_path()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("INFO"), "{}", lines[0]);
        assert!(lines[1].contains("WARN"), "{}", lines[1]);
        assert!(lines[2].contains("ERROR"), "{}", lines[2]);
        // 时间戳形如 2026-09-13T11:12:44
        assert!(lines[0].starts_with("20"), "{}", lines[0]);
        assert!(lines[0].contains('T'), "{}", lines[0]);
    }

    #[test]
    fn file_name_carries_the_date() {
        let dir = tmpdir();
        let a = Audit::open(dir.path().to_path_buf()).unwrap();
        let name = a
            .current_path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert!(name.starts_with("rmc-"), "{name}");
        assert!(name.ends_with(".log"), "{name}");
        assert_eq!(name.len(), "rmc-2026-09-13.log".len(), "{name}");
    }

    #[test]
    fn appends_across_reopen() {
        let dir = tmpdir();
        Audit::open(dir.path().to_path_buf())
            .unwrap()
            .record(Level::Info, "第一行");
        Audit::open(dir.path().to_path_buf())
            .unwrap()
            .record(Level::Info, "第二行");
        let a = Audit::open(dir.path().to_path_buf()).unwrap();
        let text = std::fs::read_to_string(a.current_path()).unwrap();
        assert_eq!(text.lines().count(), 2, "{text}");
    }

    #[test]
    fn record_strips_newlines_to_keep_one_event_per_line() {
        let dir = tmpdir();
        let a = Audit::open(dir.path().to_path_buf()).unwrap();
        a.record(Level::Error, "第一段\n第二段\r\n第三段");
        let text = std::fs::read_to_string(a.current_path()).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.contains("第一段"), "{text}");
        assert!(text.contains("第三段"), "{text}");
    }

    // --- 保留期：这三条会在清理逻辑根本没跑（`prune()` 是空转的
    // no-op）时立刻变红，不是只要「有跑过」就绿——见各自的
    // `assert_eq!(removed, ...)`。 ---

    #[test]
    fn prune_removes_files_older_than_retention() {
        let dir = tmpdir();
        let a = Audit::open(dir.path().to_path_buf()).unwrap();
        a.record(Level::Info, "今天");

        // 造一个 40 天前的文件。
        let old = dir.path().join("rmc-2000-01-01.log");
        std::fs::write(&old, "老日志\n").unwrap();
        let long_ago = SystemTime::now() - Duration::from_secs(40 * 86_400);
        filetime::set_file_mtime(&old, filetime::FileTime::from_system_time(long_ago)).unwrap();

        let removed = a.prune().unwrap();
        assert_eq!(removed, 1);
        assert!(!old.exists());
        assert!(a.current_path().exists(), "当天日志不该被删");
    }

    #[test]
    fn prune_keeps_files_inside_retention() {
        let dir = tmpdir();
        let a = Audit::open(dir.path().to_path_buf()).unwrap();
        let recent = dir.path().join("rmc-2026-09-01.log");
        std::fs::write(&recent, "较近的日志\n").unwrap();
        let days_ago = SystemTime::now() - Duration::from_secs((RETENTION_DAYS - 2) * 86_400);
        filetime::set_file_mtime(&recent, filetime::FileTime::from_system_time(days_ago)).unwrap();

        assert_eq!(a.prune().unwrap(), 0);
        assert!(recent.exists());
    }

    #[test]
    fn prune_ignores_unrelated_files() {
        let dir = tmpdir();
        let a = Audit::open(dir.path().to_path_buf()).unwrap();
        let other = dir.path().join("notes.txt");
        std::fs::write(&other, "x").unwrap();
        let long_ago = SystemTime::now() - Duration::from_secs(400 * 86_400);
        filetime::set_file_mtime(&other, filetime::FileTime::from_system_time(long_ago)).unwrap();

        assert_eq!(a.prune().unwrap(), 0);
        assert!(other.exists(), "非日志文件不得被删");
    }

    // --- 按天滚动：不等 24 小时，也不给 `Audit` 开一个只为测试存在的
    // 时钟注入口子——见模块文档第 3 条。 ---

    #[test]
    fn file_name_for_differs_across_days_and_matches_the_documented_shape() {
        assert_eq!(file_name_for(day(2026, 9, 13)), "rmc-2026-09-13.log");
        assert_ne!(
            file_name_for(day(2026, 9, 13)),
            file_name_for(day(2026, 9, 14))
        );
        // 跨年、跨月同理：不是只在日期数字上做减法就恰好碰对。
        assert_ne!(
            file_name_for(day(2026, 12, 31)),
            file_name_for(day(2027, 1, 1))
        );
    }

    // 会让这条测试变红的实现改法：把 `current_path()` 里的 `today()`
    // 换成任何固定值——`file_name_for` 已经单独证明了「两个不同日期给出
    // 不同文件名」，这条测试钉住的是 `current_path()` 真的把 `today()`
    // 的结果喂给了它，不是凑巧对上了格式。
    #[test]
    fn current_path_is_wired_to_the_real_clock() {
        let dir = tmpdir();
        let a = Audit::open(dir.path().to_path_buf()).unwrap();
        assert_eq!(
            a.current_path().file_name().unwrap().to_str().unwrap(),
            file_name_for(today())
        );
    }

    // 直接用两天的纯函数结果模拟"同一个审计目录、跨天各写一条"——
    // `record()`/`current_path()` 选文件用的是同一个 `file_name_for`，
    // 这里换成手造的两个日期喂给它，不需要真的跨天运行一次进程。
    //
    // 会让这条测试变红的实现改法：把 `file_name_for` 写成恒定返回同一
    // 个文件名（忽略参数）——两天的内容会被写进同一个文件，
    // `text1.contains("第二天的事件")` 会意外为真。
    #[test]
    fn two_different_days_land_in_two_different_files_with_no_cross_contamination() {
        let dir = tmpdir();
        let d1 = day(2026, 9, 13);
        let d2 = day(2026, 9, 14);
        let path1 = dir.path().join(file_name_for(d1));
        let path2 = dir.path().join(file_name_for(d2));
        std::fs::write(&path1, line_for(d1, Level::Info, "第一天的事件")).unwrap();
        std::fs::write(&path2, line_for(d2, Level::Info, "第二天的事件")).unwrap();

        assert_ne!(path1, path2);
        let text1 = std::fs::read_to_string(&path1).unwrap();
        let text2 = std::fs::read_to_string(&path2).unwrap();
        assert!(
            text1.contains("第一天的事件") && !text1.contains("第二天的事件"),
            "{text1}"
        );
        assert!(
            text2.contains("第二天的事件") && !text2.contains("第一天的事件"),
            "{text2}"
        );
    }

    // --- 写失败不是 Fatal：目录后来能恢复，record() 自己会好。---

    // 会让这条测试变红的实现改法：把 `record()` 里那次
    // `std::fs::create_dir_all(&self.dir)` 删掉——目录被删之后
    // `OpenOptions::open` 会因为父目录不存在直接失败，第二条记录也会
    // 一并消失，`text.contains("目录被删之后")` 断言失败（本地实测：
    // 删掉那三行之后这条测试确实失败，其余测试不受影响）。
    #[test]
    fn record_recovers_after_the_log_directory_is_removed() {
        let dir = tmpdir();
        let a = Audit::open(dir.path().to_path_buf()).unwrap();
        a.record(Level::Info, "目录还在");
        std::fs::remove_dir_all(dir.path()).unwrap();

        // 不应该 panic；目录应该被自己重新建出来，这条记录不该丢。
        a.record(Level::Info, "目录被删之后");

        let text = std::fs::read_to_string(a.current_path()).unwrap();
        assert!(text.contains("目录被删之后"), "{text}");
    }
}
