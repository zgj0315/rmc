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
//!
//! # 复审第一轮追加的修复（R85-R87），逐条写明理由
//!
//! 6. **[R85] `Audit` 的时钟收进一个可替换的字段**——第 3 条那套"拆成
//!    纯函数直接测"解决的是"格式化函数忽略参数"这一类回归，没解决
//!    "活着的 `Audit` 跨天要不要换文件"这件事本身：如果有人把
//!    `record()`/`current_path()` 优化成第一次调用时算好文件名、用
//!    `OnceLock` 之类的东西缓存起来复用，`file_name_for`/`line_for`
//!    的纯函数测试全部照样通过（它们从来没有经过 `Audit` 的实例方法），
//!    `two_different_days_...` 也测不出来（它压根没调用过 `record`/
//!    `current_path`，是手写两个文件模拟出来的）。现在 `Audit` 内部
//!    持有 `clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>`，
//!    生产路径（`open`/`open_best_effort`）固定装的是 [`today`]；
//!    `#[cfg(test)]` 专用的 `with_clock` 构造函数可以装一个能在测试
//!    里动态改写的时钟，同一个 `Audit` 实例先在一天记一条、把时钟拨到
//!    下一天再记一条，两条必须落进两个不同的文件——这才是真的在测
//!    "活着的实例"，不是测公式。`with_clock` 不对 crate 外公开，
//!    生产代码永远走 `open`/`open_best_effort`。
//! 7. **[R86] 保留期边界测试不能跟 `RETENTION_DAYS` 本身算出来**——
//!    原来 `prune_keeps_files_inside_retention` 的夹具年龄写的是
//!    `RETENTION_DAYS - 2`，把 `RETENTION_DAYS` 从 30 调小到 3 之后，
//!    夹具年龄也会跟着缩成 1 天，1 天老的文件在任何正数保留期下都
//!    "在保留期内"，这条测试因此永远不可能抓到"保留期被调小"这类
//!    回归，结构上就不可能红。现在换成写死的 29/31 天两个边界（假设
//!    `RETENTION_DAYS == 30`，用一条独立测试把这个假设钉死，改了
//!    常量这条测试会先炸出一个清楚的信号），29 天必须留、31 天必须
//!    删，`RETENTION_DAYS` 往大往小调都会被其中一条抓到。
//! 8. **[R87] 时间戳补上显式的 `±HH:MM` 偏移量**——`today()` 取不到
//!    本地时区信息时会退化到 UTC，退化之前时间戳没有任何标记能看出
//!    "这一行到底是本地时间还是 UTC"，同一份追责日志里可能一半行本地
//!    时间、一半 UTC，读的人（可能不是开发者）无从分辨，跨时区对
//!    Gateway 侧日志时只能靠猜。现在 [`line_for`] 把 `OffsetDateTime`
//!    自带的偏移量显式写进时间戳，哪怕正好是 `+00:00`（本地时区就是
//!    UTC，或者真的退化到了 UTC）也写出来，不用容易被忽略的 "Z" 简写。
//!    `today()` 上关于回退触发条件的说明也订正了——见该函数文档。
//! 9. **[R88] 目录/文件权限在 Unix 上收紧到 `0700`/`0600`**——审计
//!    日志记的是"谁在什么时候连了哪台客户设备"，原来落盘用的是
//!    `create`/`create_dir_all` 的默认权限（`0644`/`0755`），本机
//!    任何用户都能读。上一版实现对这件事一个字的说明都没有，不是
//!    权衡后决定不做，是没考虑过。见 [`harden_dir_permissions`]/
//!    [`harden_file_permissions`] 上的说明，包括为什么 Windows 上是
//!    有意的空操作。
//!
//! # Task 12 复审追加的修复（R93/R94/R95），逐条写明理由
//!
//! 10. **[R93] 目录/文件的权限收紧原来有 TOCTOU 窗口**——R88 的修法是
//!     "先用默认权限创建、再 chmod"：`create_dir_all` 先把目录建成
//!     `0755`，`OpenOptions::create` 先把文件建成 `0644`，两次系统
//!     调用之间有一个窗口。同机另一个用户能在这个窗口里 `open()` 住
//!     一个 fd（对目录是先 `readdir`/进入目录，对文件是直接
//!     `open()`），`chmod` 收紧权限管不住已经打开的 fd——之后这个
//!     进程往这份日志追加的每一行内容，那个 fd 都能照读不误。修法是
//!     [`create_dir_all_hardened`]/[`open_log_file_hardened`]：分别用
//!     `DirBuilderExt::mode(0o700)`/`OpenOptionsExt::mode(0o600)`，
//!     让内核在 `mkdir`/`open` 那一次系统调用里就带上目标权限，不再
//!     有"先宽后收紧"的中间状态。这条性质是系统调用原子性给的，不是
//!     能用单线程单元测试直接复现竞态来证明的——验证方式是代码审查
//!     （确认不再是"创建 + 事后 chmod"两步）加上原有的权限断言（确认
//!     最终态仍然正确）。
//! 11. **[R94] `record()` 原来每写一行都把目录强制 chmod 回 `0700`**
//!     ——如果现场把 `log_dir` 指到一个需要让日志采集账号读的共享
//!     目录，运维特意放宽的目录权限会被下一行日志立刻覆盖回去，且
//!     没有开关能关掉这个行为。现在目录的权限收紧只发生在两个地方：
//!     `open()`（会话开始时纠正一次，覆盖"目录是升级前的旧版本建
//!     出来的，还停留在 `0755`"这种情况）与
//!     [`create_dir_all_hardened`] 真的新建目录的那一刻（原子完成，
//!     见上一条）——目录已经存在时，`record()` 不会再对它做任何
//!     `chmod`。**故意不对文件做同样的放宽**：R94 的问题场景是"运维
//!     需要让日志采集账号遍历/读这个目录"，`log_dir` 本身经常需要对
//!     别的账号打开一条口子；但文件内容就是这个模块存在的唯一理由
//!     （R88："本机任何用户都能读"），没有一个合理场景是"运维想让
//!     文件对外放宽、又不想 record() 帮忙纠正回来"，所以文件那一侧
//!     仍然保留"每次成功 `open()` 都重新 `harden_file_permissions`"
//!     ——这也顺带兜住了"今天的文件是升级前的旧二进制建出来的，还
//!     停留在 `0644`"这种 `open_log_file_hardened` 的 `.mode()` 管不
//!     到的既存文件场景（`.mode()` 只在真正新建时生效）。
//! 12. **[R95] `today()` 上关于回退触发条件的说明第二次订正**——
//!     R87 那一轮把"多线程导致 `Err`"这个错误归因换成了"系统缺时区
//!     数据库/环境变量会导致 `Err`"，这句话本身也没经过验证，实测是
//!     假的：真实 Linux 容器里删掉 `/etc/localtime` 与
//!     `/usr/share/zoneinfo` 之后 `now_local()` 仍然是 `Ok`，偏移量
//!     `+00:00`——glibc 缺 tzdb 时静默当 UTC 处理，不会返回错误。
//!     准确表述见 [`today`] 上的说明。

use crate::error::{Error, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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

/// 当前本地时间；取不到时区信息时退化为 UTC——宁可退化，也不要审计
/// 日志因为这个次要问题直接罢工。
///
/// R87（复审订正）：这里曾经写"极少数取不到时区信息的环境"，并暗示
/// 原因是"`time` 的 `local-offset` 在 Unix 多线程进程里会返回
/// `Err`"——这个具体机制在当前锁定的 `time = "0.3.55"` 上不成立，
/// 已经实测验证过：macOS 上、以及一个真实的 Linux 容器（glibc，
/// `rust:1-slim-bookworm`）里，多线程 tokio 运行时 + 并发
/// `tokio::spawn` 出的 8 个任务同时调用 `now_local()`，全部成功。
/// 翻过这个版本的 `local_offset_at`（Unix 侧）源码：它直接调用线程
/// 安全的 `libc::localtime_r`，不像该 crate 更早的版本那样按
/// `num_threads::is_single_threaded()` 决定要不要返回 `Err`（那条
/// 逻辑现在只留在一个不相关的内部工具函数 `refresh_tz` 里，`now_
/// local()` 不会走到它）。
///
/// R95（Task 12 复审第二次订正）：上一段留下的"真正会触发这条回退的
/// 场景是系统本身缺时区数据库/环境变量"这句话本身也不成立，已经实测
/// 证伪：在一个真实 Linux 容器里删掉 `/etc/localtime` 与
/// `/usr/share/zoneinfo` 后重新调用 `now_local()`，结果是 `Ok`，
/// 偏移量 `+00:00`——**不是** `Err`。glibc 的 `localtime_r` 缺时区
/// 数据时会静默按 UTC 返回成功，不会让上一层的 `now_local()` 观察到
/// 任何失败。准确的表述是：`local_offset_at`（Unix 侧）源码里唯一的
/// `Err` 来源是 `libc::localtime_r` 本身返回错误——实际上不可达（它
/// 的 C 语言契约里没有为"没有时区数据"定义一个错误返回），所以下面这
/// 行 `unwrap_or_else(now_utc)` 在 Unix 上是死代码，从未被真正执行
/// 到。缺 tzdb 时系统是直接把本地时区当成 UTC 处理，日志里的表现是
/// 时间戳带 `+00:00`——这跟"这台机器的本地时区本来就是 UTC"是同一种
/// 输出，无法从日志文本本身区分是哪一种。
///
/// 无论具体原因是什么，回退这件事本身现在在日志文本里是可见的：
/// [`line_for`] 把 `UtcOffset` 显式写进时间戳（`±HH:MM`），退化到
/// UTC 时那一行会显式带 `+00:00`，不会让读的人误以为自己看到的是
/// 本地时间——这比"猜清楚哪个具体系统调用会不会失败"更管用。
fn today() -> time::OffsetDateTime {
    time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc())
}

/// `±HH:MM` 形式的偏移量文本，供时间戳使用——见 [`line_for`]。故意
/// 不用 "Z" 表示 UTC：`+00:00` 与本地偏移量走同一套格式，读的人不用
/// 记两套写法，也不会把"退化到了 UTC"的那一行看成"格式不一样，出
/// 错了"。
fn format_offset(offset: time::UtcOffset) -> String {
    let sign = if offset.is_negative() { '-' } else { '+' };
    format!(
        "{sign}{:02}:{:02}",
        offset.whole_hours().abs(),
        offset.minutes_past_hour().abs()
    )
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
/// 换行（见 [`Audit::record`]）。时间戳带显式的 `±HH:MM` 偏移量——
/// 见模块文档 R87。
fn line_for(d: time::OffsetDateTime, level: Level, message: &str) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{} {} {}\n",
        d.year(),
        u8::from(d.month()),
        d.day(),
        d.hour(),
        d.minute(),
        d.second(),
        format_offset(d.offset()),
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

/// R93：递归创建目录，Unix 上让内核在 `mkdir` 那一次系统调用里就带上
/// `0700`，不是先用默认权限（`0755`）创建、再单独 `chmod` 一遍——两次
/// 系统调用之间那个窗口正是 R93 要堵的 TOCTOU。`DirBuilder::create`
/// 在 `recursive(true)` 下对已存在的目录直接返回 `Ok(())`、不会碰它
/// 的权限（这一点被 [`Audit::record`] 依赖：目录已存在时不重新
/// `chmod`，见该方法上 R94 的说明）。
#[cfg(unix)]
fn create_dir_all_hardened(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_dir_all_hardened(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// R93：以追加模式打开（必要时创建）日志文件，Unix 上让内核在 `open`
/// 那一次系统调用里就带上 `0600`——原因与 [`create_dir_all_hardened`]
/// 完全对称。`.mode()` 只在文件真的被这次调用创建时生效：如果文件已经
/// 存在（例如同一天里第二次 `record()`，或者是升级前的旧二进制建
/// 出来的），这次 `open` 不会改动它现有的权限，`Audit::record` 之后
/// 仍然会调用 [`harden_file_permissions`] 补一次——理由见该方法上的
/// 说明。
#[cfg(unix)]
fn open_log_file_hardened(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_log_file_hardened(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// R88（复审发现，中低严重）：审计日志记的是"谁在什么时候连了哪台
/// 客户设备"，本机任何用户默认都能读——上一版实现对这件事一个字的
/// 说明都没有，不是权衡后决定不做，是没考虑过。这里在 Unix 上把
/// 目录收紧成 `0700`（只有属主能进）、文件收紧成 `0600`（只有属主
/// 能读写）；失败静默忽略——权限收紧不了不该阻止日志本身被写下来
/// （跟 [`Audit::record`] 同一条裁定：这类次要故障不该掐断会话）。
///
/// **Windows 上这两个函数是空操作**，不是漏做：Windows 没有 Unix 的
/// mode 位这个概念，`std::fs::Permissions` 在 Windows 上只有一个
/// "只读"标志，设不出"仅属主可读写"这种粒度；产品的真实落点是
/// `%LOCALAPPDATA%\rmc\`（每个 Windows 用户账户私有），访问控制靠
/// 的是 NTFS ACL（继承自 `%LOCALAPPDATA%` 本身的默认 ACL），不是这里
/// 能设的东西。这条防线只覆盖 Unix：`config.rs` 里 `Config::default
/// ().log_dir` 是相对路径 `"logs"`，如果落在共享目录、或者 Linux 侧
/// （CI、将来的跨平台构建）运行，`0644`/`0755` 的默认权限就是真实的
/// 暴露面，这里补上。
#[cfg(unix)]
fn harden_dir_permissions(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(dir) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        let _ = std::fs::set_permissions(dir, perms);
    }
}

#[cfg(not(unix))]
fn harden_dir_permissions(_dir: &Path) {}

#[cfg(unix)]
fn harden_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn harden_file_permissions(_path: &Path) {}

/// R85：`clock` 收进字段而不是每次都直接调 [`today`]——生产路径两个
/// 构造函数都固定装 `today`，行为跟以前完全一样；`#[cfg(test)]` 专用
/// 的 [`Audit::with_clock`] 能装一个测试可控的时钟，让"同一个活着的
/// `Audit` 实例跨天要不要换文件"这件事本身能被钉住，不止是
/// `file_name_for` 这个纯函数的行为。`Arc<dyn Fn() -> .. + Send +
/// Sync>` 而不是裸的 `fn` 指针：`fn` 指针没有可变状态，没法在测试里
/// "先给出第一天、再给出第二天"；`Ctx`（持有 `Audit`）要跨 `tokio::
/// spawn` 的 `Send` 边界，字段类型必须是 `Send + Sync`，生产用的
/// `today` 是普通函数、天然满足，测试用的时钟包着一个
/// `Arc<AtomicI64>`，同样满足。
pub struct Audit {
    dir: PathBuf,
    clock: Arc<dyn Fn() -> time::OffsetDateTime + Send + Sync>,
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
        create_dir_all_hardened(&dir).map_err(Error::LocalIo)?;
        // R94：这一次性纠正是给"目录在这次调用之前就已经存在，可能是
        // 升级前的旧版本用默认权限建出来的"这种情况用的——
        // `create_dir_all_hardened` 对已经存在的目录不会重新
        // `chmod`（见该函数上 R93 的说明）。会话跑起来之后 `record()`
        // 不会再重复这个动作，见该方法上 R94 的说明。
        harden_dir_permissions(&dir);
        Ok(Self {
            dir,
            clock: Arc::new(today),
        })
    }

    /// `open()` 失败之后的兜底：不重新尝试创建目录，无条件成功。
    /// Supervisor 用它保证"审计日志初始化失败"这件事本身不会阻止
    /// 进程继续跑——`record()` 每次调用都会自己重试
    /// `create_dir_all`（见该方法上的说明），环境恢复后（权限修好、
    /// 磁盘腾出空间）会自动开始写入，不需要重启进程。`pub(crate)`：
    /// 这不是给测试开的口子（测试就该用会失败的 `open()`），只是
    /// Supervisor 接线要用，不需要对 crate 外公开。
    pub(crate) fn open_best_effort(dir: PathBuf) -> Self {
        Self {
            dir,
            clock: Arc::new(today),
        }
    }

    /// 只给本模块自己的测试用：装一个测试可控的时钟，不经过 `open()`
    /// 那次 `create_dir_all`（测试自己决定要不要先建目录）。见结构体
    /// 与模块文档 R85 的说明。
    #[cfg(test)]
    fn with_clock(
        dir: PathBuf,
        clock: Arc<dyn Fn() -> time::OffsetDateTime + Send + Sync>,
    ) -> Self {
        Self { dir, clock }
    }

    pub fn current_path(&self) -> PathBuf {
        self.dir.join(file_name_for((self.clock)()))
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
        if let Err(e) = create_dir_all_hardened(&self.dir) {
            tracing::warn!(error = %e, dir = ?self.dir, "审计日志目录不可用，这条记录已丢弃");
            return;
        }
        // R94（复审发现）：这里原来在每次成功写入前都无条件重新调一次
        // `harden_dir_permissions`——如果现场把 `log_dir` 指到一个需要
        // 让日志采集账号读的共享目录，运维特意放宽的目录权限会被下一行
        // 日志立刻覆盖回去，没有开关能关掉这个行为。目录的权限收紧现在
        // 只发生在上面的 `create_dir_all_hardened` 真的新建目录的那一刻
        // （R93，原子完成，不会有"先宽后收紧"的中间状态）与 `open()`
        // 里的一次性纠正（针对升级前遗留的旧权限目录）；目录已经存在时
        // 这里不再重复 `chmod`，运维的调整不会被每一行日志悄悄撤销。
        let d = (self.clock)();
        let path = self.dir.join(file_name_for(d));
        let line = line_for(d, level, &flat);
        match open_log_file_hardened(&path) {
            Ok(mut f) => {
                // 文件侧仍然每次都重新收紧一遍，跟目录侧不对称——理由见
                // 模块文档 R94 一节：文件内容本身就是这个模块存在的唯一
                // 理由，没有合理场景是"运维想放宽文件权限、又不想
                // record() 纠正回来"；这也顺带兜住"今天的文件是升级前的
                // 旧二进制建出来的，还停留在 0644"这类
                // `open_log_file_hardened` 的 `.mode()` 管不到的既存
                // 文件场景。
                harden_file_permissions(&path);
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
        // R86：夹具年龄写死成 28 天，不是 `RETENTION_DAYS - 2`——原来
        // 那样写是自指的：把 `RETENTION_DAYS` 从 30 调小到 3 之后,
        // 夹具年龄也会跟着缩成 1 天，1 天老的文件在任何正数保留期下
        // 都"在保留期内"，这条测试因此永远不可能抓到"保留期被调小"
        // 这类回归。见下面 `retention_days_is_30_as_documented` 与
        // 两条固定边界测试。
        let dir = tmpdir();
        let a = Audit::open(dir.path().to_path_buf()).unwrap();
        let recent = dir.path().join("rmc-2026-09-01.log");
        std::fs::write(&recent, "较近的日志\n").unwrap();
        let days_ago = SystemTime::now() - Duration::from_secs(28 * 86_400);
        filetime::set_file_mtime(&recent, filetime::FileTime::from_system_time(days_ago)).unwrap();

        assert_eq!(a.prune().unwrap(), 0);
        assert!(recent.exists());
    }

    // 后面两条固定 29/31 天边界都假设这个值是 30——如果这个假设不成立，
    // 这条先炸出一个清楚的信号，不能让边界测试悄悄测错边界。
    //
    // 会让这条测试变红的实现改法：改 `RETENTION_DAYS` 的值（不管改大
    // 还是改小）。
    #[test]
    fn retention_days_is_30_as_documented() {
        assert_eq!(RETENTION_DAYS, 30);
    }

    // R86：29 天必须留、31 天必须删，两条都固定写死天数，不跟
    // `RETENTION_DAYS` 算——这样 `RETENTION_DAYS` 无论调大还是调小都
    // 会被其中一条抓到（`prune_removes_files_older_than_retention` 用
    // 40 天做夹具，同理只能抓"调大"；这两条专门补"调小"，也把边界
    // 精确到 1 天）。
    //
    // 会让这条测试变红的实现改法：把 `RETENTION_DAYS` 从 30 改成任何
    // 小于 30 的值（例如 3）——29 天老的文件会被误判成"超过保留期"
    // 删掉，`assert_eq!(a.prune().unwrap(), 0)` 会看到 1。
    #[test]
    fn prune_keeps_a_file_exactly_29_days_old() {
        let dir = tmpdir();
        let a = Audit::open(dir.path().to_path_buf()).unwrap();
        let recent = dir.path().join("rmc-2026-08-01.log");
        std::fs::write(&recent, "29 天前的日志\n").unwrap();
        let days_ago = SystemTime::now() - Duration::from_secs(29 * 86_400);
        filetime::set_file_mtime(&recent, filetime::FileTime::from_system_time(days_ago)).unwrap();

        assert_eq!(a.prune().unwrap(), 0);
        assert!(recent.exists());
    }

    // 会让这条测试变红的实现改法：把 `RETENTION_DAYS` 从 30 改成任何
    // 大于等于 31 的值（例如 60）——31 天老的文件会被误判成"还在保留
    // 期内"留下来，`assert_eq!(a.prune().unwrap(), 1)` 会看到 0。
    #[test]
    fn prune_removes_a_file_exactly_31_days_old() {
        let dir = tmpdir();
        let a = Audit::open(dir.path().to_path_buf()).unwrap();
        let old = dir.path().join("rmc-2026-08-01.log");
        std::fs::write(&old, "31 天前的日志\n").unwrap();
        let days_ago = SystemTime::now() - Duration::from_secs(31 * 86_400);
        filetime::set_file_mtime(&old, filetime::FileTime::from_system_time(days_ago)).unwrap();

        assert_eq!(a.prune().unwrap(), 1);
        assert!(!old.exists());
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

    // --- R85：活着的 Audit 实例跨天要不要换文件，不能只靠纯函数测。
    // ---

    // 会让这条测试变红的实现改法：把 `record()`/`current_path()`
    // "优化"成第一次调用时算好文件名、缓存起来复用（例如塞进一个
    // `OnceLock<PathBuf>` 字段）——第二条记录会被错误地追加进第一天
    // 的文件里：`path1 == path2`（`assert_ne!` 直接失败），就算文件名
    // 计算本身没被缓存，`current_path()` 单独测过（如果它也被同一个
    // bug 影响会在这里体现），本条主要钉住 `record()` 本身写进的是
    // 哪个文件。
    #[test]
    fn record_recomputes_the_file_name_on_every_call_not_just_once() {
        let dir = tmpdir();
        let d1 = day(2026, 9, 13);
        let d2 = day(2026, 9, 14);
        let clock_ts = Arc::new(std::sync::atomic::AtomicI64::new(d1.unix_timestamp()));
        let clock = {
            let clock_ts = clock_ts.clone();
            Arc::new(move || {
                time::OffsetDateTime::from_unix_timestamp(
                    clock_ts.load(std::sync::atomic::Ordering::SeqCst),
                )
                .unwrap()
            }) as Arc<dyn Fn() -> time::OffsetDateTime + Send + Sync>
        };
        let a = Audit::with_clock(dir.path().to_path_buf(), clock);

        a.record(Level::Info, "第一天的事件");
        let path1 = a.current_path();

        clock_ts.store(d2.unix_timestamp(), std::sync::atomic::Ordering::SeqCst);
        a.record(Level::Info, "第二天的事件");
        let path2 = a.current_path();

        assert_ne!(path1, path2, "跨天之后 current_path() 应该换成新文件");
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

    // --- R87：时间戳带显式的 ±HH:MM 偏移量。---

    // 会让这条测试变红的实现改法：把 `line_for` 里的 `format_offset
    // (d.offset())` 删掉——时间戳长度会缩短、第 20 个字符不再是符号位。
    #[test]
    fn timestamp_carries_an_explicit_utc_offset() {
        let dir = tmpdir();
        let a = Audit::open(dir.path().to_path_buf()).unwrap();
        a.record(Level::Info, "带时区的时间戳");
        let text = std::fs::read_to_string(a.current_path()).unwrap();
        let line = text.lines().next().unwrap();
        let ts = line.split(' ').next().unwrap();
        // 形如 2026-09-13T11:12:44+08:00：日期 10 + T 1 + 时间 8 +
        // 偏移量 6 = 25 个字符，第 20 个（0-based 索引 19）是符号位。
        assert_eq!(
            ts.len(),
            "2026-09-13T11:12:44+08:00".len(),
            "时间戳应带 ±HH:MM 偏移量：{ts}"
        );
        let sign = ts.as_bytes()[19];
        assert!(
            sign == b'+' || sign == b'-',
            "第 20 个字符应该是偏移量的符号：{ts}"
        );
    }

    #[test]
    fn format_offset_writes_the_utc_case_explicitly_as_plus_zero() {
        // 不用 "Z" 表示 UTC——退化到 UTC 的那一行应该长得跟本地时区
        // 偏移量一样，不是另一套格式。
        assert_eq!(format_offset(time::UtcOffset::UTC), "+00:00");
    }

    // --- R88：目录/文件权限在 Unix 上收紧。---

    // 会让这条测试变红的实现改法：把 `record()`/`open()` 里对
    // `harden_dir_permissions`/`harden_file_permissions` 的调用删掉
    // ——目录/文件会留着 `create_dir_all`/`OpenOptions::create` 的
    // 默认权限（`0755`/`0644`），本机任何用户都能读。
    #[cfg(unix)]
    #[test]
    fn record_locks_down_file_and_directory_permissions_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmpdir();
        let a = Audit::open(dir.path().to_path_buf()).unwrap();
        a.record(Level::Info, "权限测试");

        let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "目录权限应该收紧到 0700，实际 {dir_mode:o}"
        );

        let file_mode = std::fs::metadata(a.current_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            file_mode, 0o600,
            "文件权限应该收紧到 0600，实际 {file_mode:o}"
        );
    }

    // --- R93/R94（Task 12 复审发现）：目录权限收紧不能有 TOCTOU 窗口，
    // 也不能在目录已存在时每次写入都强制覆盖运维的调整。 ---

    // R94：目录一旦已经存在，`record()` 不该在每次成功写入前把它强制
    // `chmod` 回 `0700`——运维可能故意把它放宽给日志采集账号读，且没有
    // 开关能关掉"每行日志都覆盖回去"这个行为。
    //
    // 会让这条测试变红的实现改法：在 `record()` 里恢复对已存在目录
    // 无条件调用 `harden_dir_permissions` 的旧代码（本次修复之前的
    // 版本）——运维放宽到 `0750` 之后的第二次 `record()` 会把它立刻
    // 收紧回 `0700`，下面的 `assert_eq!(mode, 0o750, ...)` 会看到
    // `0o700`。**已做过变异验证**：临时改回旧代码后本地跑过，确认
    // 这条测试会按上述方式变红；改完已还原。
    #[cfg(unix)]
    #[test]
    fn record_does_not_re_harden_an_already_existing_directory_every_call() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmpdir();
        let a = Audit::open(dir.path().to_path_buf()).unwrap();
        a.record(Level::Info, "第一行");

        // 模拟运维把目录权限放宽给日志采集账号读。
        let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
        perms.set_mode(0o750);
        std::fs::set_permissions(dir.path(), perms).unwrap();

        a.record(Level::Info, "第二行");

        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o750,
            "record() 不该把运维放宽的目录权限强制收紧回去，实际 {mode:o}"
        );
    }

    // R93：目录/文件创建那一刻就该带上目标权限（`DirBuilderExt::mode`/
    // `OpenOptionsExt::mode`），不是先用默认权限创建、再靠一次独立的
    // `chmod` 补救——后者中间存在一个同机其他用户能抢先打开宽权限 fd
    // 的窗口。这条测试钉住"创建函数本身直接产出正确的最终权限"这个
    // 更强的性质：just-created 的目录/文件在**没有**任何后续
    // `harden_*` 调用参与的情况下，权限已经是对的。
    //
    // 会让这条测试变红的实现改法：把 `create_dir_all_hardened`/
    // `open_log_file_hardened` 里的 `.mode(...)` 删掉，退回裸的
    // `create_dir_all`/`OpenOptions::create`——新建出来的目录/文件会
    // 停留在默认的 `0755`/`0644`。
    #[cfg(unix)]
    #[test]
    fn newly_created_dir_and_file_are_hardened_by_creation_itself() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmpdir();
        let sub = dir.path().join("fresh-subdir");
        create_dir_all_hardened(&sub).unwrap();
        let dir_mode = std::fs::metadata(&sub).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "新建目录创建那一刻就该是 0700：{dir_mode:o}"
        );

        let file = sub.join("f.log");
        let _f = open_log_file_hardened(&file).unwrap();
        let file_mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            file_mode, 0o600,
            "新建文件创建那一刻就该是 0600：{file_mode:o}"
        );
    }
}
