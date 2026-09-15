//! 记住密码。密封交给 [`Sealer`]，Windows 上是 DPAPI 当前用户范围。
//! 默认不保存，只有用户在界面上勾选「记住密码」时调用方才会写入。
//!
//! # 两层划分（本 crate 的约定，见 `lib.rs` 的模块文档）
//!
//! - **纯逻辑**：[`Sealer`] / [`SecretStore`] / [`FileSecretStore`] /
//!   [`LoadOutcome`] 都不带 `#[cfg(windows)]`，不碰任何 Win32 符号，在
//!   macOS 上原生可测——本文件下面那一整个测试模块就是在这台机器上跑的。
//! - **Win32**：只有 `win` 子模块（[`DpapiSealer`]）整块
//!   `#[cfg(windows)]`，职责只到"调 `CryptProtectData`/
//!   `CryptUnprotectData`、把结果搬成普通 Rust 值"为止。
//!
//! # 落盘文件的权限（W26，与 rmc-core 的 R93 同形状）
//!
//! 密文文件在 Unix 上**创建那一刻**就带 `0600`、目录带 `0700`
//! （[`open_new_private`] / [`create_dir_all_hardened`]），不是先按 umask
//! 建出来再 `chmod` ——那两次系统调用之间有一个 TOCTOU 窗口，同机另一个
//! 用户可以抢在收紧之前 `open()` 住一个 fd，之后再怎么 `chmod` 都赶不走
//! 那个 fd。
//!
//! **Windows 侧不靠 mode 位**：产品形态里这个目录是
//! `%LOCALAPPDATA%\rmc`（具体落点由 Task 10 接线时定，本模块只收一个
//! `dir`），访问控制由该目录继承的 ACL 负责，Rust 标准库的 `mode()` 在
//! Windows 上根本没有对应物。之所以仍然把 Unix 那一半写出来：这是一个
//! **跨平台的纯逻辑层**，CI 与开发机（就是这台 macOS）上的文件是真实
//! 存在、真实可读的，不写就是真实暴露。也就是说——Windows 上不用 mode
//! 位是权衡后的结论，不是没考虑过（rmc-core 的 R88 判过这两者的区别）。
//!
//! # 口令在内存里的形状
//!
//! 取回的口令只以 `Zeroizing<String>` 出现，[`LoadOutcome`] 手写的
//! `Debug` 不打印它（`Zeroizing<String>` 自己的 `Debug` 是直接转发给
//! `String` 的，`#[derive(Debug)]` 会把口令原样打出来），诊断文案里也
//! 只有结论、没有口令。

use std::io;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// 把一段明文密封成只有"本人本机"能解开的字节，以及反过来。
///
/// 两个方法都用 `Option` 而不是 `io::Result`：失败的唯一有用信息就是
/// "解不开"，而 DPAPI 的 `GetLastError` 在换账号这种正常场景里只会给出
/// 一个对现场工程师毫无意义的代码。**失败的分类由 [`LoadOutcome`] 在
/// 存储层表达**，不在这里。
pub trait Sealer: Send + Sync {
    fn seal(&self, plain: &[u8]) -> Option<Vec<u8>>;
    fn unseal(&self, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>>;
}

/// 声明 [`LoadOutcome`]，顺带生成变体名表与变体总数。
///
/// # 为什么要经一个宏
///
/// `every_load_outcome_gives_the_password_box_its_own_verdict_and_its_own_words`
/// 那张表要能证明自己**一格都没漏**。只靠一个没有 `_ =>` 兜底的
/// `variant_name` 不够：加一个变体，它逼着补的只是 `variant_name` 那一
/// 行，表那边少一格照样全绿，而新那一格的文案一个字都没被看过。
///
/// 宏把"一共有几个变体"变成从变体列表里**数出来**的
/// [`LoadOutcome::VARIANTS`]，表于是写成定长数组
/// `[(LoadOutcome, Option<bool>, &str); LoadOutcome::VARIANTS]`——少一格
/// 就是 `error[E0308]: expected an array with a size of 5`，**编译不
/// 过**。这是 Task 3 的 `sspi::declare_auth_outcome!`（W46）定下的做法；
/// 这里是第二份，没有共用是因为共用要动 Task 3 已经收口的模块，而两个
/// 枚举的形状也不完全一样（这个枚举有一格装着口令、不能 `derive` 任何
/// 东西）。记在 task-4-report.md 里。
macro_rules! declare_load_outcome {
    (
        $(#[$emeta:meta])*
        pub enum $name:ident {
            $(
                $(#[$vmeta:meta])*
                $variant:ident $( ( $($tty:ty),* $(,)? ) )?
            ),* $(,)?
        }
    ) => {
        $(#[$emeta])*
        pub enum $name {
            $(
                $(#[$vmeta])*
                $variant $( ( $($tty),* ) )?
            ),*
        }

        impl $name {
            /// 全部变体的名字，按声明顺序。**由声明宏生成**。
            pub const VARIANT_NAMES: &'static [&'static str] = &[$(stringify!($variant)),*];

            /// 变体总数。诊断那张表的长度必须等于它。
            pub const VARIANTS: usize = Self::VARIANT_NAMES.len();

            /// 这是哪一个变体。只用来把断言失败的信息说清楚，也用来给
            /// 手写的 `Debug` 兜底——**不参与任何判断**。
            pub fn variant_name(&self) -> &'static str {
                match self {
                    $( Self::$variant { .. } => stringify!($variant) ),*
                }
            }
        }
    };
}

declare_load_outcome! {
    /// 一次取回记住的密码的结局。
    ///
    /// # 为什么 `load` 的 `Option` 不够（W21）
    ///
    /// `SecretStore::load` 的 `None` 同时表示"这台机器上本来就没记住过
    /// 密码"与"记住了但解不开"。第二种在现实里一点都不罕见：用户换了
    /// Windows 账号、或者换了一台笔记本，DPAPI 当前用户范围的密文当场
    /// 作废。压成同一个 `None` 之后，界面上的表现是密码框空着、**一句
    /// 解释都没有**，而用户记得自己勾过「记住密码」。
    ///
    /// 这是同一个缺陷类在本项目里的第三次出现（Task 2 的 `resolve()`
    /// 把"不走代理"与"解析失败"压平、Task 3 的 `next_token()` 把"协商
    /// 成功结束"与"失败结束"压平），三次的解法一样：`load` 保留那个好用
    /// 的 `Option`，另开一个**带类型的出口** [`SecretStore::load_outcome`]
    /// 给界面与诊断页读。
    ///
    /// 不 `derive(Debug)`：[`LoadOutcome::Loaded`] 里装着口令，而
    /// `Zeroizing<String>` 的 `Debug` 是直接转发给 `String` 的。手写的
    /// 实现在本文件下方。
    #[derive(Default)]
    pub enum LoadOutcome {
        /// 这台机器上没有为这个 key 记住过密码——**不是错误**，这是
        /// 「默认不保存」下的正常状态。
        #[default]
        NotRemembered,
        /// 记录在，但读不出来（目录权限、文件被别的进程独占、路径被一个
        /// 目录占住……）。带的是 `io::Error` 的说明，不含口令。
        Unreadable(String),
        /// 读到了密文，但解不开。**这一格就是"换了 Windows 账号 / 换了
        /// 机器"**，也是 W21 的整个理由：它以前跟 `NotRemembered` 一样
        /// 只是一个 `None`。
        UnsealFailed,
        /// 解开了，但解出来的字节不是合法 UTF-8——这份记录坏了（被改过、
        /// 或者是别的版本写的）。
        NotUtf8,
        /// 取回成功。里面是口令，只以 `Zeroizing<String>` 出现。
        Loaded(Zeroizing<String>),
    }
}

impl LoadOutcome {
    /// 界面/诊断页要显示的东西：`(是否取回成功, 说明文字)`。
    ///
    /// 第一项 `None` 表示"这一项没有结论"——[`LoadOutcome::NotRemembered`]
    /// 是唯一一格：没勾过记住密码本来就不该在诊断页上显示成一条失败。
    ///
    /// 跟 Task 3 的 `AuthOutcome::diagnostic` 不同，这里的 `Some(true)`
    /// 是**真的知道**：口令确实解出来了、确实是合法文本。它不代表"运维
    /// 服务器接受这个口令"，那件事只有登录那一步知道，文案里写清楚。
    pub fn diagnostic(&self) -> (Option<bool>, String) {
        match self {
            Self::NotRemembered => (None, "这台机器上没有为这个运维服务器记住过密码".into()),
            Self::Unreadable(detail) => (
                Some(false),
                format!("记住的密码读不出来：{detail}；请重新输入密码"),
            ),
            Self::UnsealFailed => (
                Some(false),
                "记住的密码解不开：密文绑定保存它的那个 Windows 账号，换了账号或换了机器就解不开。\
                 请重新输入密码并再次勾选记住密码"
                    .into(),
            ),
            Self::NotUtf8 => (
                Some(false),
                "记住的密码解开之后不是合法文本，这份记录已经损坏；请重新输入密码".into(),
            ),
            Self::Loaded(_) => (
                Some(true),
                "已从本机取回记住的密码（能不能登录运维服务器要等这次连接的结果）".into(),
            ),
        }
    }

    /// 取出口令。这也是 [`SecretStore::load`] 的全部实现——两个出口因此
    /// **结构上不可能漂移**。
    pub fn into_secret(self) -> Option<Zeroizing<String>> {
        match self {
            Self::Loaded(secret) => Some(secret),
            _ => None,
        }
    }
}

/// 手写的 `Debug`：**口令一个字节都不出现**。
///
/// 兜底那一支故意只打变体名：往后谁再加一个装着敏感内容的变体，默认
/// 行为是"只打名字"，而不是"把内容打出来"。
impl std::fmt::Debug for LoadOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(detail) => write!(f, "Unreadable({detail:?})"),
            Self::Loaded(_) => f.write_str("Loaded(<口令已隐藏>)"),
            other => f.write_str(other.variant_name()),
        }
    }
}

/// 记住密码的存储。
pub trait SecretStore: Send + Sync {
    fn save(&self, key: &str, secret: &str) -> io::Result<()>;

    /// **带类型的出口**（W21）。界面与诊断页读这个，不读 [`Self::load`]。
    fn load_outcome(&self, key: &str) -> LoadOutcome;

    /// 好用的出口：只关心"有没有口令"的调用方（例如把密码框填上）用它。
    ///
    /// 这是一个**默认实现**，而且是唯一一份：它从
    /// [`Self::load_outcome`] 里取值，于是"`load` 说有、`load_outcome`
    /// 说没有"这种漂移写不出来。
    fn load(&self, key: &str) -> Option<Zeroizing<String>> {
        self.load_outcome(key).into_secret()
    }

    fn clear(&self, key: &str) -> io::Result<()>;
}

/// 一个 key 一个文件的存储。`dir` 从哪来由接线的那一层决定（Windows 上
/// 是 `%LOCALAPPDATA%` 下的目录），本类型不猜。
pub struct FileSecretStore<S: Sealer> {
    dir: PathBuf,
    sealer: S,
}

impl<S: Sealer> FileSecretStore<S> {
    pub fn new(dir: PathBuf, sealer: S) -> Self {
        Self { dir, sealer }
    }

    /// key 可能含冒号与 @，取其哈希做文件名，避免非法字符。
    ///
    /// 只取前 16 字节（128 位）：文件名长度与碰撞概率之间的常规取舍，
    /// 而且这里的 key 空间是"本机记过几个运维服务器"，个位数。
    fn path_for(&self, key: &str) -> PathBuf {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(key.as_bytes());
        let hex: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
        self.dir.join(format!("{hex}.sealed"))
    }

    /// 写入时的临时文件名。
    ///
    /// **[`SecretStore::clear`] 必须连它一起删**（W25）：`rename` 失败
    /// 时盘上留下的是一份完整、能解开的密文，而用户点的是「不再记住
    /// 密码」。两条路各有一条测试守着。
    fn tmp_path_for(&self, key: &str) -> PathBuf {
        self.path_for(key).with_extension("tmp")
    }
}

/// W26 / R93：递归建目录，Unix 上让内核在 `mkdir` 那一次系统调用里就带上
/// `0700`。`recursive(true)` 下目录已存在直接 `Ok(())`，不碰它现有的权限。
#[cfg(unix)]
fn create_dir_all_hardened(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// Windows 一侧：权限靠 `%LOCALAPPDATA%` 继承的 ACL，没有 mode 位可带。
#[cfg(not(unix))]
fn create_dir_all_hardened(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// W26 / R93：**新建**一个只有属主能读写的文件。
///
/// `create_new(true)` 不只是为了让 `.mode()` 必然生效（`mode` 只在这次
/// 调用真的创建了文件时才起作用，冲着一个已存在的文件 `open` 是不会改
/// 它权限的）——它同时挡掉"同机另一个用户先在这个路径上放一个软链或者
/// 一个自己能读的文件、等我们把密文写进去"。调用方
/// （[`write_private_file`]）负责先清掉自己上一次留下的残留。
#[cfg(unix)]
fn open_new_private(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_new_private(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// 建一个新文件并写进去。已经存在的同名文件先删掉——那只可能是上一次
/// 写到一半留下的残留（正常路径上 `rename` 之后 tmp 就不在了）。
fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    remove_if_present(path)?;
    let mut f = open_new_private(path)?;
    f.write_all(bytes)?;
    // 记住密码这件事的意义就是下次还在，所以落盘一次再 `rename`。
    f.sync_all()?;
    Ok(())
}

/// 删文件，不存在也算成功。
fn remove_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

impl<S: Sealer> SecretStore for FileSecretStore<S> {
    fn save(&self, key: &str, secret: &str) -> io::Result<()> {
        // 先密封。密封失败时连目录都还没建，更不会有任何文件——
        // "密封失败就退回去写明文"是这一段唯一不能犯的错。
        let sealed = self
            .sealer
            .seal(secret.as_bytes())
            .ok_or_else(|| io::Error::other("密封失败，未写入任何文件"))?;
        create_dir_all_hardened(&self.dir)?;
        let path = self.path_for(key);
        let tmp = self.tmp_path_for(key);
        write_private_file(&tmp, &sealed)?;
        if let Err(e) = std::fs::rename(&tmp, &path) {
            // W25：`rename` 失败时不能把这份密文留在盘上。它跟正式文件
            // 一样解得开，而 `clear()` 那边就算也删 tmp（它确实删），也
            // 得等用户真的去点「不再记住密码」。
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        Ok(())
    }

    fn load_outcome(&self, key: &str) -> LoadOutcome {
        let sealed = match std::fs::read(self.path_for(key)) {
            Ok(bytes) => bytes,
            // 没这个文件 ≠ 有文件但读不了。前者是"没勾过记住密码"，
            // 后者要显示一条处置建议。
            Err(e) if e.kind() == io::ErrorKind::NotFound => return LoadOutcome::NotRemembered,
            Err(e) => return LoadOutcome::Unreadable(e.to_string()),
        };
        let Some(plain) = self.sealer.unseal(&sealed) else {
            return LoadOutcome::UnsealFailed;
        };
        // W24：不写 `String::from_utf8(plain.to_vec())`。`to_vec()` 会再
        // 克隆一份明文，而失败路径上 `FromUtf8Error` **持有**那一份
        // 字节、没有任何清零就被丢掉。`from_utf8` 借用着看，成功时只在
        // `to_owned()` 那里产生唯一一份拷贝（进 `Zeroizing`），失败时
        // `Utf8Error` 里只有下标，明文仍然只有 `plain` 这一份，出了这个
        // 函数由 `Zeroizing` 抹零。
        match std::str::from_utf8(&plain) {
            Ok(text) => LoadOutcome::Loaded(Zeroizing::new(text.to_owned())),
            Err(_) => LoadOutcome::NotUtf8,
        }
    }

    fn clear(&self, key: &str) -> io::Result<()> {
        // W25：两个名字都删。先删正式文件、再删可能残留的 tmp，两步都
        // 走完再报第一个错——半路 return 会把另一份密文留在盘上。
        let sealed = remove_if_present(&self.path_for(key));
        let tmp = remove_if_present(&self.tmp_path_for(key));
        sealed.and(tmp)
    }
}

#[cfg(windows)]
mod win {
    //! DPAPI。`CRYPTPROTECT_LOCAL_MACHINE` 不设置，因此密文绑定当前
    //! Windows 账号，换账号或换机器都解不开——这正是
    //! [`super::LoadOutcome::UnsealFailed`] 那一格要说的事。
    //!
    //! `dwFlags` 传 0、`pPromptStruct` 传 `None`：不给提示结构就不会弹
    //! 任何 UI，`CRYPTPROTECT_UI_FORBIDDEN` 在这里没有额外作用。
    //!
    //! 这个模块在本机（macOS）上整块被 `#[cfg(windows)]` 切掉，一行测试
    //! 都跑不到；两条闸门是 `cargo zigbuild --target
    //! x86_64-pc-windows-gnu` 与同目标的 clippy。真实的 DPAPI 行为只能靠
    //! Windows 上的人工验收（条目记在 task-4-report.md）。
    #![allow(unsafe_code)]

    use super::Sealer;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
    };
    use zeroize::{Zeroize, Zeroizing};

    pub struct DpapiSealer;

    /// 把 DPAPI 分配的输出缓冲拷走、**抹零**、`LocalFree` 还回去，并把
    /// `blob` 的两个字段清空。
    ///
    /// # 为什么要抹零（W23）
    ///
    /// `unseal` 那一路，这块缓冲里躺着的就是用户连运维服务器的口令。
    /// `LocalFree` 只是把内存还给堆，**不清零**，下一个分配者原样拿到
    /// 它。`Zeroizing` 只盖得住我们拷出来的那一份，原件留在已释放的堆
    /// 上——全局约束"口令只以 `Zeroizing` 出现"在这里被绕过。
    /// `zeroize` 用的是易失写，不会被优化掉。
    /// `seal` 那一路缓冲里是密文，抹不抹都行，统一走同一条路，少一个
    /// "这次该不该抹"的判断。
    ///
    /// 形状照 Task 3 的 `sspi::imp::take_token`：**拷贝 → 抹零 → 释放
    /// → 把字段置空**。置空是为了让"释放之后再读一次/再放一次"写不
    /// 出来。
    ///
    /// # Safety
    /// `blob` 必须是刚从 `CryptProtectData`/`CryptUnprotectData` 成功
    /// 返回、还没被释放过的输出缓冲（`pbData` 由 `LocalAlloc` 分配、
    /// `cbData` 是它的真实长度），或者 `pbData` 为 NULL；调用之后调用方
    /// 不再使用这个指针。
    unsafe fn take_blob(blob: &mut CRYPT_INTEGER_BLOB) -> Option<Zeroizing<Vec<u8>>> {
        if blob.pbData.is_null() {
            return None;
        }
        let n = blob.cbData as usize;
        let ptr = blob.pbData;
        // SAFETY: 见函数级 Safety——`ptr` 指向 DPAPI 分配的、长度为 `n`
        // 的有效缓冲，此刻还没有被释放。
        let out = Zeroizing::new(unsafe { std::slice::from_raw_parts(ptr, n) }.to_vec());
        // SAFETY: 同上，这块内存在 `LocalFree` 之前仍归本调用方支配。
        unsafe { std::slice::from_raw_parts_mut(ptr, n) }.zeroize();
        // SAFETY: 同上，且紧接着把字段置空，不会重复释放。
        unsafe {
            let _ = LocalFree(Some(HLOCAL(ptr.cast())));
        }
        blob.pbData = std::ptr::null_mut();
        blob.cbData = 0;
        Some(out)
    }

    impl Sealer for DpapiSealer {
        fn seal(&self, plain: &[u8]) -> Option<Vec<u8>> {
            // `as u32` 会在 4GB 处静悄悄截断，密封的就不是整段明文了。
            // 口令当然到不了 4GB，但这是一个公开 trait 的实现。
            let input = CRYPT_INTEGER_BLOB {
                cbData: u32::try_from(plain.len()).ok()?,
                // DPAPI 不写输入缓冲；`*mut` 只是这个 C 结构体的字段类型。
                pbData: plain.as_ptr().cast_mut(),
            };
            let mut out = CRYPT_INTEGER_BLOB::default();
            // SAFETY: `input` 与 `out` 都是本函数的局部变量，存储活到本
            // 函数返回；`input.pbData` 指向调用方传进来的 `plain`，它的
            // 生命周期覆盖整个函数体。调用期间 DPAPI 只读 `input`、只写
            // `out` 那两个字段。
            let ok =
                unsafe { CryptProtectData(&input, PCWSTR::null(), None, None, None, 0, &mut out) }
                    .is_ok();
            // **不论成败都先收走输出缓冲**（形状照 Task 3 的 W44）。DPAPI
            // 失败时不分配，`out.pbData` 就是我们初始化的 NULL，
            // `take_blob` 的 NULL 检查直接返回 `None`；万一某个失败路径上
            // 它还是分配了，这一句就是那块内存唯一的归还机会。
            // SAFETY: `out` 要么仍是我们初始化的 NULL，要么是 DPAPI 刚
            // 分配、还没释放的输出缓冲；这之后 `out` 不再被使用。
            let taken = unsafe { take_blob(&mut out) };
            if !ok {
                return None;
            }
            taken.map(|sealed| sealed.to_vec())
        }

        fn unseal(&self, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
            let input = CRYPT_INTEGER_BLOB {
                cbData: u32::try_from(sealed.len()).ok()?,
                pbData: sealed.as_ptr().cast_mut(),
            };
            let mut out = CRYPT_INTEGER_BLOB::default();
            // SAFETY: 同 `seal`。第二个参数传 `None` 表示不要那个描述
            // 字符串——要了就得再 `LocalFree` 一次。
            let ok =
                unsafe { CryptUnprotectData(&input, None, None, None, None, 0, &mut out) }.is_ok();
            // 同 `seal`：不论成败都先收走。这一路缓冲里装的是口令，
            // `take_blob` 会在 `LocalFree` 之前抹零（W23）。
            // SAFETY: 同 `seal`。
            let taken = unsafe { take_blob(&mut out) };
            if !ok {
                return None;
            }
            taken
        }
    }
}

#[cfg(windows)]
pub use win::DpapiSealer;

#[cfg(test)]
mod tests {
    use super::*;

    /// 可逆的假密封器，只做字节取反，用来验证存储层逻辑。
    ///
    /// **它证明不了"明文没落盘"**：取反之后本来就不会出现明文子串，
    /// 那条测试只能靠自己的显式前置（W22）站住。
    struct FlipSealer;

    impl Sealer for FlipSealer {
        fn seal(&self, plain: &[u8]) -> Option<Vec<u8>> {
            Some(plain.iter().map(|b| !b).collect())
        }
        fn unseal(&self, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
            Some(Zeroizing::new(sealed.iter().map(|b| !b).collect()))
        }
    }

    struct FailingSealer;

    impl Sealer for FailingSealer {
        fn seal(&self, _plain: &[u8]) -> Option<Vec<u8>> {
            None
        }
        fn unseal(&self, _sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
            None
        }
    }

    /// 解得开，但解出来不是合法 UTF-8——模拟"这份记录坏了"。
    struct NonUtf8Sealer;

    impl Sealer for NonUtf8Sealer {
        fn seal(&self, plain: &[u8]) -> Option<Vec<u8>> {
            Some(plain.to_vec())
        }
        fn unseal(&self, _sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
            Some(Zeroizing::new(vec![0xff, 0xfe, 0x80]))
        }
    }

    /// 每条测试一个独立目录。
    ///
    /// **brief 原样的写法（只用 `SystemTime::now().as_nanos()`）在这台
    /// macOS 上实测会撞**：`cargo test` 默认多线程并行跑，而这里的
    /// `SystemTime` 粒度根本到不了纳秒，两条测试拿到同一个目录、又都用
    /// `"k"` 这个 key，于是互相踩。实测 `cargo test -p rmc-win secret`
    /// 连跑 60 轮，**34 轮有测试失败**（失败的是哪几条每轮都不一样，
    /// 正是撞目录的特征）。加一个进程内自增的序号（再带上 pid，防同一台
    /// 机器上两个 `cargo test` 并行）之后同样 60 轮 0 失败。
    ///
    /// 这种 flake 比一条恒真断言更坏：它让人习惯"重跑一次就好了"。
    fn tmpdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!(
            "rmc-secret-{pid}-{n}-{seq}",
            pid = std::process::id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// 目录里的文件列表，按名字排序。
    fn files_in(dir: &Path) -> Vec<std::path::PathBuf> {
        let mut v: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        v.sort();
        v
    }

    /// `haystack` 里有没有出现 `needle` 这一串**字节**。
    ///
    /// 不走 `String::from_utf8_lossy` + `contains`：账本里第 19 个反例
    /// 正是"泄漏确实发生了、事件确实被捕获了，但渲染方式让子串匹配认不
    /// 出来"。密文是任意字节，按字节找才对。
    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    // ===================== brief 里的十条 =====================

    #[test]
    fn round_trips_a_secret() {
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        s.save("tunnel-zhang@gateway.company.com:443", "pw-123")
            .unwrap();
        let got = s.load("tunnel-zhang@gateway.company.com:443").unwrap();
        assert_eq!(got.as_str(), "pw-123");
    }

    #[test]
    fn plaintext_never_hits_the_disk() {
        // ★ W22。brief 原样的写法是一个**空转形状**：断言全写在
        // `for entry in read_dir(&dir)` 的循环体里，`save` 若一个文件都
        // 没写，循环体一次都不执行，测试照样绿。rmc-core 的审计日志踩过
        // 一模一样的坑。
        //
        // 而且这里的密封器是可逆的假货（取反），"文件里没有明文子串"
        // 本来就自动成立——光靠这一条，连"存储层真的调了密封器"都证不
        // 了。所以显式前置有三层：目录里**恰好一个**文件、**非空**、
        // 内容**不等于**明文。
        //
        // 改红（实测见 task-4-report.md 的变异表）：
        // - `save` 改成直接 `Ok(())` → "恰好一个文件"那条失败；
        // - 把 `write_private_file(&tmp, &sealed)` 换成写
        //   `secret.as_bytes()` → "不等于明文"与"没有明文子串"同时失败。
        let dir = tmpdir();
        let s = FileSecretStore::new(dir.clone(), FlipSealer);
        const PLAINTEXT: &str = "PLAINTEXT-9f2a";
        s.save("k", PLAINTEXT).unwrap();

        let files = files_in(&dir);
        assert_eq!(
            files.len(),
            1,
            "save 之后目录里应该恰好有一个文件，实际是 {files:?}"
        );
        let bytes = std::fs::read(&files[0]).unwrap();
        assert!(!bytes.is_empty(), "写出来的文件是空的：{:?}", files[0]);
        assert_ne!(
            bytes.as_slice(),
            PLAINTEXT.as_bytes(),
            "文件内容就是明文本身"
        );
        assert!(
            !contains_bytes(&bytes, PLAINTEXT.as_bytes()),
            "明文落盘了：{:?}",
            String::from_utf8_lossy(&bytes)
        );
    }

    #[test]
    fn missing_key_loads_none() {
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        assert!(s.load("nope").is_none());
    }

    #[test]
    fn clear_removes_the_secret() {
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        s.save("k", "pw").unwrap();
        s.clear("k").unwrap();
        assert!(s.load("k").is_none());
    }

    #[test]
    fn clear_on_missing_key_is_not_an_error() {
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        assert!(s.clear("never-existed").is_ok());
    }

    #[test]
    fn unseal_failure_loads_none_rather_than_panicking() {
        let dir = tmpdir();
        FileSecretStore::new(dir.clone(), FlipSealer)
            .save("k", "pw")
            .unwrap();
        // 换一个解不开的密封器，模拟换了 Windows 账号
        let s = FileSecretStore::new(dir, FailingSealer);
        assert!(s.load("k").is_none());
    }

    #[test]
    fn seal_failure_is_an_error_not_a_silent_plaintext_write() {
        let dir = tmpdir();
        let s = FileSecretStore::new(dir.clone(), FailingSealer);
        assert!(s.save("k", "pw").is_err());
        assert!(
            std::fs::read_dir(&dir).unwrap().next().is_none(),
            "失败时不该留文件"
        );
    }

    #[test]
    fn keys_with_slashes_and_colons_are_usable() {
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        let key = "tunnel-zhang@gateway.company.com:443";
        s.save(key, "pw").unwrap();
        assert_eq!(s.load(key).unwrap().as_str(), "pw");
    }

    #[test]
    fn different_keys_do_not_collide() {
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        s.save("a@gw:443", "pw-a").unwrap();
        s.save("b@gw:443", "pw-b").unwrap();
        assert_eq!(s.load("a@gw:443").unwrap().as_str(), "pw-a");
        assert_eq!(s.load("b@gw:443").unwrap().as_str(), "pw-b");
    }

    #[test]
    fn the_file_name_keeps_all_128_bits_of_the_hash() {
        // `different_keys_do_not_collide` 只用两个 key，挡不住哈希被截短
        // ——`.take(16)` 改成 `.take(4)` 全套仍然绿（复审实测 24 passed）。
        // 而截短的后果不是"文件名难看"：两个 key 撞到同一个文件名，
        // 意味着 A 运维服务器的口令被填进 B 的密码框。
        //
        // 造一次真实碰撞太做作，钉长度不做作——这一句就够。
        //
        // 改红：把 `path_for` 里的 `.take(16)` 改成任何别的数。
        let s = FileSecretStore::new(std::path::PathBuf::from("/nonexistent"), FlipSealer);
        let stem = s.path_for("tunnel-zhang@gateway.company.com:443");
        let stem = stem.file_stem().unwrap().to_str().unwrap();
        assert_eq!(stem.len(), 32, "128 位哈希应该是 32 个十六进制字符");
        assert!(
            stem.bytes().all(|b| b.is_ascii_hexdigit()),
            "文件名主体应该全是十六进制字符：{stem}"
        );
    }

    #[test]
    fn overwrite_replaces_the_previous_secret() {
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        s.save("k", "old").unwrap();
        s.save("k", "new").unwrap();
        assert_eq!(s.load("k").unwrap().as_str(), "new");
        // 覆盖是 `rename` 覆盖，不该在旁边再留一个文件。
        assert_eq!(files_in(&s.dir).len(), 1, "覆盖之后多出了文件");
    }

    // ============ W21：五格结局，每一格一条身份测试 ============

    #[test]
    fn a_key_that_was_never_saved_is_not_remembered_rather_than_unreadable() {
        // 「没勾过记住密码」这一格。Task 2 的教训是 7 个变体里 3 个没有
        // 身份测试，而那 3 个恰好是诊断页最需要的——这一格就是没有代理
        // 的现场唯一会看到的那一条。
        //
        // 改红：把 `NotFound` 那一支也归到 `Unreadable`。
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        assert_eq!(s.load_outcome("nope").variant_name(), "NotRemembered");
    }

    #[test]
    fn a_record_that_cannot_be_read_is_told_apart_from_one_that_is_not_there() {
        // 「文件在，但读不出来」这一格：用一个目录占住那个路径，
        // `fs::read` 在 macOS/Linux/Windows 上都会失败，而且不是
        // `NotFound`。
        //
        // 改红：把 `Err(e) => Unreadable` 换成 `Err(_) => NotRemembered`。
        let dir = tmpdir();
        let s = FileSecretStore::new(dir, FlipSealer);
        std::fs::create_dir_all(s.path_for("k")).unwrap();
        let outcome = s.load_outcome("k");
        assert_eq!(
            outcome.variant_name(),
            "Unreadable",
            "实际是 {outcome:?}（读一个目录不该被当成「没记住过」）"
        );
    }

    #[test]
    fn the_reason_a_record_cannot_be_read_is_the_real_io_error_text() {
        // ★ W62。`every_load_outcome_...` 那张表里这一格用的是**字面量**
        // `Unreadable("权限不足".into())`，于是只测得到 `format!` 模板，
        // 测不到**真实的 `io::Error` 说明有没有接上**。评审实测 M20——
        // 把 `LoadOutcome::Unreadable(e.to_string())` 换成
        // `Unreadable(String::new())`——**102 全绿**，而诊断页上剩下的是
        // 「记住的密码读不出来：；请重新输入密码」：现场工程师看不出是
        // 权限不足、是被一个目录占住、还是被别的进程独占，也就无从处置。
        //
        // 做法是**逐字**对：先在这台机器上、对着这个路径亲手取一次真实
        // 的 `io::Error`，实现里那一句必须接的就是它。
        //
        // 改红：
        // - `Unreadable(e.to_string())` → `Unreadable(String::new())`（M20）
        //   → 「原因是空的」那条失败；
        // - 换成 `e.kind().to_string()` 之类别的说明 → 逐字相等那条失败；
        // - `format!("记住的密码读不出来：{detail}；…")` 里去掉 `{detail}`
        //   → 「诊断行里带着原因」那条失败。
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        let path = s.path_for("k");
        std::fs::create_dir_all(&path).unwrap();

        let want = std::fs::read(&path)
            .expect_err("这条测试自己先失灵了：读一个目录居然成功了")
            .to_string();
        assert!(
            !want.is_empty(),
            "这条测试自己先失灵了：io::Error 的说明是空的"
        );

        let outcome = s.load_outcome("k");
        let LoadOutcome::Unreadable(detail) = &outcome else {
            panic!("这一格应该是 Unreadable，实际是 {outcome:?}");
        };
        assert_eq!(
            detail, &want,
            "带的不是真实的 io::Error 说明（诊断页上原因会消失或者变成一句空话）"
        );

        let (ok, text) = outcome.diagnostic();
        assert_eq!(ok, Some(false));
        assert!(text.contains(&want), "诊断行里没有把原因带上：{text}");
    }

    #[test]
    fn a_record_that_does_not_unseal_says_so_instead_of_looking_unremembered() {
        // ★ W21 的整个理由。用户换了 Windows 账号或换了机器，DPAPI 解不
        // 开——这跟"根本没记住过"必须分得开，否则密码框空着、一句解释
        // 都没有。
        //
        // 改红：把 `unseal` 失败那一支换成 `NotRemembered`；或者干脆
        // 让 `load_outcome` 只返回 `load` 的 `Option`（那就是 brief 的
        // 原样，本条当场失败）。
        let dir = tmpdir();
        FileSecretStore::new(dir.clone(), FlipSealer)
            .save("k", "pw")
            .unwrap();
        let s = FileSecretStore::new(dir, FailingSealer);
        let outcome = s.load_outcome("k");
        assert_eq!(outcome.variant_name(), "UnsealFailed", "实际是 {outcome:?}");
        // 而且这一格必须给出"换了账号/换了机器"的处置建议，不是一句
        // 空话——这正是用户唯一需要知道的事。
        let (ok, text) = outcome.diagnostic();
        assert_eq!(ok, Some(false));
        assert!(text.contains("Windows 账号"), "没有说清原因：{text}");
    }

    #[test]
    fn a_record_that_unseals_into_non_utf8_is_its_own_outcome() {
        // 「解开了但内容坏了」这一格：跟"解不开"的处置建议不一样
        // （前者是重新输密码，后者也是重新输密码但原因完全不同，诊断页
        // 上说错了人会去查错方向）。
        //
        // 改红：把 `Err(_) => NotUtf8` 换成 `Err(_) => UnsealFailed`。
        let dir = tmpdir();
        let s = FileSecretStore::new(dir, NonUtf8Sealer);
        s.save("k", "pw").unwrap();
        let outcome = s.load_outcome("k");
        assert_eq!(outcome.variant_name(), "NotUtf8", "实际是 {outcome:?}");
        assert!(s.load("k").is_none(), "坏记录不该冒充一个口令");
    }

    #[test]
    fn a_secret_that_comes_back_reports_itself_as_loaded() {
        // 成功那一格的身份测试（`round_trips_a_secret` 查的是内容，
        // 查不出它走的是哪一格）。
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        s.save("k", "pw-123").unwrap();
        let outcome = s.load_outcome("k");
        assert_eq!(outcome.variant_name(), "Loaded");
        assert_eq!(outcome.diagnostic().0, Some(true));
        assert_eq!(outcome.into_secret().unwrap().as_str(), "pw-123");
    }

    #[test]
    fn every_load_outcome_gives_the_password_box_its_own_verdict_and_its_own_words() {
        // ★ W21 的"十格全部被一条表驱动测试钉住"那个标准（Task 3 的
        // `AuthOutcome` 定的），这里是五格。
        //
        // 改红：
        // - 任意一格的文案清空 → 关键词那条 +「五句话两两不同」同时失败；
        // - 把 `NotRemembered` 从 `None` 翻成 `Some(false)` → 第一格的
        //   `ok` 对不上（后果是没勾过记住密码的机器上诊断页报一条硬失败）；
        // - 把 `Loaded` 翻成 `Some(false)` → 同上；
        // - 给 `LoadOutcome` 加一格却不动这张表 → **编译不过**
        //   （`error[E0308]: expected an array with a size of 5`）。
        let cases: [(LoadOutcome, Option<bool>, &str); LoadOutcome::VARIANTS] = [
            (
                LoadOutcome::NotRemembered,
                None,
                "没有为这个运维服务器记住过密码",
            ),
            (
                LoadOutcome::Unreadable("权限不足".into()),
                Some(false),
                "读不出来",
            ),
            (LoadOutcome::UnsealFailed, Some(false), "换了账号或换了机器"),
            (LoadOutcome::NotUtf8, Some(false), "已经损坏"),
            (
                LoadOutcome::Loaded(Zeroizing::new("pw".into())),
                Some(true),
                "已从本机取回",
            ),
        ];

        // 长度已经由编译器钉住；这里再把**是哪些**变体对上，防"同一格
        // 写两遍、另一格没写"。
        let listed: std::collections::BTreeSet<&str> =
            cases.iter().map(|(o, _, _)| o.variant_name()).collect();
        let declared: std::collections::BTreeSet<&str> =
            LoadOutcome::VARIANT_NAMES.iter().copied().collect();
        assert_eq!(
            listed,
            declared,
            "表里漏了这些变体：{:?}",
            declared.difference(&listed).collect::<Vec<_>>()
        );

        for (outcome, want_ok, keyword) in &cases {
            let (ok, text) = outcome.diagnostic();
            assert_eq!(ok, *want_ok, "{}", outcome.variant_name());
            assert!(
                text.contains(keyword),
                "{} 的说明里没有「{keyword}」：{text}",
                outcome.variant_name()
            );
            // 说明文字里永远不该出现口令。`Loaded` 那一格带着 "pw"，
            // 但那是两个字母、容易假阳性，所以用一个不会自然出现的串。
            assert!(
                !text.contains("pw-secret-marker"),
                "{} 的说明里出现了口令",
                outcome.variant_name()
            );
        }

        // 每一句话两两不同：两格给出同一句话，等于现场工程师看到的还是
        // 同一条信息。
        let texts: std::collections::BTreeSet<String> =
            cases.iter().map(|(o, _, _)| o.diagnostic().1).collect();
        assert_eq!(texts.len(), cases.len(), "有两格给出了同一句话");
    }

    #[test]
    fn the_secret_never_shows_up_in_the_debug_rendering() {
        // 全局约束：口令不进日志 / `Debug` / 错误。
        // `#[derive(Debug)]` 会把它原样打出来——`Zeroizing<String>` 的
        // `Debug` 就是转发给 `String` 的。
        //
        // 改红：把手写的 `Debug` 换成 `#[derive(Debug)]`。
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        s.save("k", "pw-secret-marker").unwrap();
        let outcome = s.load_outcome("k");
        let rendered = format!("{outcome:?}");
        assert!(
            !rendered.contains("pw-secret-marker"),
            "口令进了 Debug：{rendered}"
        );
        assert!(
            rendered.contains("Loaded"),
            "至少要说得出是哪一格：{rendered}"
        );

        // 错误那一格里也不许有口令（它装的是 io::Error 的说明）。
        let dir = tmpdir();
        let s2 = FileSecretStore::new(dir, FlipSealer);
        std::fs::create_dir_all(s2.path_for("k")).unwrap();
        assert!(!format!("{:?}", s2.load_outcome("k")).contains("pw-secret-marker"));
    }

    #[test]
    fn load_hands_back_a_secret_in_the_loaded_situation_and_in_no_other() {
        // ★ W60。上一版这条测试叫 `..._in_all_five_situations`，**名不
        // 副实**：循环只走了 `["nope","k"] × [&miss, &ok]`，也就是
        // `NotRemembered` 与 `Loaded` 两格，`Unreadable` 与 `NotUtf8`
        // 一次都没进去。评审实测 M21——把 `into_secret` 的兜底改成
        // `Unreadable(detail) => Some(Zeroizing::new(detail))`，也就是
        // **把 `io::Error` 的说明文字当口令填进密码框、用户会拿这段文字
        // 去登录**——**102 全绿**。
        //
        // W21 要的「每一格都有身份测试」在 `diagnostic()` 那一侧做满了
        // （定长表 + 加变体编译不过），在 `load` / `into_secret` 这一侧
        // 没有。现在这条测试跟那张表同形：长度由 `LoadOutcome::VARIANTS`
        // 钉住，**加第六格却忘了这里就是 `error[E0308]`**，不会再静默
        // 漏格。每一格都是真造出来的现场（真文件、真 `fs::read`），不是
        // 字面量。
        //
        // 改红：
        // - `into_secret` 的 `_ => None` 放行任何一个非 `Loaded` 的格子
        //   （M21）→ 那一格的 `load` 与 `into_secret` 两条同时失败；
        // - 给 `FileSecretStore` 单独覆写一个 `load`（M17 那一枪）→ 同上；
        // - 任何一格的分类改掉（例如 `Err(e) => Unreadable` 换成
        //   `NotRemembered`）→ 该格的身份断言失败。

        // 五种现场，每种一个独立目录，互不干扰。
        let missing = FileSecretStore::new(tmpdir(), FlipSealer);

        let unreadable = FileSecretStore::new(tmpdir(), FlipSealer);
        std::fs::create_dir_all(unreadable.path_for("k")).unwrap();

        let unseal_failed_dir = tmpdir();
        FileSecretStore::new(unseal_failed_dir.clone(), FlipSealer)
            .save("k", "pw")
            .unwrap();
        let unseal_failed = FileSecretStore::new(unseal_failed_dir, FailingSealer);

        let not_utf8 = FileSecretStore::new(tmpdir(), NonUtf8Sealer);
        not_utf8.save("k", "pw").unwrap();

        let loaded = FileSecretStore::new(tmpdir(), FlipSealer);
        loaded.save("k", "pw-123").unwrap();

        // 长度由编译器钉住。`Box<dyn SecretStore>` 是因为几种现场的
        // `Sealer` 类型不同，而 `load` 的默认实现正是要从 trait 这一侧
        // 调进去。
        let cases: [(&str, Box<dyn SecretStore>, &str); LoadOutcome::VARIANTS] = [
            ("NotRemembered", Box::new(missing), "nope"),
            ("Unreadable", Box::new(unreadable), "k"),
            ("UnsealFailed", Box::new(unseal_failed), "k"),
            ("NotUtf8", Box::new(not_utf8), "k"),
            ("Loaded", Box::new(loaded), "k"),
        ];

        // 长度对了还要**是哪些格**也对，防"同一格写两遍、另一格没写"。
        let listed: std::collections::BTreeSet<&str> = cases.iter().map(|(n, _, _)| *n).collect();
        let declared: std::collections::BTreeSet<&str> =
            LoadOutcome::VARIANT_NAMES.iter().copied().collect();
        assert_eq!(
            listed,
            declared,
            "表里漏了这些变体：{:?}",
            declared.difference(&listed).collect::<Vec<_>>()
        );

        for (want_variant, store, key) in &cases {
            let outcome = store.load_outcome(key);
            assert_eq!(
                outcome.variant_name(),
                *want_variant,
                "这一格造出来的不是 {want_variant}，而是 {outcome:?}"
            );
            let is_loaded = matches!(outcome, LoadOutcome::Loaded(_));
            assert_eq!(
                is_loaded,
                *want_variant == "Loaded",
                "{want_variant}：variant_name 与真实的变体对不上"
            );

            // ★ 守 M21 的两句：只有 `Loaded` 那一格交得出口令，其余四格
            // 一律 `None`——**密码框里绝不能出现一段 `io::Error` 的说明
            // 文字**。
            assert_eq!(
                store.load(key).is_some(),
                is_loaded,
                "{want_variant}：load 与 load_outcome 的说法不一致"
            );
            assert_eq!(
                outcome.into_secret().is_some(),
                is_loaded,
                "{want_variant}：into_secret 交出了一个本不该存在的口令"
            );
        }

        // 而且 `Loaded` 那一格交出来的确实是存进去的那个口令——M21 交出
        // 的是别的字符串，这一句连"内容对不对"也一并钉住。
        let (_, loaded_store, loaded_key) = cases
            .iter()
            .find(|(n, _, _)| *n == "Loaded")
            .expect("表里没有 Loaded 这一格");
        assert_eq!(loaded_store.load(loaded_key).unwrap().as_str(), "pw-123");
    }

    // ============ W25：临时文件不能变成一份留在盘上的密文 ============

    #[test]
    fn a_failed_rename_does_not_strand_the_ciphertext_on_disk() {
        // ★ W25。`rename` 失败时 tmp 留在盘上，里面是一份**完整、解得
        // 开**的密文，而 `clear()` 删的是 `.sealed`。
        //
        // 让 `rename` 失败的办法：拿一个**非空目录**占住目标路径，
        // rename(file, 非空目录) 在 macOS/Linux/Windows 上都失败。
        //
        // 改红：把 `save` 里 `rename` 失败分支的
        // `let _ = std::fs::remove_file(&tmp);` 删掉。
        let dir = tmpdir();
        let s = FileSecretStore::new(dir.clone(), FlipSealer);
        let blocker = s.path_for("k");
        std::fs::create_dir_all(&blocker).unwrap();
        std::fs::write(blocker.join("占位"), b"x").unwrap();

        assert!(s.save("k", "pw-123").is_err(), "rename 应该失败");

        let leftovers: Vec<_> = files_in(&dir)
            .into_iter()
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "失败之后盘上还留着能解开的密文：{leftovers:?}"
        );
    }

    #[test]
    fn clear_also_removes_a_stranded_tmp_file() {
        // W25 的另一半：就算真有一份 tmp 残留（进程被杀、盘满……），
        // 用户点「不再记住密码」之后盘上不能还留着能解开的密文。
        //
        // 改红：把 `clear` 改回只删 `path_for(key)`。
        let dir = tmpdir();
        let s = FileSecretStore::new(dir.clone(), FlipSealer);
        let tmp = s.tmp_path_for("k");
        std::fs::write(&tmp, s.sealer.seal(b"pw-123").unwrap()).unwrap();
        assert!(tmp.exists());

        s.clear("k").unwrap();

        assert!(!tmp.exists(), "clear 之后 tmp 还在：{tmp:?}");
        assert!(files_in(&dir).is_empty(), "clear 之后目录里还有东西");
    }

    #[test]
    fn clear_still_removes_the_tmp_file_when_removing_the_sealed_one_fails() {
        // ★ W61 —— W25 的第三半。`clear` 写的是
        // `let sealed = ...; let tmp = ...; sealed.and(tmp)`：**两步都
        // 求值**，只报第一个错。评审实测 P2——改成
        // `remove_if_present(&self.path_for(key))?;` 第一步就早退——
        // **102 全绿**。而那正是用户点「不再记住密码」之后最不能发生的
        // 事：`.sealed` 删失败，`.tmp` 里那份**完整、解得开**的密文原样
        // 留在盘上。
        //
        // 造法：拿一个**目录**占住 `.sealed` 那个路径。`fs::remove_file`
        // 冲着目录调用在各平台上都失败、且都不是 `NotFound`
        // （Unix 上 `unlink` 给 EISDIR/EPERM；Windows 上 `DeleteFileW`
        // 给 ERROR_ACCESS_DENIED，std 随后那个「忽略只读属性再删一次」的
        // 兜底要 `CreateFileW` 打开它，而那一步没带
        // `FILE_FLAG_BACKUP_SEMANTICS`、打不开目录，于是原样把
        // ACCESS_DENIED 报回来）。所以**这条测试在 Windows 上照跑**，
        // 不加 `#[cfg(unix)]`、不会在 Windows CI 上静默消失。断言只要求
        // 「是个错」，不认具体的 `ErrorKind`。
        //
        // **两个方向都造**：只挡 `.sealed` 的话，把实现改成「先删 `.tmp`
        // 用 `?` 早退、再删 `.sealed`」这个**镜像早退**照样全绿（实测
        // N3，见 task-4-fix-1-report.md 的变异表）——那种写法在
        // `.tmp` 删不掉时会把 `.sealed` 留在盘上，一样是把密文留给了
        // 点过「不再记住密码」的用户。所以两个名字各挡一次。
        //
        // 改红：
        // - `remove_if_present(&self.path_for(key))?;` 早退（P2）→
        //   第一个方向的「另一个名字还在」失败；
        // - `remove_if_present(&self.tmp_path_for(key))?;` 早退（N3）→
        //   第二个方向的同一条失败；
        // - 两句都改成 `let _ = ...; Ok(())` → 「报了成功」失败。
        for block_sealed in [true, false] {
            let s = FileSecretStore::new(tmpdir(), FlipSealer);
            let sealed = s.path_for("k");
            let tmp = s.tmp_path_for("k");

            // 挡住的那个名字：放一个目录，`fs::remove_file` 必然失败。
            // 另一个名字：放一份**解得开的密文**，它必须被删掉。
            let (blocked, must_go) = if block_sealed {
                (&sealed, &tmp)
            } else {
                (&tmp, &sealed)
            };
            std::fs::create_dir_all(blocked).unwrap();
            std::fs::write(must_go, s.sealer.seal(b"pw-123").unwrap()).unwrap();
            assert!(must_go.exists());

            assert!(
                s.clear("k").is_err(),
                "block_sealed={block_sealed}：有一步根本删不掉，clear 却报了成功"
            );
            assert!(
                !must_go.exists(),
                "block_sealed={block_sealed}：一步失败之后另一步没跑，\
                 能解开的密文留在了盘上：{must_go:?}"
            );
            assert!(
                blocked.is_dir(),
                "block_sealed={block_sealed}：占位的目录被删掉了，这一轮就白造了：{blocked:?}"
            );
        }
    }

    // ============ W26：创建那一刻就带上权限 ============

    #[cfg(unix)]
    #[test]
    fn the_directory_and_the_file_are_created_private() {
        // ★ W26（与 rmc-core 的 R93 同形状）。Windows 上靠
        // `%LOCALAPPDATA%` 的 ACL、mode 位没有意义，但这是一个跨平台的
        // 纯逻辑层，CI 与开发机上就是真实暴露。
        //
        // 改红：把 `.mode(0o600)` 改成 `.mode(0o644)`，或者把
        // `DirBuilderExt::mode(0o700)` 换成 `fs::create_dir_all`。
        use std::os::unix::fs::PermissionsExt;
        let base = tmpdir().join("sub").join("dir");
        let s = FileSecretStore::new(base.clone(), FlipSealer);
        s.save("k", "pw").unwrap();

        let dir_mode = std::fs::metadata(&base).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "目录权限是 {dir_mode:o}，不是 0700");

        let file_mode = std::fs::metadata(s.path_for("k"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "密文文件权限是 {file_mode:o}，不是 0600");
    }

    #[cfg(unix)]
    #[test]
    fn an_overwrite_does_not_widen_the_permissions() {
        // 第二次 `save` 走的是"删 tmp → create_new → rename 覆盖"，
        // 新文件的权限必须还是 0600。
        //
        // 改红：把 `write_private_file` 里的 `create_new(true)` 换成
        // `create(true).truncate(true)`，再把前面那句
        // `remove_if_present` 删掉——残留的宽权限 tmp 会被沿用。
        use std::os::unix::fs::PermissionsExt;
        let s = FileSecretStore::new(tmpdir(), FlipSealer);
        s.save("k", "old").unwrap();
        // 手工留一个宽权限的残留 tmp，模拟上一次写到一半被杀
        let tmp = s.tmp_path_for("k");
        std::fs::write(&tmp, b"leftover").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o666)).unwrap();

        s.save("k", "new").unwrap();

        assert_eq!(s.load("k").unwrap().as_str(), "new");
        let file_mode = std::fs::metadata(s.path_for("k"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "覆盖之后权限放宽成了 {file_mode:o}");
    }
}
