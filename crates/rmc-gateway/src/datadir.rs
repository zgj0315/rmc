//! 数据目录：身份密钥、配置、账号、状态、审计日志都在这里。目录 0700，文件 0600。

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

pub const ENV_DATA_DIR: &str = "RMC_GATEWAY_DATA";

#[derive(Debug, Clone)]
pub struct DataDir {
    root: PathBuf,
}

impl DataDir {
    /// `$RMC_GATEWAY_DATA`，否则 `~/.rmc-gateway`。
    pub fn default_path() -> PathBuf {
        Self::path_from(
            std::env::var_os(ENV_DATA_DIR),
            std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")),
        )
    }

    pub(crate) fn path_from(env: Option<OsString>, home: Option<OsString>) -> PathBuf {
        if let Some(e) = env.filter(|e| !e.is_empty()) {
            return PathBuf::from(e);
        }
        let home = home
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| OsString::from("."));
        PathBuf::from(home).join(".rmc-gateway")
    }

    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn create(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn identity_key(&self) -> PathBuf {
        self.root.join("identity.key")
    }
    pub fn config(&self) -> PathBuf {
        self.root.join("config.toml")
    }
    pub fn accounts(&self) -> PathBuf {
        self.root.join("accounts.toml")
    }
    pub fn accounts_lock(&self) -> PathBuf {
        self.root.join("accounts.lock")
    }
    pub fn status(&self) -> PathBuf {
        self.root.join("status.json")
    }
    pub fn audit_dir(&self) -> PathBuf {
        self.root.join("audit")
    }

    /// 目录属主是不是当前用户。做法不需要 libc：在目录里建一个临时文件
    /// （它的属主必然是当前 euid），比较两者的 uid。
    #[cfg(unix)]
    pub fn owned_by_current_user(&self) -> io::Result<bool> {
        use std::os::unix::fs::MetadataExt;
        let probe = tempfile::NamedTempFile::new_in(&self.root)?;
        let me = probe.as_file().metadata()?.uid();
        Ok(std::fs::metadata(&self.root)?.uid() == me)
    }

    #[cfg(not(unix))]
    pub fn owned_by_current_user(&self) -> io::Result<bool> {
        Ok(true)
    }
}

/// 写临时文件 → 0600 → rename 覆盖。中途失败不留下半截文件。
///
/// 目标已存在时**静默覆盖**——`config.toml`/`accounts.toml`/`status.json` 都要能
/// 覆盖写，这是本函数的既定语义，不要为了某一个调用点（比如身份文件）改掉它；
/// 需要「目标已存在就拒绝」的场景用下面的 `write_private_atomic_noclobber`。
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = new_private_tmp(path)?;
    use std::io::Write;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// 跟 `write_private_atomic` 一样原子写、0600，但目标已存在时**失败、不覆盖**
/// （`io::ErrorKind::AlreadyExists`）。
///
/// R——评审 Important 3：身份文件的「拒绝覆盖」原来是 `path.exists()` 检查之后
/// 才落盘，检查与落盘之间有间隙（TOCTOU）——两个 `init` 同时指向同一个数据目录，
/// 都能通过前面的 `exists()` 检查，最后落地的那个会静默覆盖另一个；而换身份密钥
/// 等于所有连接码作废，这是 brief 里唯一被强调「必须」的不变式，不能靠一次
/// check-then-act 来守。这里把「已存在就拒绝」下沉到文件系统的原子操作本身
/// （`persist_noclobber`，底层走 `link`+`unlink` 或平台原生的 no-replace
/// rename），检查与落盘之间不再有间隙。
pub fn write_private_atomic_noclobber(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = new_private_tmp(path)?;
    use std::io::Write;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(path).map_err(|e| e.error)?;
    Ok(())
}

/// 两个 `write_private_atomic*` 共用的准备步骤：目标目录下建临时文件，权限收到 0600。
fn new_private_tmp(path: &Path) -> io::Result<tempfile::NamedTempFile> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "路径没有父目录"))?;
    let tmp = tempfile::Builder::new().prefix(".tmp-").tempfile_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(tmp)
}

/// 当前进程是不是 root。同样不需要 libc：临时文件的属主 uid 为 0 即 root。
#[cfg(unix)]
pub fn running_as_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    tempfile::NamedTempFile::new()
        .and_then(|f| f.as_file().metadata())
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
pub fn running_as_root() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_beats_the_home_default() {
        // 只测纯函数那一层，不动进程环境变量。
        let p = DataDir::path_from(
            Some(std::ffi::OsString::from("/x/y")),
            Some(std::ffi::OsString::from("/home/u")),
        );
        assert_eq!(p, PathBuf::from("/x/y"));
        let p = DataDir::path_from(None, Some(std::ffi::OsString::from("/home/u")));
        assert_eq!(p, PathBuf::from("/home/u/.rmc-gateway"));
    }

    /// 改红：`create` 里把 `0o700` 改成 `0o755`。
    #[cfg(unix)]
    #[test]
    fn the_directory_is_created_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let d = DataDir::at(tmp.path().join("data"));
        d.create().unwrap();
        let mode = std::fs::metadata(d.root()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{mode:o}");
    }

    /// 原子写：写完之后目录里没有临时文件残留，内容对，权限 0600。
    /// 改红：`write_private_atomic` 里把 `rename` 换成直接 `fs::write`——第二格
    /// （权限）红；把 `0o600` 改成 `0o644`——同样红。
    #[test]
    fn private_atomic_write_leaves_no_temp_file_and_is_private() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("f");
        write_private_atomic(&p, b"hello").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"hello");
        let names: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // 覆盖写也走同一条路
        write_private_atomic(&p, b"again").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"again");
    }

    /// `write_private_atomic_noclobber`：目标不存在时正常落盘；目标已存在时
    /// 拒绝，且原文件一字节不变——这条测试盯的是 Important 3 那类
    /// check-then-act 竞态：`persist_noclobber` 必须让「目标是否已存在」这件事
    /// 在文件系统的一次原子操作里完成判断，不能靠调用方先 `exists()` 再落盘。
    /// 改红：**实测过**——把函数体里的 `tmp.persist_noclobber(path)` 换成
    /// `tmp.persist(path)`（即退化成会覆盖的那一个），红的落点比字面猜测更早：
    /// 第二次 `write_private_atomic_noclobber(&p, b"second")` 不再返回
    /// `Err`，`.unwrap_err()` 本身直接 panic（"called `Result::unwrap_err()`
    /// on an `Ok` value"），根本走不到后面比较文件内容那句 `assert_eq!`。
    /// 两种红都是「这条测试确实在防这个回归」的证据，只是命中的断言点不同，
    /// 如实记录。
    #[test]
    fn noclobber_write_refuses_an_existing_target_and_leaves_it_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("f");
        write_private_atomic_noclobber(&p, b"first").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"first");
        let err = write_private_atomic_noclobber(&p, b"second").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");
        assert_eq!(
            std::fs::read(&p).unwrap(),
            b"first",
            "拒绝覆盖必须做到原文件字节不变"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_test_process_is_not_root_and_owns_its_tempdir() {
        // CI 与开发机都不以 root 跑测试；这条同时是 `running_as_root` 的反向自证。
        let tmp = tempfile::tempdir().unwrap();
        let d = DataDir::at(tmp.path().to_path_buf());
        assert!(d.owned_by_current_user().unwrap());
        assert!(!running_as_root());
    }
}
