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
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "路径没有父目录"))?;
    let mut tmp = tempfile::Builder::new().prefix(".tmp-").tempfile_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    use std::io::Write;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
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
