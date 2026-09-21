//! accounts.toml：账号、端口、口令的 argon2id 哈希、是否启用。
//! CLI 改写它（`AccountStore`，写临时文件 + rename，用 `accounts.lock` 串行化），
//! 服务端只读它（`AccountReader`，按 mtime 缓存）。没有 IPC。

use crate::datadir::{write_private_atomic, DataDir};
use crate::{Error, Result};
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use base64::Engine;
use rmc_core::code::AccountName;
use serde::{Deserialize, Serialize};
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    #[serde(with = "account_name_serde")]
    pub name: AccountName,
    pub port: u16,
    pub password_hash: String,
    pub enabled: bool,
    pub created_at_unix: u64,
    #[serde(default)]
    pub note: String,
}

mod account_name_serde {
    use rmc_core::code::AccountName;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(n: &AccountName, s: S) -> Result<S::Ok, S::Error> {
        n.as_str().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<AccountName, D::Error> {
        let s = String::deserialize(d)?;
        AccountName::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    #[serde(default, rename = "account")]
    accounts: Vec<Account>,
}

pub fn generate_password() -> Zeroizing<String> {
    use rand::RngCore;
    let mut bytes = Zeroizing::new([0u8; 18]);
    rand::rngs::OsRng.fill_bytes(&mut *bytes);
    Zeroizing::new(base64::engine::general_purpose::STANDARD_NO_PAD.encode(*bytes))
}

pub fn hash_password(pw: &str) -> String {
    argon2::Argon2::default()
        .hash_password(pw.as_bytes())
        .expect("argon2 默认参数不会失败")
        .to_string()
}

pub fn verify_hash(pw: &str, phc: &str) -> bool {
    let Ok(parsed) = argon2::password_hash::phc::PasswordHash::new(phc) else {
        return false;
    };
    argon2::Argon2::default()
        .verify_password(pw.as_bytes(), &parsed)
        .is_ok()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_file(path: &PathBuf) -> Result<File> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text)
            .map_err(|e| Error::Accounts(format!("{} 解析失败：{e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(File::default()),
        Err(e) => Err(Error::Accounts(format!("读 {} 失败：{e}", path.display()))),
    }
}

// ---------------------------------------------------------------- CLI 侧

pub struct AccountStore {
    dir: DataDir,
    ports: RangeInclusive<u16>,
    listen_port: u16,
}

impl AccountStore {
    pub fn open(dir: &DataDir, cfg: &crate::config::GatewayConfig, listen_port: u16) -> Self {
        Self {
            dir: dir.clone(),
            ports: cfg.reverse_ports(),
            listen_port,
        }
    }

    /// 持锁读-改-写。`std::fs::File::lock` 是 1.89 稳定的 API，进程退出自动释放。
    fn with_lock<T>(&self, f: impl FnOnce(&mut File) -> Result<T>) -> Result<T> {
        let lock = std::fs::File::create(self.dir.accounts_lock())?;
        lock.lock()?;
        let path = self.dir.accounts();
        let mut file = read_file(&path)?;
        let out = f(&mut file)?;
        let text = toml::to_string(&file).map_err(|e| Error::Accounts(e.to_string()))?;
        write_private_atomic(&path, text.as_bytes())?;
        Ok(out)
    }

    pub fn add(
        &self,
        name: &AccountName,
        port: Option<u16>,
        note: &str,
    ) -> Result<(Account, Zeroizing<String>)> {
        let pw = generate_password();
        let hash = hash_password(&pw);
        let ports = self.ports.clone();
        let listen = self.listen_port;
        let acc = self.with_lock(|file| {
            if file.accounts.iter().any(|a| &a.name == name) {
                return Err(Error::Accounts(format!(
                    "账号 {name} 已存在（吊销过的账号名不能复用，换一个名字）"
                )));
            }
            let used: std::collections::HashSet<u16> =
                file.accounts.iter().map(|a| a.port).collect();
            let port = match port {
                Some(p) => {
                    if p == listen {
                        return Err(Error::Accounts(format!("{p} 是监听端口，不能给账号")));
                    }
                    if !ports.contains(&p) {
                        return Err(Error::Accounts(format!(
                            "{p} 不在反向端口区间 {}-{} 内",
                            ports.start(),
                            ports.end()
                        )));
                    }
                    if used.contains(&p) {
                        return Err(Error::Accounts(format!("端口 {p} 已被别的账号占用")));
                    }
                    p
                }
                None => ports
                    .clone()
                    .find(|p| *p != listen && !used.contains(p))
                    .ok_or_else(|| {
                        Error::Accounts(format!(
                            "反向端口区间 {}-{} 已经用完",
                            ports.start(),
                            ports.end()
                        ))
                    })?,
            };
            let acc = Account {
                name: name.clone(),
                port,
                password_hash: hash.clone(),
                enabled: true,
                created_at_unix: now_unix(),
                note: note.to_string(),
            };
            file.accounts.push(acc.clone());
            Ok(acc)
        })?;
        Ok((acc, pw))
    }

    pub fn reset_password(&self, name: &AccountName) -> Result<Zeroizing<String>> {
        let pw = generate_password();
        let hash = hash_password(&pw);
        self.with_lock(|file| {
            let a = file
                .accounts
                .iter_mut()
                .find(|a| &a.name == name)
                .ok_or_else(|| Error::Accounts(format!("没有账号 {name}")))?;
            a.password_hash = hash.clone();
            Ok(())
        })?;
        Ok(pw)
    }

    pub fn revoke(&self, name: &AccountName) -> Result<()> {
        self.with_lock(|file| {
            let a = file
                .accounts
                .iter_mut()
                .find(|a| &a.name == name)
                .ok_or_else(|| Error::Accounts(format!("没有账号 {name}")))?;
            a.enabled = false;
            Ok(())
        })
    }

    pub fn list(&self) -> Result<Vec<Account>> {
        Ok(read_file(&self.dir.accounts())?.accounts)
    }
}

// ---------------------------------------------------------------- 服务端侧

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verify {
    Ok { port: u16 },
    Rejected,
}

/// 文件的 `(mtime, len)` → 上次解析结果，`AccountReader::snapshot` 的缓存键。
type CacheEntry = ((SystemTime, u64), std::sync::Arc<Vec<Account>>);

pub struct AccountReader {
    path: PathBuf,
    cache: Mutex<Option<CacheEntry>>,
    /// 账号不存在时也跑一次同样代价的校验
    dummy_hash: String,
}

impl AccountReader {
    pub fn new(dir: &DataDir) -> Self {
        Self {
            path: dir.accounts(),
            cache: Mutex::new(None),
            dummy_hash: hash_password(&generate_password()),
        }
    }

    /// 缓存键是 `(mtime, len)`，不是只看 `len`：两次改写如果长度相同（比如
    /// 两次 `reset_password`，argon2 默认参数下 PHC 串恒定 97 字符），只看
    /// `len` 会把第二次改写误判成「文件没变」，继续把第一次的快照吐回去——
    /// `the_reader_notices_a_change_that_keeps_the_file_length` 这条测试就
    /// 是钉这件事的。
    ///
    /// 这个缓存键理论上的边界：**同一个文件系统时间戳 + 同一个长度**的两次
    /// 改写会被漏掉。如实记录，不假装它不存在——ext4/APFS/NTFS 的 mtime 都
    /// 精确到纳秒，两次独立的 `write_private_atomic` 调用（哪怕紧挨着）在
    /// 现实里不会撞到同一个纳秒；如果真的撞上了，那不是这个缓存设计的问题，
    /// 是我们想看见的一个更大的问题（时钟分辨率或文件系统本身不对）。
    fn snapshot(&self) -> std::sync::Arc<Vec<Account>> {
        let stamp = std::fs::metadata(&self.path)
            .ok()
            .and_then(|m| Some((m.modified().ok()?, m.len())));
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let (Some(stamp), Some((old, list))) = (stamp, cache.as_ref()) {
            if *old == stamp {
                return list.clone();
            }
        }
        let list = std::sync::Arc::new(
            read_file(&self.path)
                .map(|f| f.accounts)
                .unwrap_or_default(),
        );
        if let Some(stamp) = stamp {
            *cache = Some((stamp, list.clone()));
        }
        list
    }

    pub fn verify(&self, name: &str, password: &str) -> Verify {
        let list = self.snapshot();
        match list.iter().find(|a| a.name.as_str() == name && a.enabled) {
            Some(a) if verify_hash(password, &a.password_hash) => Verify::Ok { port: a.port },
            Some(_) => Verify::Rejected,
            None => {
                // 同样的代价，同样的答案。
                let _ = verify_hash(password, &self.dummy_hash);
                Verify::Rejected
            }
        }
    }

    pub fn is_active(&self, name: &str) -> bool {
        self.snapshot()
            .iter()
            .any(|a| a.name.as_str() == name && a.enabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use crate::datadir::DataDir;

    fn store(tmp: &tempfile::TempDir) -> AccountStore {
        let d = DataDir::at(tmp.path().to_path_buf());
        d.create().unwrap();
        let mut cfg = GatewayConfig::new("203.0.113.10:22000".parse().unwrap());
        cfg.reverse_port_min = 22001;
        cfg.reverse_port_max = 22003; // 只留三个号，好测「用完了」
        AccountStore::open(&d, &cfg, 22000)
    }

    /// 并发测试专用：宽端口区间，两个独立 `AccountStore` 指向同一个数据目录。
    /// 不能复用上面窄区间的 `store()`——20+20 个账号会先撞上「区间用完」，
    /// 跟并发正确性毫无关系（brief 正文那版夹具就是这么必挂的）。
    fn wide_store(tmp: &tempfile::TempDir) -> AccountStore {
        let d = DataDir::at(tmp.path().to_path_buf());
        d.create().unwrap();
        let cfg = GatewayConfig::new("203.0.113.10:22000".parse().unwrap()); // 默认 22001-22999
        cfg.save(&d).unwrap();
        AccountStore::open(&d, &cfg, 22000)
    }

    fn name(s: &str) -> AccountName {
        AccountName::parse(s).unwrap()
    }

    /// 加账号：拿到最小空闲端口与一次性口令；口令只以 argon2id 哈希落盘。
    /// 改红：`add` 里把 `hash_password(&pw)` 换成 `pw.to_string()`——第三格红。
    #[test]
    fn add_allocates_the_lowest_free_port_and_stores_only_a_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        let (a, pw) = s.add(&name("zhang"), None, "张三").unwrap();
        assert_eq!(a.port, 22001);
        assert_eq!(pw.len(), 24);
        let text = std::fs::read_to_string(tmp.path().join("accounts.toml")).unwrap();
        assert!(!text.contains(pw.as_str()), "口令明文进了文件");
        assert!(text.contains("$argon2id$"), "{text}");
        let (b, _) = s.add(&name("li"), None, "").unwrap();
        assert_eq!(b.port, 22002);
    }

    #[test]
    fn explicit_port_must_be_free_in_range_and_not_the_listen_port() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        assert!(s.add(&name("a"), Some(22000), "").is_err(), "监听端口");
        assert!(s.add(&name("a"), Some(22004), "").is_err(), "区间外");
        s.add(&name("a"), Some(22003), "").unwrap();
        assert!(s.add(&name("b"), Some(22003), "").is_err(), "被占");
        assert!(s.add(&name("a"), None, "").is_err(), "重名");
    }

    #[test]
    fn range_exhaustion_is_an_error_not_a_panic() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        for n in ["a", "b", "c"] {
            s.add(&name(n), None, "").unwrap();
        }
        let e = s.add(&name("d"), None, "").unwrap_err();
        assert!(e.to_string().contains("用完"), "{e}");
    }

    /// 服务端读取：对的口令给端口；错的、停用的、不存在的一律 Rejected。
    ///
    /// 改红：**实测过**——brief 原文这句写的是「把 `verify` 里 `enabled`
    /// 判断删掉——第三格绿」，「绿」是笔误（也可能是数错了断言序号）：实测
    /// 把 `match list.iter().find(|a| a.name.as_str() == name && a.enabled)`
    /// 里的 `&& a.enabled` 删掉，这条测试**确实红**——命中的是 `s.revoke`
    /// 之后带着 `"吊销后必须拒"` 说明的那句 `assert_eq!`（吊销之后
    /// `verify` 仍然放行旧口令），不是「第三格」（第三句 `assert_eq!` 是
    /// `r.verify("nobody", pw.as_str())`，跟 `enabled` 无关，删掉判断后依旧
    /// 绿）。已按六步流程做过：注入前 `grep -c` 确认锚点恰好一行、注入、
    /// 跑测试看到真红、还原、`touch`、`diff` 核对与备份一致。
    #[test]
    fn reader_verifies_password_and_respects_revocation() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        let (_, pw) = s.add(&name("zhang"), None, "").unwrap();
        let r = AccountReader::new(&DataDir::at(tmp.path().to_path_buf()));
        assert_eq!(r.verify("zhang", pw.as_str()), Verify::Ok { port: 22001 });
        assert_eq!(r.verify("zhang", "wrong"), Verify::Rejected);
        assert_eq!(r.verify("nobody", pw.as_str()), Verify::Rejected);
        s.revoke(&name("zhang")).unwrap();
        assert_eq!(
            r.verify("zhang", pw.as_str()),
            Verify::Rejected,
            "吊销后必须拒"
        );
        assert!(!r.is_active("zhang"));
    }

    /// 「账号不存在」与「口令错」在耗时上不可区分：两者都要跑一次 argon2。
    /// 改红：`verify` 里对 `None` 分支直接 `return Verify::Rejected`——第二格红
    /// （不存在的账号快一个数量级）。
    #[test]
    fn unknown_account_costs_the_same_as_a_wrong_password() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        s.add(&name("zhang"), None, "").unwrap();
        let r = AccountReader::new(&DataDir::at(tmp.path().to_path_buf()));
        let t = |f: &dyn Fn()| {
            let t0 = std::time::Instant::now();
            for _ in 0..3 {
                f();
            }
            t0.elapsed()
        };
        let wrong = t(&|| {
            r.verify("zhang", "wrong");
        });
        let unknown = t(&|| {
            r.verify("nobody", "wrong");
        });
        // argon2 默认参数一次约 20-60ms；不存在的账号若不跑哈希会是微秒级。
        assert!(
            unknown.as_secs_f64() > wrong.as_secs_f64() * 0.3,
            "不存在的账号太快了：{unknown:?} vs {wrong:?}"
        );
    }

    #[test]
    fn reset_password_changes_the_hash_and_revoke_keeps_the_port() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        let (a, pw1) = s.add(&name("zhang"), None, "").unwrap();
        let pw2 = s.reset_password(&name("zhang")).unwrap();
        assert_ne!(pw1.as_str(), pw2.as_str());
        let r = AccountReader::new(&DataDir::at(tmp.path().to_path_buf()));
        assert_eq!(r.verify("zhang", pw1.as_str()), Verify::Rejected);
        assert_eq!(r.verify("zhang", pw2.as_str()), Verify::Ok { port: a.port });
        s.revoke(&name("zhang")).unwrap();
        let listed = s.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert!(!listed[0].enabled);
        assert_eq!(listed[0].port, a.port, "吊销后端口保留，不让别人顶上");
        assert!(s.add(&name("li"), Some(a.port), "").is_err());
    }

    /// R3（控制者订正）：`(mtime, len)` 缓存键真的在守「同长不同内容」的改写——
    /// 两次 `reset_password` 产出的 PHC 串长度恒为 97 字符（argon2 默认参数下
    /// 与口令内容无关），只看 `len` 会把第二次改写误判成没变。
    /// 用同一个 `AccountReader`：先建缓存（第一次 verify 命中，把当时的
    /// `(mtime, len)` 存进缓存），再改一次密码，断言旧口令失效、新口令生效。
    /// 改红：把 `snapshot` 的缓存键从 `(mtime, len)` 改成只看 `len`——这条红
    /// （旧口令仍然「有效」，因为缓存被当成没变而继续吐旧快照）。
    #[test]
    fn the_reader_notices_a_change_that_keeps_the_file_length() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        s.add(&name("zhang"), None, "").unwrap();
        let r = AccountReader::new(&DataDir::at(tmp.path().to_path_buf()));
        let pw1 = s.reset_password(&name("zhang")).unwrap();
        assert_eq!(
            r.verify("zhang", pw1.as_str()),
            Verify::Ok { port: 22001 },
            "先建一次缓存"
        );
        let pw2 = s.reset_password(&name("zhang")).unwrap();
        assert_eq!(
            r.verify("zhang", pw1.as_str()),
            Verify::Rejected,
            "旧口令该失效"
        );
        assert_eq!(
            r.verify("zhang", pw2.as_str()),
            Verify::Ok { port: 22001 },
            "新口令该生效"
        );
    }

    /// 并发改写不丢更新：两个线程各加一个账号，最后两个都在。
    /// 改红：`with_lock` 里把 `file.lock()` 删掉——这条会间歇性红（跑十遍）。
    #[test]
    fn concurrent_adds_do_not_lose_each_other() {
        let tmp = tempfile::tempdir().unwrap();
        let s1 = wide_store(&tmp);
        let s2 = wide_store(&tmp);
        let h = std::thread::spawn(move || {
            for i in 0..20 {
                s2.add(&name(&format!("b{i}")), None, "").unwrap();
            }
        });
        for i in 0..20 {
            s1.add(&name(&format!("a{i}")), None, "").unwrap();
        }
        h.join().unwrap();
        assert_eq!(s1.list().unwrap().len(), 40);
        let ports: std::collections::HashSet<u16> =
            s1.list().unwrap().iter().map(|a| a.port).collect();
        assert_eq!(ports.len(), 40, "端口撞了");
    }
}
