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
    Zeroizing::new(b64_encode_no_pad(bytes.as_slice()))
}

/// `base64::Engine::encode` 是 `encode<T: AsRef<[u8]>>(&self, input: T) -> String`
/// ——**按值**收 `T`。`generate_password` 原来直接调
/// `STANDARD_NO_PAD.encode(*bytes)`：`*bytes` 把 `Zeroizing<[u8; 18]>`
/// 按值解引用出一份裸 `[u8; 18]`（`Copy`），这份 18 字节明文熵的拷贝落进
/// `encode` 调用帧里的泛型参数，返回后不会被清零——是跟 `identity.rs`
/// 返工过两轮的同一个模式：熵的裸拷贝一旦离开 `Zeroizing`，就再也回不去。
///
/// 这里换成一个**非泛型**的 `&[u8]` 参数把「按值传」这条路堵死：调用点
/// 只能传引用（`bytes.as_slice()` 或 `&*bytes`），不能传 `*bytes`——
/// `[u8; 18]` 不会自动转换成 `&[u8]`，改回 `b64_encode_no_pad(*bytes)`
/// 类型不匹配，编译不过。这是编译期钉子，不是运行时断言：`encode` 本身是
/// 泛型的，钉不住「传值还是传引用」这件事本身（`T: AsRef<[u8]>` 两种都
/// 满足），所以钉子挪到这个非泛型的中间层。
fn b64_encode_no_pad(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
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
        match read_file(&self.path) {
            Ok(f) => {
                let list = std::sync::Arc::new(f.accounts);
                // **只在读成功时才写缓存**（终审 FR-1b）。原来这里不分成没成
                // 功：读失败时 `unwrap_or_default()` 给出的**空表**会连同当时
                // 的 `stamp` 一起被写进缓存，而事后 `chown`/`chmod` 修回属主与
                // 权限**不改 mtime 也不改 len**——`stamp` 一个字节都没变，下一
                // 个 tick 直接命中缓存，那张空表就此永久生效，非得重写一次
                // `accounts.toml` 或重启 `serve` 才能解开。空表意味着所有认证
                // 被拒、所有在线隧道在一个扫描周期内被断开，代价太大。
                // 读成功才更新缓存，读失败就什么都不记，下一次调用自然重试。
                if let Some(stamp) = stamp {
                    *cache = Some((stamp, list.clone()));
                }
                list
            }
            Err(e) => {
                // **出声**（终审 FR-1a）。原来这一支是 `unwrap_or_default()`，
                // 一条日志都不打：运维在审计与日志里看不到任何痕迹，看到的只有
                // 「全部隧道在五秒内断光、所有新认证被拒」。
                //
                // 文案刻意不提「账号变更」这类词：这条日志出现时，账号表**压根
                // 没被读到**，服务端并不知道里面写着什么，更没有任何账号被停用。
                // 把原因直接指向最常见的那条真实路径（用 `sudo` 跑过 `account`
                // 子命令，`accounts.toml` 成了 root 所有），让运维知道该去查什么。
                tracing::error!(
                    error = %e,
                    path = %self.path.display(),
                    "读不到账号表，本次按空表处理：所有认证都会被拒绝、在线隧道会在一个扫描周期内被断开。\
                     这不是运维侧对任何账号做过变更的结果——服务端根本没读到这个文件。\
                     最常见的原因是它的属主或权限不对（比如用 sudo 跑过 account 子命令，文件成了 root 所有的 0600，\
                     而 serve 以普通用户在跑）：检查 accounts.toml 与数据目录的属主和权限，\
                     改回 serve 所用的那个用户即可；修好之后下一次读取就会自动恢复，不必重启 serve"
                );
                std::sync::Arc::new(Vec::new())
            }
        }
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

    /// 把 `tracing` 的输出收进一个 `Vec<u8>`，只在当前线程上生效
    /// （`with_default`），不碰全局订阅者，跟并行跑的别的测试互不干扰。
    #[cfg(unix)]
    #[derive(Clone, Default)]
    struct CapturedLogs(std::sync::Arc<Mutex<Vec<u8>>>);

    #[cfg(unix)]
    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[cfg(unix)]
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogs;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[cfg(unix)]
    fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, String) {
        let sink = CapturedLogs::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::ERROR)
            .finish();
        let out = tracing::subscriber::with_default(sub, f);
        let text =
            String::from_utf8(sink.0.lock().unwrap_or_else(|e| e.into_inner()).clone()).unwrap();
        (out, text)
    }

    /// 终审 FR-1a：**读不到 `accounts.toml` 时必须出声**。
    ///
    /// 复现的是这条真实路径：`serve` 以普通用户在跑，运维用
    /// `sudo rmc-gateway account add li` 开了个账号，新的 `accounts.toml`
    /// 成了 root 所有的 0600。`std::fs::metadata` 只要目录可遍历就成功
    /// （stat 不需要读权限），所以服务端拿得到 `(mtime, len)`，只有真正
    /// 的 `read_to_string` 会 EACCES——原来这一支是 `unwrap_or_default()`，
    /// 空表、零日志：五秒内全部在线隧道被断、所有新认证被拒，而运维手上
    /// 没有任何线索。
    ///
    /// 这条测试钉三件事：出声了、说清了该查什么（属主/权限）、**没有**
    /// 把它说成账号被吊销/停用（那是一句会把运维带去查账号表内容的假话，
    /// 而账号表这一刻压根没被读到）。
    ///
    /// 改红（**实测过**）：在 `snapshot` 的 `Err(e)` 分支那句
    /// `tracing::error!(` 上方加一行 `#[cfg(any())]`（等价于把这条日志
    /// 整个删掉，只留 `std::sync::Arc::new(Vec::new())`）——实际输出
    /// `一条日志都没打：""`，`assert!(logs.contains("读不到账号表"))` 红。
    #[cfg(unix)]
    #[test]
    fn a_failure_to_read_the_account_table_is_logged_loudly() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        let (_, pw) = s.add(&name("zhang"), None, "").unwrap();
        let path = tmp.path().join("accounts.toml");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let r = AccountReader::new(&DataDir::at(tmp.path().to_path_buf()));
        let (verdict, logs) = capture_logs(|| r.verify("zhang", pw.as_str()));
        // 不管断言过不过，先把权限还原，免得 `tempdir` 清理时遇上麻烦。
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(
            verdict,
            Verify::Rejected,
            "读不到账号表就必须拒（fail-closed）"
        );
        assert!(logs.contains("读不到账号表"), "一条日志都没打：{logs:?}");
        assert!(
            logs.contains("属主") && logs.contains("权限"),
            "文案要让运维知道去查属主/权限：{logs}"
        );
        // 夹具里的账号名 `zhang`、目录名（tempdir 随机名）都不含下面这两个
        // 词，这条否定断言因此不会被夹具自己弄假（GLOBAL.md 那条通用教训）。
        assert!(
            !logs.contains("吊销") && !logs.contains("停用"),
            "读文件失败不是账号被吊销/停用，不能这么写：{logs}"
        );
    }

    /// 终审 FR-1b：**读失败不许把缓存写坏**——权限修回来之后下一次读就该
    /// 自愈，不用重写文件、更不用重启 `serve`。
    ///
    /// 原来的写法 `if let Some(stamp) = stamp { *cache = Some((stamp,
    /// list.clone())); }` 不分读成没成功：EACCES 那一次的**空表**连同当时
    /// 的 `stamp` 被写进缓存。而 `chmod`/`chown` 修回权限**不动 mtime 也
    /// 不动 len**，`stamp` 一字不变 → 下一次调用命中缓存 → 继续吐那张空表，
    /// 永久。这条测试刻意用一个**冷缓存**的 `AccountReader`（建好就直接撞
    /// 权限错误，从没缓存过好的快照）——热缓存那条路会在 `stamp` 没变时
    /// 提前命中旧的好快照，测不出这件事。
    ///
    /// 改红（**实测过**，下面这一枪真的打红了）：把 `Err` 分支最后那句
    /// `std::sync::Arc::new(Vec::new())` 换成
    /// `let list = std::sync::Arc::new(Vec::new()); if let Some(stamp) =
    /// stamp { *cache = Some((stamp, list.clone())); } list`
    /// ——也就是让读失败这一支也写缓存，等价于修复前的老行为。实际输出：
    /// `assertion left == right failed: 权限修好之后下一次读就该自愈，
    /// 不该被上一次失败的空表锁死 / left: Rejected / right: Ok { port: 22001 }`。
    #[cfg(unix)]
    #[test]
    fn a_failed_read_does_not_poison_the_cache() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let s = store(&tmp);
        let (_, pw) = s.add(&name("zhang"), None, "").unwrap();
        let path = tmp.path().join("accounts.toml");
        let before = std::fs::metadata(&path).unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let r = AccountReader::new(&DataDir::at(tmp.path().to_path_buf()));
        assert_eq!(
            r.verify("zhang", pw.as_str()),
            Verify::Rejected,
            "读不到账号表时必须 fail-closed"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        // 反向自证：`chmod` 确实没改 mtime/len，也就是说缓存键一个字节都
        // 没变——如果上面那次失败把空表写进了缓存，下面这句就必然命中缓存
        // 里的空表，这条断言因此真的带载。
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
        assert_eq!(before.len(), after.len());
        assert_eq!(
            r.verify("zhang", pw.as_str()),
            Verify::Ok { port: 22001 },
            "权限修好之后下一次读就该自愈，不该被上一次失败的空表锁死"
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
