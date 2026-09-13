//! Gateway host key 的首次记录与变更拒绝，见方案 3.8。
//!
//! 文件格式是本项目自定义的两段式格式，每条非空、非注释行形如
//! `[host]:port SHA256:<指纹>`，两段之间以空白分隔，恰好两段。
//!
//! R23：这**不是** OpenSSH known_hosts 的子集，只是长得像——真正的
//! OpenSSH known_hosts 一行是 3-4 段（hosts、key 类型、base64 编码的
//! 公钥、可选注释），哈希过的主机名、`@cert-authority`/`@revoked`
//! 前缀都是合法写法；拿一份真的 known_hosts 文件指望这里能读，光是
//! 段数对不上就会在第一条普通记录上失败，哈希主机名、marker 这些花样
//! 根本用不上就已经不兼容了。这里只是记一句「像」，不能当「兼容」宣传。
//!
//! # R26：这个模块防的是什么，不防什么
//!
//! R21/R24 两轮裁决先后判过这个问题，这里写的是最终结论，不是历史。
//!
//! **不防**：一个已经拿到 known_hosts 写权限的攻击者。这种攻击者根本
//! 不需要「伪造出一行解析不出来的记录」——直接写一行格式完全正确、
//! 指纹是自己那把假 key 的记录，`lookup()` 会老老实实读出来当成
//! `Matched` 放行。伪造格式损坏的记录对这类攻击者毫无意义，这个模块
//! 也从没打算防这个：能写文件的人，直接写「看起来对」的假货就赢了。
//!
//! **防**：意外损坏与局部篡改——磁盘扇区错误、并发写入撞车产生的半截
//! 行、人工改配置手滑、备份/同步过程中的字节损坏。这类损坏的共同点是
//! *不知道会砸中哪一行、也不知道会把内容改成什么样*，不是针对性伪造。
//! 这个模块要保住的性质很窄但很硬：
//!
//! > 只要 `key` 自己的记录**有可能**以某种损坏的形式存在于文件里，
//! > 就绝不能返回 `FirstSeen`。
//!
//! 这条性质靠 R24 的判断顺序落地，见 `lookup()` 上的文档注释。
//!
//! R24 的判断顺序（替换了 R21 那版「先看 host 再决定要不要校验格式」）：
//! 1. 扫描整份文件，收集 host 段与 `key` **逐字节相等**的干净记录。
//! 2. 只要有一条这样的精确匹配，直接凭它回答（`Matched` 或者
//!    `HostKeyMismatch`）——文件里别处再乱，`key` 自己的答案已经确定，
//!    不受影响。这一条保住了 R21 想要的可用性：一条记录健康，就不该被
//!    同一份文件里别的记录拖累。
//! 3. 没有精确匹配，但文件里有**任意**一行解析不出干净的两段记录——
//!    不管那行看起来是哪个 host 的——一律 `Fatal`：没法排除那行原本
//!    就是 `key` 自己的记录被砸坏了。这里故意不再按「跟这次查询是否
//!    相关」缩小范围：一旦答案不确定，宁可回 `Fatal` 让人工核实，也不
//!    能猜「大概率不是我」就放行写一条全新记录。
//! 4. 没有精确匹配，文件干净地解析完——才是真正的「这个 Gateway
//!    从没见过」，返回 `FirstSeen`。
//!
//! 代价（裁决明确接受）：文件里有一行损坏时，去连一个全新的、真正从没
//! 见过的 Gateway 也会被拒绝，即使损坏的那行跟这个新 Gateway 毫无关系。
//! 这是对的方向——文件已经不干净了，该由人去修——而且比 a633146 那版
//! （任何记录损坏都能连累到一次精确匹配）要窄得多。
//!
//! R24 之下，「解析成功」必须定义得足够严格，损坏才能可靠地表现成
//! 「解析失败」而不是「一条看起来还行、只是 host 对不上的记录」：
//! - **R25**：指纹段必须形如 `SHA256:` 加 43 个无填充 base64 字符，跟
//!   `fingerprint_sha256()` 产出的形状完全一致。这条在 R21 时代是可有
//!   可无的（指纹内容乱了，充其量制造一次误判的 `HostKeyMismatch`，不
//!   影响安全性），但在 R24 之下是承重的：如果指纹段允许任意非空白
//!   字符串，一行「host 对不上、指纹段本身被砸烂」的记录会被当成
//!   「一条正常但无关的记录」悄悄放过，不会被计入「文件有损坏」，
//!   这正是要堵的洞之一。
//! - host 段同理必须形如 `[<非空内容>]:<纯数字端口>`——方括号、冒号
//!   这些分隔符结构本身被砸坏（掉了方括号、端口里混进了非数字字符、
//!   方括号内容为空）时，必须算解析失败，不能被当成「跟这次查询无关
//!   的另一个 host」放过。
//!
//! **这条防线的真实边界**：如果损坏恰好把 `key` 的 host 段变成了*另一
//! 个语法上完全合法的主机名*（比如掉了一个字符，`gateway.company.com`
//! 变成 `gateway.company.co`——这本身还是一个合法域名），单看这一行，
//! 没有任何办法把它和「本来就是另一个真实存在的 Gateway」区分开——
//! `different_gateways_are_tracked_separately` 这条测试本身就要求
//! `gw-a`/`gw-b` 这种只差一个字符的主机名必须被当成两个独立、互不
//! 拖累的记录。任何足够强到能揪出「合法但可能是砸坏的」字符串的启发式
//! （编辑距离、前缀/后缀比对、长度比对）都会连带把「用户真的配置了两个
//! 名字很像、甚至恰好同一端口的 Gateway」这个再正常不过的场景一起误杀
//! ——已经验证过：本模块现有的
//! `different_gateways_are_tracked_separately`（相差一个字符）和
//! `same_host_on_a_different_port_is_a_separate_record`（同主机名不同
//! 端口，key 串长度还不一样）这两条已经在跑的必需行为，会被这类启发式
//! 直接命中误杀。这个残留缺口不是没做，是没法在不破坏正常多 Gateway
//! 场景的前提下靠内容校验关上——跟「防不住已经能写文件的攻击者」是
//! 同一类边界：都是「内容层面已经无法分辨真假」，不是实现疏漏。
//!
//! 本地文件系统失败（权限错误、磁盘满、父目录其实是个文件……）一律构造
//! `Error::LocalIo`，不是 `Error::Io`：`Error::Io` 分类是 Network，会被
//! Supervisor 当成网络抖动无限退避重连；但这类本地故障重试无法自愈，
//! 必须 Fatal 立刻停下来让工程师看见。见 `error.rs` 上 R14/R15 的注释。

use crate::addr::HostPort;
use crate::error::{Error, Result};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// 本条目此前没有记录，已写入。
    FirstSeen,
    /// 与记录一致。
    Matched,
}

pub struct KnownHosts {
    path: PathBuf,
}

/// 按 OpenSSH 的方式计算指纹：SHA256 后 base64，去掉填充，得到形如
/// `SHA256:<43 个字符>` 的字符串——与 `ssh-keygen -lf` 的输出逐字符一致，
/// 运维手册要求工程师能拿客户端界面上的这串和 Gateway 侧
/// `ssh-keygen -lf` 读出来的肉眼核对，格式对不上就没法比。
pub fn fingerprint_sha256(key_blob: &[u8]) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(key_blob);
    let body = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    format!("SHA256:{body}")
}

/// 文件里一条记录的 key：host 与 port 分开记，同一个主机名换个端口就是
/// 不同的 Gateway 身份（OpenSSH 对待非默认端口就是这样处理的）。恒定加
/// 中括号，不管 host 本身是不是 IPv6 字面量，读写两边用同一个函数，不会
/// 因为要不要加括号产生歧义。
fn entry_key(gateway: &HostPort) -> String {
    format!("[{}]:{}", gateway.host, gateway.port)
}

/// R24：host 段是否长得像一条记录该有的样子——方括号包住非空内容，
/// 紧跟 `]:`，后面只有数字端口，整个 token 之外没有多余字符。
///
/// 这不是重新实现 `HostPort` 的完整校验（不检查端口范围、不识别历史
/// 遗留的数字式 IPv4 之类），只是「这段字节起码保持着记录该有的分隔符
/// 结构」的最基本形状检查。目的很窄：让分隔符结构本身被砸坏（掉了
/// 方括号、掉了冒号、端口里混进了非数字字符、方括号内容为空）能表现成
/// 解析失败，而不是被当成「跟这次查询无关的另一个 host」悄悄放过——
/// 见模块顶部 R26 段落里「这条防线的真实边界」：这条校验完全帮不上
/// 「host 段本身还是一个合法主机名、只是内容不对」这种损坏，那是不同
/// 的、没法靠内容校验关上的缺口。
fn looks_like_host_token(token: &str) -> bool {
    let Some(rest) = token.strip_prefix('[') else {
        return false;
    };
    let Some((host, port)) = rest.split_once("]:") else {
        return false;
    };
    !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
}

/// R25：指纹段是否长得像 `fingerprint_sha256()` 会产出的样子——
/// `SHA256:` 后跟 43 个无填充 base64 字符。R24 之下这条是承重的：见
/// 模块顶部的说明，指纹段内部的损坏必须能表现成解析失败，不能被当成
/// 「一条正常但无关的记录」放过，否则「没有精确匹配 ⇒ 这行是不是
/// `key` 自己的记录」这条推理会被指纹段的损坏绕过。
fn looks_like_fingerprint(token: &str) -> bool {
    let Some(body) = token.strip_prefix("SHA256:") else {
        return false;
    };
    body.len() == 43
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// 文件已损坏时构造的错误。用 `ErrorKind::InvalidData` 包一层
/// `Error::LocalIo`：语义上贴切（数据本身不合法，不是某次系统调用失败），
/// 分类上也是我们要的 Fatal——文件损坏重试没有用，必须让人来处理。
fn corrupt(message: impl Into<String>) -> Error {
    Error::LocalIo(std::io::Error::new(ErrorKind::InvalidData, message.into()))
}

impl KnownHosts {
    pub fn open(path: PathBuf) -> Self {
        Self { path }
    }

    /// 落盘路径。Task 4 的接口清单里没列这个方法，但 Task 7 要在界面上
    /// 显示 known_hosts 文件的位置，所以这里是刻意导出，不是漏改
    /// 可见性。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 在文件里查找 `key` 对应的指纹。见模块顶部 R26/R24 段落的完整
    /// 推理，这里只列结论：
    ///
    /// - 文件里存在跟 `key` 逐字节相等、且干净可解析的记录 → 直接凭它
    ///   回答（`Ok(Some(fp))`），文件里别处是否损坏跟这次查询无关。
    /// - 没有这样的精确匹配，但文件里有任意一行（不管是哪个 host 的）
    ///   解析不出干净的「host 指纹」两段 → `Err(_)`（`Fatal`）：没法
    ///   排除那行原本就是 `key` 自己的记录。
    /// - 没有精确匹配，文件干净解析完 → `Ok(None)`（含文件不存在的
    ///   情况，两者都是「还没见过这个 Gateway」）。
    /// - 精确匹配出现了不止一种指纹值（互相矛盾）→ `Err(_)`：无法
    ///   判断哪一条才是真的，报错交给人核实；完全相同的重复记录不算
    ///   矛盾，容忍。
    fn lookup(&self, key: &str) -> Result<Option<String>> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            // R14：本地文件系统错误，必须是 LocalIo（Fatal），不是 Io
            // （Network）——重试解决不了权限错误或者路径本身是个目录
            // 这类问题。
            Err(e) => return Err(Error::LocalIo(e)),
        };

        let mut found: Option<String> = None;
        // R24：文件里是否存在任意一行解析不出干净记录——不区分是哪个
        // host 的，见模块顶部的推理。只留第一处损坏的行号/原文，方便
        // 报错时给人一个线索去修文件。
        let mut damaged: Option<(usize, String)> = None;

        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            // 非空、非注释行 trim 后不可能是空字符串，split_whitespace
            // 至少产出一个 token。
            let host = parts.next().expect("非空行必有至少一个 token");
            let fp = parts.next();
            let extra = parts.next();

            let clean_record = match (fp, extra) {
                (Some(fp), None) if looks_like_host_token(host) && looks_like_fingerprint(fp) => {
                    Some((host, fp))
                }
                _ => None,
            };

            let Some((host, fp)) = clean_record else {
                if damaged.is_none() {
                    damaged = Some((lineno + 1, raw.to_string()));
                }
                continue;
            };

            if host != key {
                continue;
            }
            match &found {
                None => found = Some(fp.to_string()),
                Some(prev) if prev == fp => {
                    // 完全相同的重复记录，容忍。
                }
                Some(prev) => {
                    return Err(corrupt(format!(
                        "known_hosts 中 {key} 存在互相矛盾的记录（{prev} 与 {fp}），\
                         文件可能被篡改，需要人工核实后再连接"
                    )));
                }
            }
        }

        match (found, damaged) {
            (Some(fp), _) => Ok(Some(fp)),
            (None, Some((lineno, raw))) => Err(corrupt(format!(
                "known_hosts 第 {lineno} 行解析不出干净的记录（{raw}），\
                 无法确认其中是否原本是 {key} 的记录，需要人工核实后再连接"
            ))),
            (None, None) => Ok(None),
        }
    }

    fn append(&self, key: &str, fingerprint: &str) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                // R14：本地文件系统错误显式构造 LocalIo，不能靠 `?` 的
                // `From` 自动转换——Error 上没有为它挂 `#[from]`（见
                // error.rs 上 R15 的注释），这是刻意的编译期摩擦。
                std::fs::create_dir_all(parent).map_err(Error::LocalIo)?;
            }
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(Error::LocalIo)?;
        writeln!(f, "{key} {fingerprint}").map_err(Error::LocalIo)?;
        Ok(())
    }

    /// 首次连接记录指纹；已有记录且一致返回 `Verdict::Matched`；已有记录
    /// 但不一致时返回 `Error::HostKeyMismatch`，且不覆盖原记录——变更
    /// 拒绝是这个模块存在的唯一理由，覆盖了记录等于放弃了这个理由。
    pub fn check(&self, gateway: &HostPort, fingerprint: &str) -> Result<Verdict> {
        let key = entry_key(gateway);
        match self.lookup(&key)? {
            None => {
                self.append(&key, fingerprint)?;
                Ok(Verdict::FirstSeen)
            }
            Some(recorded) if recorded == fingerprint => Ok(Verdict::Matched),
            Some(recorded) => Err(Error::HostKeyMismatch {
                expected: recorded,
                actual: fingerprint.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::HostPort;
    use crate::error::ErrorClass;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("创建临时目录失败")
    }

    fn gw() -> HostPort {
        "gateway.company.com:443".parse().unwrap()
    }

    /// 测试用的合法指纹：真的走一遍 `fingerprint_sha256()`，保证形状
    /// 能通过 R25 的校验（43 个无填充 base64 字符），不同的 seed 产出
    /// 不同的指纹字符串。R25 之后，字面量 "SHA256:aaa" 这种占位符已经
    /// 不再是「看起来无所谓的短字符串」——它自己就是一个形状不合法的
    /// 指纹，会被 lookup() 当成损坏处理，所以测试里但凡指纹要被写入
    /// 文件、再被读回来比对，就必须用这个函数产出的真实形状。
    fn fp(seed: &str) -> String {
        fingerprint_sha256(seed.as_bytes())
    }

    #[test]
    fn first_connection_records_the_key() {
        let dir = tmpdir();
        let kh = KnownHosts::open(dir.path().join("known_hosts"));
        assert_eq!(kh.check(&gw(), &fp("a")).unwrap(), Verdict::FirstSeen);
        assert_eq!(kh.check(&gw(), &fp("a")).unwrap(), Verdict::Matched);
    }

    #[test]
    fn changed_key_is_rejected_with_both_fingerprints() {
        let dir = tmpdir();
        let kh = KnownHosts::open(dir.path().join("known_hosts"));
        kh.check(&gw(), &fp("a")).unwrap();
        let err = kh.check(&gw(), &fp("b")).unwrap_err();
        match err {
            Error::HostKeyMismatch { expected, actual } => {
                assert_eq!(expected, fp("a"));
                assert_eq!(actual, fp("b"));
            }
            other => panic!("类别不对：{other}"),
        }
    }

    #[test]
    fn mismatch_does_not_overwrite_the_record() {
        let dir = tmpdir();
        let kh = KnownHosts::open(dir.path().join("known_hosts"));
        kh.check(&gw(), &fp("a")).unwrap();
        let _ = kh.check(&gw(), &fp("b"));
        assert_eq!(kh.check(&gw(), &fp("a")).unwrap(), Verdict::Matched);
    }

    #[test]
    fn different_gateways_are_tracked_separately() {
        let dir = tmpdir();
        let kh = KnownHosts::open(dir.path().join("known_hosts"));
        let a: HostPort = "gw-a.company.com:443".parse().unwrap();
        let b: HostPort = "gw-b.company.com:443".parse().unwrap();
        kh.check(&a, &fp("a")).unwrap();
        assert_eq!(kh.check(&b, &fp("b")).unwrap(), Verdict::FirstSeen);
        assert_eq!(kh.check(&a, &fp("a")).unwrap(), Verdict::Matched);
    }

    #[test]
    fn same_host_on_a_different_port_is_a_separate_record() {
        let dir = tmpdir();
        let kh = KnownHosts::open(dir.path().join("known_hosts"));
        let a: HostPort = "gw.company.com:443".parse().unwrap();
        let b: HostPort = "gw.company.com:2222".parse().unwrap();
        kh.check(&a, &fp("a")).unwrap();
        assert_eq!(kh.check(&b, &fp("a")).unwrap(), Verdict::FirstSeen);
    }

    #[test]
    fn creates_parent_directory_on_first_write() {
        let dir = tmpdir();
        let path = dir.path().join("nested").join("deeper").join("known_hosts");
        let kh = KnownHosts::open(path.clone());
        kh.check(&gw(), &fp("a")).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn ignores_blank_and_comment_lines() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        std::fs::write(
            &path,
            format!("# 注释\n\n[gateway.company.com]:443 {}\n", fp("a")),
        )
        .unwrap();
        let kh = KnownHosts::open(path);
        assert_eq!(kh.check(&gw(), &fp("a")).unwrap(), Verdict::Matched);
    }

    #[test]
    fn fingerprint_format_matches_openssh() {
        // ssh-keygen -lf 的输出形如 SHA256:<43 个 base64 字符，无填充>
        let fp = fingerprint_sha256(b"test key blob");
        assert!(fp.starts_with("SHA256:"), "{fp}");
        let body = &fp["SHA256:".len()..];
        assert_eq!(body.len(), 43, "{fp}");
        assert!(!body.contains('='), "{fp}");
    }

    // --- 以下是本任务补的用例 ---

    // 这是最关键的一条：只用同一个 KnownHosts 实例前后调用两次 check，
    // 证明不了「记录真的落盘了」——如果实现偷懒用内存里的 HashMap 缓存、
    // 从来没真正写文件，上面几条测试一样会绿。这里显式 drop 掉第一个
    // 实例、重新从磁盘打开第二个实例，只有真的落盘读回才能让变更拒绝
    // 生效。
    //
    // 会让这条测试变红的改法：把 check()/append() 改成只在内存里维护一份
    // HashMap，不写文件（或者写了文件但 lookup 不读文件，直接查内存）。
    #[test]
    fn mismatch_is_still_rejected_after_reopening_the_store_from_disk() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        {
            let kh = KnownHosts::open(path.clone());
            assert_eq!(kh.check(&gw(), &fp("a")).unwrap(), Verdict::FirstSeen);
        } // kh 在此 drop，不留任何进程内状态

        let kh2 = KnownHosts::open(path);
        // 先证明确实是从磁盘读回来的匹配值……
        assert_eq!(kh2.check(&gw(), &fp("a")).unwrap(), Verdict::Matched);
        // ……再证明变更会被拒绝，且不是拿内存里的旧值凑巧比对上的。
        let err = kh2.check(&gw(), &fp("b")).unwrap_err();
        match err {
            Error::HostKeyMismatch { expected, actual } => {
                assert_eq!(expected, fp("a"));
                assert_eq!(actual, fp("b"));
            }
            other => panic!("类别不对：{other}"),
        }
    }

    // 文件存在但是空文件，跟文件压根不存在应该是同一种效果：都还没有任何
    // 记录。
    //
    // 会让这条测试变红的改法：把「文本为空」当成一种损坏格式来报错，而不
    // 是当成零条记录处理。
    #[test]
    fn empty_file_behaves_like_no_records_yet() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, "").unwrap(); // 文件存在，但 0 字节——不同于文件不存在
        let kh = KnownHosts::open(path);
        assert_eq!(kh.check(&gw(), &fp("a")).unwrap(), Verdict::FirstSeen);
    }

    // 【表格行 2：右 host，缺指纹】被篡改成「这一行解析不出指纹」的
    // 记录，绝不能被当成「这个 Gateway 还没见过」处理——那样一次针对
    // 目标记录的破坏就能骗过变更拒绝，变成隐蔽的首次信任（TOFU 被
    // 绕过）。必须报错，而且要分类成 Fatal。
    //
    // 会让这条测试变红的改法：lookup() 遇到解析不出「host 指纹」两段的
    // 行时把它当成无害记录悄悄跳过，而不是计入 damaged。
    #[test]
    fn malformed_line_for_the_target_host_is_rejected_not_treated_as_first_seen() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        // 只有 host，没有指纹字段：格式损坏。
        std::fs::write(&path, "[gateway.company.com]:443\n").unwrap();
        let kh = KnownHosts::open(path);
        let err = kh.check(&gw(), &fp("a")).unwrap_err();
        assert_eq!(err.class(), ErrorClass::Fatal, "{err}");
        assert!(
            !matches!(err, Error::HostKeyMismatch { .. }),
            "损坏的记录不是「不一致」，是「读不出来」，两者需要区分：{err}"
        );
    }

    // R24 的「一个代价」：文件里有一行损坏（哪怕是别的 host 的），去连
    // 一个全新、真正从没见过的 Gateway 也会被拒绝。这是 R21 那版
    // 「不该拖累无关 host」结论的直接反转——R21 本身考虑的可用性方向没
    // 错，但裁决重新判过之后认为：没法排除那行损坏原本就是当前查询的
    // host 自己的记录，「大概率不是我」不足以支撑放行写一条全新记录。
    //
    // 会让这条测试变红的改法：只要 host 不匹配 key 就直接跳过、不计入
    // damaged（也就是 R21 版本的写法）。
    #[test]
    fn damaged_line_for_a_different_host_blocks_first_seen_for_a_brand_new_host() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        // 只有 gw-a 的一条坏记录（缺指纹），从没出现过 gw-b。
        std::fs::write(&path, "[gw-a.company.com]:443\n").unwrap();
        let kh = KnownHosts::open(path);
        let b: HostPort = "gw-b.company.com:443".parse().unwrap();
        let err = kh.check(&b, &fp("b")).unwrap_err();
        assert_eq!(err.class(), ErrorClass::Fatal, "{err}");
    }

    // R24 保住的那一半：只要 `key` 自己有精确匹配，文件里别处再乱也不
    // 影响这次查询的答案——这是 R21 想要的可用性，R24 之下依然成立。
    //
    // 会让这条测试变红的改法：找到精确匹配之后，还因为文件里存在别处
    // 的 damaged 记录而报错（也就是 a633146 版本的写法——任何记录损坏
    // 都能连累一次精确匹配）。
    #[test]
    fn malformed_line_for_a_different_host_does_not_block_a_valid_match_for_this_host() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        // gw-a 有合法记录；gw-b 的记录缺指纹，格式损坏，但跟这次查询
        // gw-a 无关。
        std::fs::write(
            &path,
            format!(
                "[gw-a.company.com]:443 {}\n[gw-b.company.com]:443\n",
                fp("a")
            ),
        )
        .unwrap();
        let kh = KnownHosts::open(path);
        let a: HostPort = "gw-a.company.com:443".parse().unwrap();
        assert_eq!(kh.check(&a, &fp("a")).unwrap(), Verdict::Matched);
    }

    // 【表格行 3：行首有空白】不该被误伤——这是正常场景，不是损坏。
    // 缩进、手工编辑留下的前导空格必须被 `trim()` 正常吃掉，走到跟没有
    // 缩进完全一样的干净记录路径。
    //
    // 会让这条测试变红的改法：校验时用 `raw` 而不是 `raw.trim()`，导致
    // 行首空白被当成 host token 的一部分，从而 `looks_like_host_token`
    // 失败、被误判成损坏。
    #[test]
    fn leading_whitespace_before_a_record_is_not_treated_as_damage() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, format!("   [gateway.company.com]:443 {}\n", fp("a"))).unwrap();
        let kh = KnownHosts::open(path);
        assert_eq!(kh.check(&gw(), &fp("a")).unwrap(), Verdict::Matched);
    }

    // 【表格行 4，本轮加固的两条之一：host 段被砸坏、token 数量不变】
    // 掉了开头的方括号——`split_whitespace()` 看到的仍然是「一行两个
    // token」，token 数量没有变化，但 host 段已经不是「[<内容>]:<端口>」
    // 这个形状了。这条在 a633146 与上一轮（R21）里都没有关上：两版都
    // 只比较 host 字符串是否等于 key，对不上就当成「无关的另一个
    // host」放过，从没检查过 host 段本身还成不成形状。
    //
    // 会让这条测试变红的改法：去掉 `looks_like_host_token` 校验，只要
    // token 数量对（两段）、fp 形状对，就当成干净记录，不管 host 段
    // 本身的分隔符结构是否完整。
    #[test]
    fn host_token_corrupted_with_token_count_preserved_is_fatal() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        // 掉了开头的 '['：还是恰好两个空白分隔的 token，但 host 段
        // 形状已经不对了。
        std::fs::write(&path, format!("gateway.company.com]:443 {}\n", fp("a"))).unwrap();
        let kh = KnownHosts::open(path);
        let err = kh.check(&gw(), &fp("a")).unwrap_err();
        assert_eq!(err.class(), ErrorClass::Fatal, "{err}");
    }

    // 【表格行 5，本轮加固的两条之一：host 段被砸坏、token 数量被打破】
    // host 内部混进了一个空格——`split_whitespace()` 会把这一行切成
    // 三段而不是两段。这条在 a633146 里是 Fatal（那版先校验格式、不管
    // host 是否匹配），但在上一轮 R21 的改法下变成了 FirstSeen——R21
    // 把「先看 host 是否等于 key」放到了格式校验前面，而这里 host 段
    // 里混进空格之后，`parts.next()` 拿到的第一个 token 只是 host 的
    // 前半截，天然就跟完整的 key 字符串不相等，于是被当成「无关的另一
    // 个 host」直接跳过，格式校验根本没机会跑——这是 R21 改法引入的
    // 真实回归，不是本来就该这样。
    //
    // 会让这条测试变红的改法：恢复 R21 版本的判断顺序（先比较第一个
    // token 是否等于 key，不等于就直接 continue，不管后面 token 数量
    // 对不对）。
    #[test]
    fn host_token_corrupted_with_token_count_broken_is_fatal() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        // host 内部混进一个空格，行被切成三段。
        std::fs::write(&path, format!("[gateway. company.com]:443 {}\n", fp("a"))).unwrap();
        let kh = KnownHosts::open(path);
        let err = kh.check(&gw(), &fp("a")).unwrap_err();
        assert_eq!(err.class(), ErrorClass::Fatal, "{err}");
    }

    // 【表格行 1：host 段之后跟着多余的垃圾字段】跟上一条是同一个机制
    // （token 数量对不上就是损坏），只是垃圾出现在末尾而不是 host 内部。
    // 顺带覆盖「host 重复出现／多余字段」这一类——不管多出来的那个
    // token 内容是垃圾还是把 host 重复写了一遍，`extra` 非 None 就足以
    // 判定损坏，不需要关心多出来的内容具体是什么。
    #[test]
    fn host_line_with_a_garbage_trailing_field_is_treated_as_damaged() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        std::fs::write(
            &path,
            format!("[gateway.company.com]:443 {} 多余的垃圾字段\n", fp("a")),
        )
        .unwrap();
        let kh = KnownHosts::open(path);
        let err = kh.check(&gw(), &fp("a")).unwrap_err();
        assert_eq!(err.class(), ErrorClass::Fatal, "{err}");
    }

    // 【表格行 7：host 段为空】方括号里什么都没有——`looks_like_host_token`
    // 里「内容非空」这条分支专门盯这个。
    #[test]
    fn empty_bracketed_host_is_treated_as_damaged() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, format!("[]:443 {}\n", fp("a"))).unwrap();
        let kh = KnownHosts::open(path);
        let b: HostPort = "gw-b.company.com:443".parse().unwrap();
        // 查询一个跟这条空 host 记录毫不相关的全新 host，一样要 Fatal
        // ——这条空记录既不匹配任何合法 key，也不能被放过。
        let err = kh.check(&b, &fp("b")).unwrap_err();
        assert_eq!(err.class(), ErrorClass::Fatal, "{err}");
    }

    // 【表格行 8：指纹段本身被砸坏】这是 R25 承重的地方：指纹段形状
    // 校验之前，一行「host 对不上、指纹段本身是垃圾」的记录会被当成
    // 「正常但无关的记录」放过，不计入 damaged——而 R24 之下，任何
    // 记录都可能是被砸坏的 `key` 自己的记录，指纹段的损坏必须一样能
    // 表现成解析失败。
    //
    // 会让这条测试变红的改法：去掉 `looks_like_fingerprint` 校验，只要
    // 是非空白字符串就当成合法指纹。
    #[test]
    fn damage_inside_the_fingerprint_token_blocks_first_seen_for_a_different_host() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        // gw-a 的指纹段本身是垃圾（形状不对，不是 43 字符无填充
        // base64），查询的是完全不同的 gw-b。
        std::fs::write(&path, "[gw-a.company.com]:443 SHA256:这不是合法指纹\n").unwrap();
        let kh = KnownHosts::open(path);
        let b: HostPort = "gw-b.company.com:443".parse().unwrap();
        let err = kh.check(&b, &fp("b")).unwrap_err();
        assert_eq!(err.class(), ErrorClass::Fatal, "{err}");
    }

    // 同一个 host 出现两条互相矛盾的记录（例如被篡改追加了一条），无法
    // 判断哪一条才是真的，不能悄悄选一条了事——那样攻击者只要在合法记录
    // 后面追加一行自己的假指纹，就有几率被采信。必须报错交给人核实。
    //
    // 这里两条指纹都必须是形状合法的真实指纹（用 fp() 产出），否则这条
    // 测试测的就不是「两条合法但矛盾的记录」，而是巧合般走到了
    // 「指纹形状不对，判定成 damaged」那条分支——虽然结果都是 Fatal，
    // 但测的已经不是这个测试名字所声称的东西了。
    //
    // 会让这条测试变红的改法：lookup() 找到第一条匹配就直接 return（“先到
    // 先得”，不再继续扫描核对后面是否有冲突记录）。
    #[test]
    fn conflicting_duplicate_entries_are_rejected() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        std::fs::write(
            &path,
            format!(
                "[gateway.company.com]:443 {}\n[gateway.company.com]:443 {}\n",
                fp("a"),
                fp("b")
            ),
        )
        .unwrap();
        let kh = KnownHosts::open(path);
        let err = kh.check(&gw(), &fp("a")).unwrap_err();
        assert_eq!(err.class(), ErrorClass::Fatal, "{err}");
        assert!(
            !matches!(err, Error::HostKeyMismatch { .. }),
            "这是「文件里有两条矛盾记录」，不是「记录和这次连接的指纹不一致」：{err}"
        );
    }

    // 两条完全相同的记录重复出现（比如并发写入偶然造成的重复行），跟只有
    // 一条记录是等价的，不该报错——这条用来和上一条「冲突」区分开：容忍
    // 的是「重复」，拒绝的是「矛盾」。
    #[test]
    fn duplicate_identical_entries_are_tolerated() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        std::fs::write(
            &path,
            format!(
                "[gateway.company.com]:443 {}\n[gateway.company.com]:443 {}\n",
                fp("a"),
                fp("a")
            ),
        )
        .unwrap();
        let kh = KnownHosts::open(path);
        assert_eq!(kh.check(&gw(), &fp("a")).unwrap(), Verdict::Matched);
    }

    // 证明本地文件系统故障分类成 Fatal，不是 Network——这是本任务存在的
    // 裁决理由本身：退避重连解决不了权限错误/磁盘满，如果分类成 Network，
    // Supervisor 会永远重建隧道，工程师永远看不到需要处理的原因。
    //
    // 这条测试特意让 lookup() 那半边先顺利放行（目标文件本身「找不到」，
    // 落在 NotFound 分支，返回 Ok(None)，跟正常的「第一次见」没有区别），
    // 好让失败真的发生在 append() 的 create_dir_all 这一步：父目录本身
    // 存在、可读可执行，唯独没有写权限，所以在它下面新建 `missing_subdir`
    // 会失败在「没权限」而不是「不存在」——这样才是真的在盯 append() 这条
    // 路径上的 LocalIo 映射，而不是又落回 lookup() 的通用分支（早先的
    // 写法「父路径本身是个文件」在 lookup() 阶段 read_to_string 就已经
    // 因为 NotADirectory 报错退出了，从没走到 append()，那种写法测的其实
    // 是 lookup()，不是本意，已改成下面这条只测 lookup() 的测试）。
    //
    // 用改权限位而不是「父路径是个文件」，是因为这次要制造的失败点必须
    // 在 append() 里，不能在 lookup() 里就先跳出去。
    //
    // R22：改权限位这个手法本身依赖「当前用户挡得住权限位」——以 root
    // 跑测试时 CAP_DAC_OVERRIDE 会让 0o500 形同虚设，create_dir_all 照样
    // 成功，这不是代码有 bug，是这台机器压根没法制造出「本地文件系统
    // 失败」这个前提。跟 gateway/tests/test_scripts.bats 里
    // `[ -f /.dockerenv ] || skip "..."` 一个思路：环境不满足就明说原因
    // 跳过，不能既跳不过又断言失败，把「环境不支持」和「代码有 bug」
    // 混成一回事。`rmc-core`目前还没有 CI，没法断言「跑测试的环境一定
    // 不是 root」，所以这里在运行时探测。
    //
    // 会让这条测试变红的改法：append() 里把 create_dir_all 那行的
    // Error::LocalIo 换回 Error::Io（或者恢复成裸的 `?`，如果 Error 上又
    // 挂回了 `From<io::Error>`）。
    #[test]
    #[cfg(unix)]
    fn unwritable_known_hosts_directory_is_fatal_not_network() {
        use std::os::unix::fs::PermissionsExt;

        if running_as_root() {
            eprintln!(
                "跳过 unwritable_known_hosts_directory_is_fatal_not_network：\
                 当前以 root 运行，权限位挡不住 root（CAP_DAC_OVERRIDE），\
                 这个环境没法验证「目录不可写导致 LocalIo」这个前提，\
                 不是这条测试或者被测代码本身有问题。"
            );
            return;
        }

        let dir = tmpdir();
        let readonly_dir = dir.path().join("readonly_dir");
        std::fs::create_dir_all(&readonly_dir).unwrap();
        std::fs::set_permissions(&readonly_dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let path = readonly_dir.join("missing_subdir").join("known_hosts");
        let kh = KnownHosts::open(path);
        let err = kh.check(&gw(), &fp("a")).unwrap_err();

        // 测试结束前把权限还原，不然临时目录在某些平台上可能删不掉。
        std::fs::set_permissions(&readonly_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(err.class(), ErrorClass::Fatal, "{err}");
        assert!(
            matches!(err, Error::LocalIo(_)),
            "应为 LocalIo，而不是 {err}"
        );
    }

    /// 是否以 root 身份在跑测试。用外部 `id -u` 命令而不是 unsafe 调用
    /// `geteuid()`——crate 顶层 `#![forbid(unsafe_code)]` 对测试代码
    /// 同样生效，`id` 是 coreutils 的一部分，Linux/macOS 都自带。
    #[cfg(unix)]
    fn running_as_root() -> bool {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .filter(|out| out.status.success())
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|s| s.trim() == "0")
            .unwrap_or(false)
    }

    // 同一条裁决的另一半：读的那条路径（lookup）也要落到 LocalIo，不是
    // Io——brief 给的原始实现在这里恰好写反了（`Error::Io(e)`），这条测试
    // 专门盯这个位置。
    //
    // 会让这条测试变红的改法：lookup() 里 `Err(e) => return
    // Err(Error::Io(e))`（brief 原文的写法）。
    #[test]
    fn known_hosts_path_that_is_a_directory_is_fatal_not_network() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        std::fs::create_dir_all(&path).unwrap(); // 让 known_hosts 路径本身是个目录
        let kh = KnownHosts::open(path);
        let err = kh.check(&gw(), &fp("a")).unwrap_err();
        assert_eq!(err.class(), ErrorClass::Fatal, "{err}");
        assert!(
            matches!(err, Error::LocalIo(_)),
            "应为 LocalIo，而不是 {err}"
        );
    }
}
