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
//! 这份自定义格式的解析故意很严格：任何一行既不是空行、也不是以 `#`
//! 开头的注释，又对得上「本次查询的 host」却切不出「host 指纹」恰好
//! 两段的，一律当成文件已损坏，直接报错（`Error::LocalIo`，分类
//! Fatal），绝不 `continue` 跳过悄悄当成“没这条记录”处理。理由是这个
//! 模块存在的意义就是拒绝「Gateway host key 变了」——如果攻击者把目标
//! 记录本身改成解析不出来的样子，一个「解析失败就当没见过」的实现会把
//! 这次篡改误判成「首次连接」，反手写下攻击者的假指纹，TOFU 保护形同
//! 虚设。同理，同一个 host 出现两条互相矛盾的记录（被追加了一行假的）
//! 也不挑一条算数，一样报错交给人核实；两条完全相同的记录才当作无害的
//! 重复容忍。
//!
//! R21：这份严格校验的范围只到「本次查询的 host」为止，不因为**别的**
//! host 的记录损坏而牵连整个文件。客户端在服役期里会陆续给多个客户
//! Gateway 各记一条（见 `different_gateways_are_tracked_separately`），
//! 如果任何一行格式不对就让整份文件报废，一次并发写入的半截写入、一次
//! 手工改错、一处局部磁盘损坏，就能拖累文件里所有其它本来完好的
//! Gateway，直到有人手工修好这份文件——影响面比这个模块要防的「针对
//! 某一条记录的定向篡改」大得多。所以判断顺序是：先看这一行的 host
//! 是不是当前要查的那个，不是就跳过（哪怕这一行本身格式不对，也留给
//! 它自己的 host 被查询的那一刻去触发同样的保护）；是的话才要求剩下
//! 的部分必须是「指纹，且恰好一段」，对不上就报错。
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

/// 文件已损坏（某一行解析不出「host 指纹」两段，或者同一个 host 有互相
/// 矛盾的记录）时构造的错误。用 `ErrorKind::InvalidData` 包一层
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

    /// 在文件里查找 `key` 对应的指纹。
    ///
    /// 返回值的三种情况：
    /// - `Ok(None)`：文件不存在，或者存在但没有这个 host 的记录——两者
    ///   视为等价，都是「还没见过这个 Gateway」。
    /// - `Ok(Some(fp))`：找到唯一的记录（或者若干条内容完全相同的重复
    ///   记录）。
    /// - `Err(_)`：文件读不出来（本地 IO 故障），或者 `key` 自己的那条
    ///   记录没法安全解释（这一行本身解析不出「指纹」，或者同一个 host
    ///   有互相矛盾的记录）。
    ///
    /// R21：校验范围只到 `key` 为止——别的 host 的记录哪怕格式本身有
    /// 问题，只要它的 host 段不是 `key`，这里就当它不存在，不会因此
    /// 拒绝当前这次查询。理由见模块顶部的注释：一份 known_hosts 会记
    /// 多个 Gateway，不能因为其中一条坏了就让所有其它 Gateway 的维护
    /// 全部停摆；等那条坏记录自己的 host 被查询时，同样的保护会再次
    /// 触发，篡改并没有被这次放行绕过。
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
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            // 非空、非注释行 trim 后不可能是空字符串，split_whitespace
            // 至少产出一个 token。
            let host = parts.next().expect("非空行必有至少一个 token");
            // R21：先只看这一行是不是 `key` 的记录，跟这次查询无关的行
            // 立刻跳过——哪怕它自己格式不对，也不在这次查询的校验范围
            // 内，见本函数上面的文档注释与模块顶部的注释。
            if host != key {
                continue;
            }
            let fp = parts.next();
            let extra = parts.next();
            let (Some(fp), None) = (fp, extra) else {
                // 故意不 continue 跳过：这一行的 host 段就是 `key` 本身，
                // 却切不出「指纹」恰好一段，说明这条记录被破坏到没法
                // 安全解释了——不能假装没看见，见模块顶部的注释。
                return Err(corrupt(format!(
                    "known_hosts 第 {} 行 {key} 的记录格式不对（应为「[host]:port SHA256:...」）：{raw}",
                    lineno + 1
                )));
            };
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
        Ok(found)
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

    #[test]
    fn first_connection_records_the_key() {
        let dir = tmpdir();
        let kh = KnownHosts::open(dir.path().join("known_hosts"));
        assert_eq!(kh.check(&gw(), "SHA256:aaa").unwrap(), Verdict::FirstSeen);
        assert_eq!(kh.check(&gw(), "SHA256:aaa").unwrap(), Verdict::Matched);
    }

    #[test]
    fn changed_key_is_rejected_with_both_fingerprints() {
        let dir = tmpdir();
        let kh = KnownHosts::open(dir.path().join("known_hosts"));
        kh.check(&gw(), "SHA256:aaa").unwrap();
        let err = kh.check(&gw(), "SHA256:bbb").unwrap_err();
        match err {
            Error::HostKeyMismatch { expected, actual } => {
                assert_eq!(expected, "SHA256:aaa");
                assert_eq!(actual, "SHA256:bbb");
            }
            other => panic!("类别不对：{other}"),
        }
    }

    #[test]
    fn mismatch_does_not_overwrite_the_record() {
        let dir = tmpdir();
        let kh = KnownHosts::open(dir.path().join("known_hosts"));
        kh.check(&gw(), "SHA256:aaa").unwrap();
        let _ = kh.check(&gw(), "SHA256:bbb");
        assert_eq!(kh.check(&gw(), "SHA256:aaa").unwrap(), Verdict::Matched);
    }

    #[test]
    fn different_gateways_are_tracked_separately() {
        let dir = tmpdir();
        let kh = KnownHosts::open(dir.path().join("known_hosts"));
        let a: HostPort = "gw-a.company.com:443".parse().unwrap();
        let b: HostPort = "gw-b.company.com:443".parse().unwrap();
        kh.check(&a, "SHA256:aaa").unwrap();
        assert_eq!(kh.check(&b, "SHA256:bbb").unwrap(), Verdict::FirstSeen);
        assert_eq!(kh.check(&a, "SHA256:aaa").unwrap(), Verdict::Matched);
    }

    #[test]
    fn same_host_on_a_different_port_is_a_separate_record() {
        let dir = tmpdir();
        let kh = KnownHosts::open(dir.path().join("known_hosts"));
        let a: HostPort = "gw.company.com:443".parse().unwrap();
        let b: HostPort = "gw.company.com:2222".parse().unwrap();
        kh.check(&a, "SHA256:aaa").unwrap();
        assert_eq!(kh.check(&b, "SHA256:aaa").unwrap(), Verdict::FirstSeen);
    }

    #[test]
    fn creates_parent_directory_on_first_write() {
        let dir = tmpdir();
        let path = dir.path().join("nested").join("deeper").join("known_hosts");
        let kh = KnownHosts::open(path.clone());
        kh.check(&gw(), "SHA256:aaa").unwrap();
        assert!(path.exists());
    }

    #[test]
    fn ignores_blank_and_comment_lines() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, "# 注释\n\n[gateway.company.com]:443 SHA256:aaa\n").unwrap();
        let kh = KnownHosts::open(path);
        assert_eq!(kh.check(&gw(), "SHA256:aaa").unwrap(), Verdict::Matched);
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
            assert_eq!(kh.check(&gw(), "SHA256:aaa").unwrap(), Verdict::FirstSeen);
        } // kh 在此 drop，不留任何进程内状态

        let kh2 = KnownHosts::open(path);
        // 先证明确实是从磁盘读回来的匹配值……
        assert_eq!(kh2.check(&gw(), "SHA256:aaa").unwrap(), Verdict::Matched);
        // ……再证明变更会被拒绝，且不是拿内存里的旧值凑巧比对上的。
        let err = kh2.check(&gw(), "SHA256:bbb").unwrap_err();
        match err {
            Error::HostKeyMismatch { expected, actual } => {
                assert_eq!(expected, "SHA256:aaa");
                assert_eq!(actual, "SHA256:bbb");
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
        assert_eq!(kh.check(&gw(), "SHA256:aaa").unwrap(), Verdict::FirstSeen);
    }

    // 被篡改成「这一行解析不出指纹」的记录，绝不能被当成「这个 Gateway
    // 还没见过」处理——那样一次针对目标记录的破坏就能骗过变更拒绝，变成
    // 隐蔽的首次信任（TOFU 被绕过）。必须报错，而且要分类成 Fatal。
    //
    // 会让这条测试变红的改法：lookup() 遇到解析不出「host 指纹」两段的
    // 行时 continue 跳过（也就是这份 brief 原始实现的写法），而不是报错。
    #[test]
    fn malformed_line_for_the_target_host_is_rejected_not_treated_as_first_seen() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        // 只有 host，没有指纹字段：格式损坏。
        std::fs::write(&path, "[gateway.company.com]:443\n").unwrap();
        let kh = KnownHosts::open(path);
        let err = kh.check(&gw(), "SHA256:aaa").unwrap_err();
        assert_eq!(err.class(), ErrorClass::Fatal, "{err}");
        assert!(
            !matches!(err, Error::HostKeyMismatch { .. }),
            "损坏的记录不是「不一致」，是「读不出来」，两者需要区分：{err}"
        );
    }

    // R21：别的 host 的记录格式不对，不该拖累「这个从没见过的 host 应该
    // 是 FirstSeen」这个结论——一份 known_hosts 会记多个 Gateway，一条
    // 记录损坏不该让所有其它 Gateway 的维护全部停摆。
    //
    // 会让这条测试变红的改法：把 lookup() 里「先判断 host 是否匹配 key
    // 再校验格式」的顺序颠倒回「先校验格式再判断 host」（R21 之前的
    // 写法）。
    #[test]
    fn malformed_line_for_a_different_host_does_not_block_first_seen_for_this_host() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        // 只有 gw-a 的一条坏记录（缺指纹），从没出现过 gw-b。
        std::fs::write(&path, "[gw-a.company.com]:443\n").unwrap();
        let kh = KnownHosts::open(path);
        let b: HostPort = "gw-b.company.com:443".parse().unwrap();
        assert_eq!(kh.check(&b, "SHA256:bbb").unwrap(), Verdict::FirstSeen);
    }

    // R21 的另一半：别的 host 的记录格式不对，也不该拖累「这个 host 的
    // 合法记录本来就该 Matched」这个结论。
    //
    // 会让这条测试变红的改法：同上，颠倒 lookup() 里的判断顺序。
    #[test]
    fn malformed_line_for_a_different_host_does_not_block_a_valid_match_for_this_host() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        // gw-a 有合法记录；gw-b 的记录缺指纹，格式损坏，但跟这次查询
        // gw-a 无关。
        std::fs::write(
            &path,
            "[gw-a.company.com]:443 SHA256:aaa\n[gw-b.company.com]:443\n",
        )
        .unwrap();
        let kh = KnownHosts::open(path);
        let a: HostPort = "gw-a.company.com:443".parse().unwrap();
        assert_eq!(kh.check(&a, "SHA256:aaa").unwrap(), Verdict::Matched);
    }

    // 同一个 host 出现两条互相矛盾的记录（例如被篡改追加了一条），无法
    // 判断哪一条才是真的，不能悄悄选一条了事——那样攻击者只要在合法记录
    // 后面追加一行自己的假指纹，就有几率被采信。必须报错交给人核实。
    //
    // 会让这条测试变红的改法：lookup() 找到第一条匹配就直接 return（“先到
    // 先得”，不再继续扫描核对后面是否有冲突记录）。
    #[test]
    fn conflicting_duplicate_entries_are_rejected() {
        let dir = tmpdir();
        let path = dir.path().join("known_hosts");
        std::fs::write(
            &path,
            "[gateway.company.com]:443 SHA256:aaa\n[gateway.company.com]:443 SHA256:bbb\n",
        )
        .unwrap();
        let kh = KnownHosts::open(path);
        let err = kh.check(&gw(), "SHA256:aaa").unwrap_err();
        assert_eq!(err.class(), ErrorClass::Fatal, "{err}");
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
            "[gateway.company.com]:443 SHA256:aaa\n[gateway.company.com]:443 SHA256:aaa\n",
        )
        .unwrap();
        let kh = KnownHosts::open(path);
        assert_eq!(kh.check(&gw(), "SHA256:aaa").unwrap(), Verdict::Matched);
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
        let err = kh.check(&gw(), "SHA256:aaa").unwrap_err();

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
        let err = kh.check(&gw(), "SHA256:aaa").unwrap_err();
        assert_eq!(err.class(), ErrorClass::Fatal, "{err}");
        assert!(
            matches!(err, Error::LocalIo(_)),
            "应为 LocalIo，而不是 {err}"
        );
    }
}
