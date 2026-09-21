//! OpenSSH 风格的指纹工具，只给一体机 host key 的展示用。
//!
//! # Task 10：这个模块从「host key 变更拒绝账本」瘦身成纯工具函数
//!
//! 在本任务之前，这个模块还实现了一份自定义 known_hosts 文件（首次
//! 记录、变更拒绝、损坏检测……），用来核对运维服务器的 SSH host key。
//! 本任务把运维服务器一侧的 host key 校验换成了「核对连接码里的指纹」
//! （`rmc_core::code::ServerFingerprint`，`ssh::handler::ClientHandler::
//! check_server_key`）——没有「首次连接自动信任」，也没有本地状态可以
//! 持久化，因此 `KnownHosts`/`Verdict`/`check()`/`open()`/文件读写整个
//! 失去了存在理由，随本任务一起删掉。
//!
//! **留下来的这几样，服务的是另一件事**：预检第二步（`preflight.rs`
//! 的 `probe_host_key_over`）要把一体机的 SSH host key 渲染成运维手册
//! 里工程师能拿 `ssh-keygen -lf` 肉眼核对的样子——那是给人看的展示，
//! 不是我们钉死比对的那个指纹（`ServerFingerprint`：对 32 字节裸
//! ed25519 公钥做 SHA-256 再 base64url，不带填充）。两套指纹算法不是
//! 一回事，不能混用：
//!
//! - [`fingerprint_sha256`] / [`fingerprint_of`]：OpenSSH 风格
//!   `SHA256:<43 个无填充 base64 字符>`，对整个公钥 blob（`ssh-ed25519`
//!   编码，含类型前缀）做哈希——一体机指纹展示用这个；
//! - `rmc_core::code::ServerFingerprint::of_ed25519_public`：对**裸**
//!   32 字节 ed25519 公钥做哈希，base64url 编码——运维服务器 TLS/SSH
//!   两层比对连接码指纹用这个。
//!
//! [`Fingerprint`] 与 [`redact_for_error`] 是这两个函数的配套类型/
//! 工具，一并留下。

use crate::error::{Error, Result};

/// 按 OpenSSH 的方式计算指纹：SHA256 后 base64，去掉填充，得到形如
/// `SHA256:<43 个字符>` 的字符串——与 `ssh-keygen -lf` 的输出逐字符一致，
/// 运维手册要求工程师能拿客户端界面上的这串和一体机侧
/// `ssh-keygen -lf` 读出来的肉眼核对，格式对不上就没法比。
pub fn fingerprint_sha256(key_blob: &[u8]) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(key_blob);
    let body = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    format!("SHA256:{body}")
}

/// 一体机指纹展示的入口：直接产出类型化的 [`Fingerprint`]，不需要调用方
/// 自己再包一层 `Fingerprint::new(&fingerprint_sha256(blob)).expect(...)`
/// ——这个 round-trip 永远不会失败（`fingerprint_sha256` 产出的形状本来
/// 就是 `Fingerprint::new` 认可的那种），但"永远不会失败"不等于"可以在
/// 展示路径上放一个 `expect`"：这里直接在指纹自己的模块内构造
/// `Fingerprint`，绕开 `new()` 的运行时校验——校验从"运行时判断，可能
/// 失败"变成"由这个函数的实现保证"。
pub fn fingerprint_of(key_blob: &[u8]) -> Fingerprint {
    Fingerprint(fingerprint_sha256(key_blob))
}

/// 指纹段是否长得像 [`fingerprint_sha256`] 会产出的样子——`SHA256:` 后跟
/// 43 个无填充 base64 字符。
fn looks_like_fingerprint(token: &str) -> bool {
    let Some(body) = token.strip_prefix("SHA256:") else {
        return false;
    };
    body.len() == 43
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// 已经校验过形状（`SHA256:` 加 43 个合法字符）的指纹。只能通过
/// [`Fingerprint::new`] 构造——字段私有，本模块之外没有办法绕开校验直接
/// 拼出一个实例。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// 校验 `s` 是否形如 `SHA256:` 加 43 个合法字符；校验通过才能构造出
    /// 实例。
    pub fn new(s: &str) -> Result<Self> {
        if looks_like_fingerprint(s) {
            Ok(Self(s.to_string()))
        } else {
            Err(Error::Config(format!(
                "指纹格式不对，应为「SHA256:」加 43 个 base64 字符：{s}"
            )))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// 把不受信任的原文安全地嵌进用户可见的错误文案：截断长度、转义不可
/// 打印字符。本模块自己已经不再有会读到不受信任内容的代码路径（那是
/// 删掉的文件损坏检测的事），但 `transport/connect.rs` 里代理响应头的
/// 长度截断规范仍然引用这条规矩（同一处不受信任原文进错误文案的规矩，
/// 不必另写一份），留着给它当参照与共用的转义实现。
pub fn redact_for_error(raw: &str) -> String {
    const MAX_CHARS: usize = 120;
    let mut chars = raw.chars();
    let head: String = chars.by_ref().take(MAX_CHARS).collect();
    let truncated = chars.next().is_some();
    // 只转义控制字符（NUL、C0/C1、DEL 这类）——普通的可打印非 ASCII
    // 内容（中文之类）原样保留，不然日志会被转义成一堆 \u{...}，反而
    // 更难读。
    let escaped: String = head
        .chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().collect::<String>()
            } else {
                c.to_string()
            }
        })
        .collect();
    if truncated {
        format!("{escaped}…（已截断）")
    } else {
        escaped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_format_matches_openssh() {
        // ssh-keygen -lf 的输出形如 SHA256:<43 个 base64 字符，无填充>
        let fp = fingerprint_sha256(b"test key blob");
        assert!(fp.starts_with("SHA256:"), "{fp}");
        let body = &fp["SHA256:".len()..];
        assert_eq!(body.len(), 43, "{fp}");
        assert!(!body.contains('='), "{fp}");
    }

    #[test]
    fn fingerprint_of_matches_fingerprint_sha256_then_new() {
        // fingerprint_of 是 fingerprint_sha256() 之后再 Fingerprint::new()
        // 的替代品，两条路径必须产出完全相同的值——差异只在于 fingerprint_of
        // 不会在调用处放一个本该走不到、却仍然存在的 `expect`。
        let blob = b"another test key blob";
        let via_new = Fingerprint::new(&fingerprint_sha256(blob)).unwrap();
        assert_eq!(fingerprint_of(blob), via_new);
    }

    /// 上面那条测试的两边都是本模块自己的函数（`fingerprint_of` 与
    /// `fingerprint_sha256`），只要哪天两边同时改坏（比如都换成别的哈希
    /// 算法、都少截一段），断言照样相等，运维手册要求的"跟 `ssh-keygen
    /// -lf` 肉眼核对"这条现实世界的性质却已经悄悄碎了，没有任何测试会
    /// 变红。
    ///
    /// 这里的 blob 和期望指纹都不是本模块算出来的：blob 是
    /// `gateway/test-env` 里 `tunnel_host_ed25519_key.pub` 的公钥字段
    /// （原始 OpenSSH base64，标准填充），期望指纹是对着同一把 key 跑
    /// `ssh-keygen -lf` 读出来的，两者都是从 harness 里复制出来的固定值，
    /// 不经过本模块任何函数计算。
    #[test]
    fn fingerprint_of_matches_a_golden_vector_from_the_harness_host_key() {
        use base64::Engine;
        // gateway/test-env 里 tunnel_host_ed25519_key.pub 的公钥字段：
        //   ssh-ed25519 <这一串> root@buildkitsandbox
        const HARNESS_HOST_KEY_BASE64: &str =
            "AAAAC3NzaC1lZDI1NTE5AAAAIBEJjzpvcneu1b/9vNy6VGfPT4e4fI3VuHI4ZmmMxCvl";
        // `docker exec ... ssh-keygen -lf tunnel_host_ed25519_key.pub` 的输出。
        const EXPECTED: &str = "SHA256:6gVA/NoPLo9zNp8Ch4uQW0Ieu3Nk10kJxCxLdidvQTM";

        let blob = base64::engine::general_purpose::STANDARD
            .decode(HARNESS_HOST_KEY_BASE64)
            .expect("测试夹具里的 base64 常量本身必须合法");
        assert_eq!(fingerprint_of(&blob).as_str(), EXPECTED);
    }

    #[test]
    fn fingerprint_new_accepts_a_correctly_shaped_string() {
        assert!(Fingerprint::new(&fingerprint_sha256(b"a")).is_ok());
    }

    #[test]
    fn fingerprint_new_rejects_empty_string() {
        assert!(Fingerprint::new("").is_err());
    }

    #[test]
    fn fingerprint_new_rejects_a_string_that_is_not_a_fingerprint_at_all() {
        assert!(Fingerprint::new("not a fingerprint").is_err());
    }

    #[test]
    fn fingerprint_new_rejects_a_fingerprint_with_an_embedded_space() {
        assert!(Fingerprint::new("SHA256:with space").is_err());
    }

    #[test]
    fn fingerprint_new_rejects_the_short_placeholder_used_before_this_round() {
        // 这份报告自己前几轮的测试夹具用的就是这个占位符——它本身就是一个
        // 形状不合法的指纹，构造不出来。
        assert!(Fingerprint::new("SHA256:aaa").is_err());
    }

    /// 字符集校验里的 `+` 分支：种子 "seed-1" 的指纹里同时有 `+` 和 `/`，
    /// 专门堵住"手滑把 `|| b == b'+'` 从字符集里删掉"——现实里大约一半的
    /// 真实 host key 产出的指纹会带 `+`。
    #[test]
    fn fingerprint_containing_a_plus_character_round_trips() {
        let fp = fingerprint_sha256(b"seed-1");
        assert!(fp.contains('+'), "夹具没起作用，换个种子：{fp}");
        assert!(Fingerprint::new(&fp).is_ok());
    }

    /// `body.len() == 43` 这条长度校验：构造一个字符集完全合法、只是
    /// 长度差一位（43 变 44）的指纹段，堵住"把 `== 43` 松成 `>= 43`，
    /// 或者干脆删掉长度校验"这两种放宽。
    #[test]
    fn fingerprint_new_rejects_wrong_length() {
        let mut too_long = fingerprint_sha256(b"a");
        too_long.push('A'); // 43 位的合法 body 变成 44 位，字符集依旧合法
        assert!(Fingerprint::new(&too_long).is_err());
    }

    /// 报错时把「哪一行解析不出来」的原文塞进去之前必须先经过
    /// `redact_for_error`——这段原文没通过任何格式校验，可能是几十 KB
    /// 的垃圾（意外拼接进来的另一份日志），也可能是磁盘交叉写坏之后混
    /// 进来的另一个文件的内容。本项目的规矩是这类不受信任的内容不能
    /// 原样进用户可见的错误。
    #[test]
    fn damaged_line_error_message_is_bounded_in_length() {
        // 20 KB 的垃圾，没有任何空白。
        let junk = "x".repeat(20_000);
        let out = redact_for_error(&junk);
        assert!(out.len() < 1000, "没有被截断，长度是 {} 字节", out.len());
    }

    /// 控制字符（NUL 是磁盘故障/半截写入最典型的痕迹）不能原样出现在
    /// 错误文案里，必须被转义。
    #[test]
    fn damaged_line_containing_control_bytes_does_not_leak_them_raw() {
        let junk = "garbage\u{0}line\u{0}with\u{0}nulls";
        let out = redact_for_error(junk);
        assert!(
            !out.contains('\u{0}'),
            "NUL 字节被原样塞进了错误文案：{out:?}"
        );
        assert!(out.contains("garbage"), "至少要保留可读的一部分：{out}");
    }
}
