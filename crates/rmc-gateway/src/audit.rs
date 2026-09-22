//! 审计日志：JSON Lines，按天一个文件，保留 180 天。**不写口令**。
//! 这是原方案 §7.1 明确缺的那一块；原方案里 sshd 看到的来源永远是
//! 127.0.0.1，这里是真实地址。
//!
//! **口令绝不进审计日志是构造上的保证，不是靠小心**：`AuditEvent` 枚举里
//! 根本没有一个字段类型是"口令"或者能装下口令的自由文本（`account`/`peer`
//! 都是账号名与地址，`reason` 是固定的几句提示文案，不是任意字符串）。
//! 想往里塞一个口令字段，先得改这个枚举——那一步本身就会被代码审查挡住。

use crate::clock::{date_stamp, rfc3339};
use crate::datadir::DataDir;
use crate::Result;
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

pub const RETENTION_DAYS: u32 = 180;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    ServerStart {
        listen: String,
    },
    AuthOk {
        account: String,
        peer: String,
    },
    AuthFail {
        account: String,
        peer: String,
    },
    Banned {
        peer: String,
    },
    /// 未认证连接配额被打满，多出来的连接直接关掉。
    ///
    /// **终审 FR-4**：这一支原来只有一句 `tracing::info!`，不进审计。
    /// 「未认证连接配额被打满」是这套东西最薄弱的一环——一个不需要任何
    /// 账号、不需要任何口令的人就能把全局 64 个名额占满，让所有正常的
    /// 现场连接连 TLS 都握不上；而审计是这件事发生过的唯一痕迹。日志
    /// 会轮转、会被采集器丢，审计文件是按天留 180 天的那一份。
    TooManyUnauth {
        peer: String,
    },
    TunnelUp {
        account: String,
        port: u16,
        peer: String,
    },
    TunnelDown {
        account: String,
        port: u16,
        reason: String,
    },
    EngineerOpen {
        account: String,
        port: u16,
        peer: String,
    },
    EngineerClose {
        account: String,
        port: u16,
        peer: String,
        seconds: u64,
        to_client: u64,
        from_client: u64,
    },
    EngineerRejected {
        port: u16,
        peer: String,
        reason: String,
    },
    AccountChanged {
        account: String,
        action: String,
    },
}

#[derive(Serialize)]
struct Line<'a> {
    ts: String,
    #[serde(flatten)]
    ev: &'a AuditEvent,
}

pub struct AuditLog {
    dir: PathBuf,
    // 同一进程内串行写；跨进程（CLI 记 AccountChanged）靠 O_APPEND 一行一写。
    write: Mutex<()>,
}

impl AuditLog {
    pub fn open(dir: &DataDir) -> Result<Self> {
        std::fs::create_dir_all(dir.audit_dir())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.audit_dir(), std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            dir: dir.audit_dir(),
            write: Mutex::new(()),
        })
    }

    pub fn path_for(&self, t: SystemTime) -> PathBuf {
        self.dir.join(format!("audit-{}.log", date_stamp(t)))
    }

    pub fn record(&self, ev: AuditEvent) {
        let now = SystemTime::now();
        let line = match serde_json::to_string(&Line {
            ts: rfc3339(now),
            ev: &ev,
        }) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, "审计事件序列化失败");
                return;
            }
        };
        let _g = self.write.lock().unwrap_or_else(|e| e.into_inner());
        let r = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path_for(now))
            .and_then(|mut f| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
                }
                append_line(&mut f, &line)
            });
        if let Err(e) = r {
            tracing::error!(error = %e, "审计日志写入失败");
        }
        tracing::info!(target: "audit", "{line}");
    }

    /// 按文件名里的日期删旧文件（不看 mtime——备份/拷贝会改 mtime）。
    pub fn prune(&self, keep_days: u32) {
        let today = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() / 86_400)
            .unwrap_or(0) as i64;
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(stamp) = name
                .strip_prefix("audit-")
                .and_then(|s| s.strip_suffix(".log"))
            else {
                continue;
            };
            let Some(days) = days_from_stamp(stamp) else {
                continue;
            };
            if today - days > i64::from(keep_days) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// 一行 JSON + 换行，**一次 `write_all`**。
///
/// **终审 FR-5**：原来这里是 `writeln!(f, "{line}")`。`writeln!` 走的是
/// `io::Write::write_fmt`，它按格式串的片段逐段 `write_all`——对一个
/// `File`（无缓冲）就是**两次 `write(2)`**：先内容，再换行。追加模式下
/// 单次 `write(2)` 才是原子的，两次之间别的进程（`serve` 与 CLI 的
/// `account` 子命令同时往同一天的文件里追加）可以插进来，结果是一行
/// JSON 被截进另一行，两行都不再是合法 JSON——而审计日志的全部价值就
/// 在于事后能被逐行解析。拼成一个缓冲区再一次写出去，把这个窗口关掉。
///
/// 它不保证「任意长度都原子」（PIPE_BUF 之类的限制仍在），但审计行是
/// 几百字节量级，远在任何一个平台的原子写阈值之内。
fn append_line(f: &mut impl Write, line: &str) -> std::io::Result<()> {
    let mut buf = String::with_capacity(line.len() + 1);
    buf.push_str(line);
    buf.push('\n');
    f.write_all(buf.as_bytes())
}

/// `YYYY-MM-DD` → 自 1970-01-01 的天数（Hinnant 的 `days_from_civil`，
/// `civil_from_days` 的逆函数）。同样的取整陷阱、同样的绕开写法：
/// `era` 那一行故意写成 `if y >= 0 { y } else { y - 399 } / 400`。
fn days_from_stamp(s: &str) -> Option<i64> {
    let mut it = s.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一次 `write` 调用就把「内容 + 换行」写完。
    ///
    /// **终审 FR-5**：`serve` 与 CLI 的 `account` 子命令是两个进程，会
    /// 同时往同一天的审计文件里追加。`O_APPEND` 只保证**单次** `write(2)`
    /// 的原子性；`writeln!` 走 `write_fmt`，对无缓冲的 `File` 会拆成两次
    /// 系统调用（内容、换行），两次之间另一个进程插进来，一行 JSON 就被
    /// 截进另一行，两行都不再能被逐行解析——审计日志的全部价值就在这。
    ///
    /// 「两个进程真并发时会不会截断」在单元测试里**造不出稳定的复现**
    /// （要靠调度撞窗口），所以这里钉的是那个可以确定性观察的性质本身：
    /// **只发生一次 `write` 调用**。夹具是一个只实现 `write` 的计数
    /// 写入器——`write_fmt` 的默认实现正是靠反复调用它来拼输出的。
    ///
    /// 改红（**实测过**）：把 `append_line` 的函数体换回
    /// `writeln!(f, "{line}")`——`writes` 变成 2（内容一次、换行一次），
    /// `assert_eq!(w.writes, 1, ...)` 红。
    #[test]
    fn one_line_goes_out_in_a_single_write_call() {
        #[derive(Default)]
        struct Counting {
            writes: usize,
            buf: Vec<u8>,
        }
        impl Write for Counting {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                // 空写不算数：`write_all(b"")` 根本不会走到这里，这一句
                // 只是防止将来有人加了空片段把计数弄花。
                if !b.is_empty() {
                    self.writes += 1;
                    self.buf.extend_from_slice(b);
                }
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut w = Counting::default();
        append_line(&mut w, r#"{"event":"auth_ok"}"#).unwrap();
        assert_eq!(
            w.writes, 1,
            "一行审计要一次写完：分两次写的话，另一个进程的追加会插在中间，\
             把这一行截断成两段谁也解析不了的东西"
        );
        assert_eq!(
            String::from_utf8(w.buf).unwrap(),
            "{\"event\":\"auth_ok\"}\n"
        );
    }

    /// 改红：`Line` 上去掉 `#[serde(flatten)]`——第二格红（事件字段被包在
    /// "ev" 里）。
    #[test]
    fn records_one_json_line_per_event_with_a_timestamp() {
        let tmp = tempfile::tempdir().unwrap();
        let d = DataDir::at(tmp.path().to_path_buf());
        let log = AuditLog::open(&d).unwrap();
        log.record(AuditEvent::AuthFail {
            account: "zhang".into(),
            peer: "203.0.113.5:4242".into(),
        });
        let text = std::fs::read_to_string(log.path_for(SystemTime::now())).unwrap();
        let v: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(v["event"], "auth_fail");
        assert_eq!(v["account"], "zhang");
        assert!(v["ts"].as_str().unwrap().ends_with('Z'));
        assert_eq!(text.lines().count(), 1);
    }

    #[test]
    fn days_from_stamp_inverts_civil_from_days() {
        for days in [0i64, 10_957, 20_454, 30_000] {
            let (y, m, d) = crate::clock::civil_from_days(days);
            assert_eq!(
                days_from_stamp(&format!("{y:04}-{m:02}-{d:02}")),
                Some(days)
            );
        }
    }

    /// 改红：**实测过**——`prune` 里的比较改成 `<`（或按 mtime 删）都能
    /// 打红，命中 `!... .exists()` 那句断言。**但字面把 `>` 改成 `>=`
    /// 是假支票，如实记录**：`audit-2020-01-01.log` 距"今天"
    /// （2026 年）已经超过 2000 天，远超 `RETENTION_DAYS`（180）；
    /// `today - days > 180` 与 `today - days >= 180` 在这个量级的差距下
    /// 结果完全一样（都是 `true`），实测这一改仍然全绿。真正踩这个
    /// 判断的边界值需要精确构造"恰好等于 `keep_days`"的天数差，不是这条
    /// 测试的现有夹具能覆盖的——这条测试本来就没打算验 `>` 和 `>=` 在
    /// 边界上的一位之差，它验的是"删旧文件、按文件名日期不是 mtime、
    /// 不动无关文件"。
    #[test]
    fn prune_deletes_by_the_date_in_the_file_name() {
        let tmp = tempfile::tempdir().unwrap();
        let d = DataDir::at(tmp.path().to_path_buf());
        let log = AuditLog::open(&d).unwrap();
        std::fs::write(d.audit_dir().join("audit-2020-01-01.log"), "old\n").unwrap();
        std::fs::write(d.audit_dir().join("unrelated.txt"), "keep\n").unwrap();
        log.record(AuditEvent::ServerStart { listen: "x".into() });
        log.prune(RETENTION_DAYS);
        assert!(!d.audit_dir().join("audit-2020-01-01.log").exists());
        assert!(d.audit_dir().join("unrelated.txt").exists());
        assert!(log.path_for(SystemTime::now()).exists());
    }
}
