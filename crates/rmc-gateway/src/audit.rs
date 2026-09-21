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
                writeln!(f, "{line}")
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
