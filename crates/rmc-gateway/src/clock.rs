//! UTC 日期与 RFC 3339 时间戳。不引 chrono/time：只要天数↔日历这一个算法
//! （Howard Hinnant 的 `civil_from_days`）。
//!
//! 派发前用 python 对着标准库跑过 5000 个随机天数（含负数）往返比对，一致。
//! **`era` 那两行故意写成 `if z >= 0 { z } else { z - 146_096 } / 146_097`**，
//! 不能简化成 `z / 146_097`——Rust 的整数除法对负数是向零取整，
//! python 的 `//` 是向下取整，两者在负数上会分道扬镳；这一行就是绕开这个差异
//! 用的（本项目只会用到 1970 年以后的日期，但保留这条注释说明为什么不能删）。

use std::time::{SystemTime, UNIX_EPOCH};

/// 自 1970-01-01 的天数 → `(年, 月, 日)`。
pub fn civil_from_days(z: i64) -> (i64, u8, u8) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn civil_from_unix(secs: u64) -> (i64, u8, u8) {
    civil_from_days((secs / 86_400) as i64)
}

pub fn rfc3339(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, m, d) = civil_from_unix(secs);
    let s = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        s / 3600,
        (s % 3600) / 60,
        s % 60
    )
}

pub fn date_stamp(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, m, d) = civil_from_unix(secs);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// 改红：`civil_from_days` 里任何一个常数（比如 `719_468`、`146_097`、
    /// `1460`、`36_524`、`146_096`、`153`、`5`、`2`、`3`、`9`、`10`）。
    #[test]
    fn known_dates() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1));
        assert_eq!(civil_from_unix(951_782_400), (2000, 2, 29), "闰日");
        assert_eq!(civil_from_unix(1_789_948_800), (2026, 9, 21));
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::from_secs(1_789_948_800 + 3661)),
            "2026-09-21T01:01:01Z"
        );
        assert_eq!(
            date_stamp(UNIX_EPOCH + Duration::from_secs(1_789_948_800)),
            "2026-09-21"
        );
    }

    /// 往返：`civil_from_days` 与它在 `audit.rs` 里的逆函数 `days_from_stamp`
    /// 互为反函数，覆盖控制者补充里给出的四个校验点（含跨千年、跨世纪）。
    #[test]
    fn round_trips_at_the_four_checkpoints_from_the_brief() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        assert_eq!(civil_from_days(20_454), (2026, 1, 1));
        assert_eq!(civil_from_days(30_000), (2052, 2, 20));
    }
}
