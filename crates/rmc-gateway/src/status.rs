//! status.json：serve 在隧道起落与每次扫描时原子写出，`status` 子命令只读它。没有 IPC。

use crate::clock::rfc3339;
use crate::datadir::{write_private_atomic, DataDir};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// 服务端至少每个扫描周期（5s，见 `server::Timings::default`）写一次；超过
/// 这个时长没更新，就当它没在跑。30 秒 = 6 个扫描周期，留足够的余量给
/// 一次偶发的慢写，同时仍然远小于「人去看一眼」的时间尺度。
pub const STALE_AFTER_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub account: String,
    pub port: u16,
    pub peer: String,
    pub since: String,
    pub engineers: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub pid: u32,
    pub updated_unix: u64,
    pub listen: String,
    pub fingerprint: String,
    pub tunnels: Vec<TunnelStatus>,
}

pub fn write(dir: &DataDir, st: &Status) -> Result<()> {
    let text = serde_json::to_string_pretty(st).map_err(|e| Error::Config(e.to_string()))?;
    write_private_atomic(&dir.status(), text.as_bytes())?;
    Ok(())
}

pub fn read(dir: &DataDir) -> Result<Option<Status>> {
    match std::fs::read_to_string(dir.status()) {
        Ok(t) => serde_json::from_str(&t)
            .map(Some)
            .map_err(|e| Error::Config(format!("status.json 解析失败：{e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn is_live(st: &Status, now_unix: u64) -> bool {
    now_unix.saturating_sub(st.updated_unix) <= STALE_AFTER_SECS
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn since_text(t: std::time::SystemTime) -> String {
    rfc3339(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_staleness() {
        let tmp = tempfile::tempdir().unwrap();
        let d = DataDir::at(tmp.path().to_path_buf());
        assert_eq!(read(&d).unwrap(), None);
        let st = Status {
            pid: 1,
            updated_unix: 1000,
            listen: "0.0.0.0:22000".into(),
            fingerprint: "x".into(),
            tunnels: vec![],
        };
        write(&d, &st).unwrap();
        assert_eq!(read(&d).unwrap(), Some(st.clone()));
        assert!(is_live(&st, 1030));
        assert!(!is_live(&st, 1031), "改红：把 STALE_AFTER_SECS 改成 31");
    }
}
