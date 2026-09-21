//! config.toml：对外地址（只用于打印连接码）与反向端口区间。

use crate::datadir::{write_private_atomic, DataDir};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::ops::RangeInclusive;

pub const DEFAULT_LISTEN_PORT: u16 = 22000;
pub const DEFAULT_REVERSE_PORTS: RangeInclusive<u16> = 22001..=22999;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// 写进连接码、客户端实际拨的地址。**不是**监听地址。
    pub public_addr: SocketAddr,
    pub reverse_port_min: u16,
    pub reverse_port_max: u16,
}

impl GatewayConfig {
    pub fn new(public_addr: SocketAddr) -> Self {
        Self {
            public_addr,
            reverse_port_min: *DEFAULT_REVERSE_PORTS.start(),
            reverse_port_max: *DEFAULT_REVERSE_PORTS.end(),
        }
    }

    pub fn reverse_ports(&self) -> RangeInclusive<u16> {
        self.reverse_port_min..=self.reverse_port_max
    }

    pub fn validate(&self) -> Result<()> {
        if self.reverse_port_min == 0 || self.reverse_port_min > self.reverse_port_max {
            return Err(Error::Config(format!(
                "反向端口区间不合法：{}-{}",
                self.reverse_port_min, self.reverse_port_max
            )));
        }
        if self.public_addr.port() == 0 {
            return Err(Error::Config("public_addr 的端口不能是 0".into()));
        }
        Ok(())
    }

    pub fn save(&self, dir: &DataDir) -> Result<()> {
        self.validate()?;
        let text = toml::to_string(self).map_err(|e| Error::Config(e.to_string()))?;
        let text = format!("# 由 rmc-gateway init 生成。public_addr 是写进连接码的对外地址，改了之后用 account list 重新取连接码。\n{text}");
        write_private_atomic(&dir.config(), text.as_bytes())?;
        Ok(())
    }

    pub fn load(dir: &DataDir) -> Result<Self> {
        let text = std::fs::read_to_string(dir.config()).map_err(|e| {
            Error::Config(format!(
                "读不到 {}：{e}；先运行 init",
                dir.config().display()
            ))
        })?;
        let cfg: Self = toml::from_str(&text)
            .map_err(|e| Error::Config(format!("config.toml 解析失败：{e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_then_load_round_trips_and_validates() {
        let tmp = tempfile::tempdir().unwrap();
        let d = DataDir::at(tmp.path().to_path_buf());
        let c = GatewayConfig::new("203.0.113.10:22000".parse().unwrap());
        c.save(&d).unwrap();
        assert_eq!(GatewayConfig::load(&d).unwrap(), c);
        let mut bad = c.clone();
        bad.reverse_port_min = 30000;
        assert!(bad.save(&d).is_err());
    }
}
