//! 客户端配置。内置默认值，现场可改的部分落在应用目录。

use crate::addr::HostPort;
use crate::error::{Error, Result};
use std::ops::RangeInclusive;
use std::path::PathBuf;

/// 允许申请的反向端口范围，编译进二进制。
pub const ALLOWED_REVERSE_PORTS: RangeInclusive<u16> = 22000..=22999;

#[derive(Debug, Clone)]
pub struct Config {
    pub gateway: HostPort,
    pub appliance: HostPort,
    /// 本账号的反向端口，随账号由运维下发，存在应用目录。
    pub reverse_port: u16,
    pub known_hosts_path: PathBuf,
    pub log_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // 现场必须修改；这里给的只是首次呈现给用户的占位值，取自方案
            // 设计.md §3.10 界面示意图里原样出现的域名与端口
            // （`地址 [ gateway.company.com ] : [ 443 ]`）。
            gateway: HostPort::new("gateway.company.com", 443).expect("内置默认值必须自解析通过"),
            // R13 / 方案设计.md §3.8：一体机 SSH 默认端口是 61001，不是
            // 22——gateway/test-env/appliance/Dockerfile 明确警告过不要把
            // 这个端口简化回 22，因为 22 恰恰是掩盖这整类错误的值。主机部分
            // 同样只是占位符，现场必须按实际网络修改。
            appliance: HostPort::new("192.168.1.1", 61001).expect("内置默认值必须自解析通过"),
            // 真实值随账号由运维下发；这里先给范围内的最小值占位，保证
            // 一份刚生成、还没被现场信息覆盖的默认配置本身也能通过
            // validate（见 default_config_passes_its_own_validation）。
            reverse_port: *ALLOWED_REVERSE_PORTS.start(),
            known_hosts_path: PathBuf::from("known_hosts"),
            log_dir: PathBuf::from("logs"),
        }
    }
}

/// 校验 gateway 与一体机地址的关系：一体机不能和 Gateway 是同一个地址，
/// 也不能指向本机回环。这两条规则存在的理由是防止 Gateway 的隧道被接回
/// 客户端自己身上（方案设计.md §3.1 的网络拓扑图假设一体机在客户内网、
/// Gateway 在公网，这两个地址永远不该重合）。
///
/// 不对外公开：唯一对外的入口是下面的 `ValidatedAddresses::validate`,让
/// 校验通过这件事在类型上留下证据，而不是校验完之后又能被随手绕开。
fn validate_addresses(gateway: &HostPort, appliance: &HostPort) -> Result<()> {
    if appliance == gateway {
        return Err(Error::Config("一体机地址不能与 Gateway 地址相同".into()));
    }
    if appliance.is_loopback() {
        return Err(Error::Config(format!(
            "一体机地址不能指向本机：{appliance}"
        )));
    }
    Ok(())
}

/// 校验通过的 gateway/appliance 地址对。
///
/// # R10：这是解决"Config::validate 是死代码"的落点
///
/// `Config::validate` 拒绝 loopback 一体机与"一体机等于 Gateway"，但
/// Supervisor（Task 10）处理 `Command::Start` 时用的地址来自 UI 直接输入，
/// 并不天然打包成一份 `Config`（`Config` 还带着 `reverse_port`、
/// `known_hosts_path` 等和这两条地址规则无关的字段），于是这两条规则从来
/// 没人调用过。
///
/// 这个类型把"校验通过"做成了拿到值本身的前提，而不是一个可以被跳过的
/// 步骤：字段是私有的，本模块之外没有办法用结构体字面量绕过 `validate`
/// 直接拼出一个 `ValidatedAddresses`——包括 Task 10 自己的 `supervisor.rs`,
/// 哪怕两者同在 rmc-core 这一个 crate 里。
///
/// **Task 10 必须调用什么**：处理 `Command::Start` 时，先用它携带的
/// gateway/appliance 调 `ValidatedAddresses::validate(gateway, appliance)`,
/// 再用返回值里的地址去拨号；不要把 `Command::Start` 里的裸 `HostPort`
/// 直接传给隧道，那正是这个类型存在之前"校验从未被调用"的原样重现。
/// 需要指向 127.0.0.1 假一体机的测试（例如
/// `degraded_probe_recovers_when_the_appliance_comes_back`）改用
/// `ValidatedAddresses::for_test` 构造，不经过这道校验。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAddresses {
    gateway: HostPort,
    appliance: HostPort,
}

impl ValidatedAddresses {
    /// 生产路径的唯一入口：校验通过才能拿到值。
    pub fn validate(gateway: HostPort, appliance: HostPort) -> Result<Self> {
        validate_addresses(&gateway, &appliance)?;
        Ok(Self { gateway, appliance })
    }

    pub fn gateway(&self) -> &HostPort {
        &self.gateway
    }

    pub fn appliance(&self) -> &HostPort {
        &self.appliance
    }

    /// 仅供本 crate 内部测试构造，跳过地址关系校验。`#[cfg(test)]` 意味着
    /// 这个函数在生产构建里根本不是"不建议调用"的君子协定，而是不存在的
    /// 符号——不依赖任何人自觉遵守命名约定，也不会被外部 crate 意外用到。
    #[cfg(test)]
    pub(crate) fn for_test(gateway: HostPort, appliance: HostPort) -> Self {
        Self { gateway, appliance }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if !ALLOWED_REVERSE_PORTS.contains(&self.reverse_port) {
            return Err(Error::Config(format!(
                "反向端口 {} 超出允许范围 {}-{}",
                self.reverse_port,
                ALLOWED_REVERSE_PORTS.start(),
                ALLOWED_REVERSE_PORTS.end()
            )));
        }
        validate_addresses(&self.gateway, &self.appliance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cfg(reverse_port: u16) -> Config {
        Config {
            gateway: "gateway.company.com:443".parse().unwrap(),
            appliance: "192.168.100.10:22".parse().unwrap(),
            reverse_port,
            known_hosts_path: PathBuf::from("/tmp/rmc/known_hosts"),
            log_dir: PathBuf::from("/tmp/rmc/logs"),
        }
    }

    #[test]
    fn accepts_port_inside_allowed_range() {
        assert!(cfg(22001).validate().is_ok());
        assert!(cfg(22000).validate().is_ok());
        assert!(cfg(22999).validate().is_ok());
    }

    #[test]
    fn rejects_port_below_range() {
        let err = cfg(21999).validate().unwrap_err();
        assert!(err.to_string().contains("22000"), "{err}");
    }

    #[test]
    fn rejects_port_above_range() {
        assert!(cfg(23000).validate().is_err());
    }

    #[test]
    fn rejects_appliance_equal_to_gateway() {
        let mut c = cfg(22001);
        c.appliance = c.gateway.clone();
        let err = c.validate().unwrap_err();
        assert!(err.to_string().contains("一体机"), "{err}");
    }

    #[test]
    fn rejects_loopback_appliance() {
        // 转发目标指向本机毫无意义，且会把 Gateway 的通道接到客户端自己身上。
        let mut c = cfg(22001);
        c.appliance = "127.0.0.1:22".parse().unwrap();
        assert!(c.validate().is_err());
    }

    // --- R13：一体机 SSH 默认端口是 61001。---

    #[test]
    fn default_config_uses_appliance_ssh_port_61001_not_22() {
        // 方案设计.md §3.8 明确要求内置默认端口 61001；brief 给的所有夹具
        // 都写 22，而 gateway/test-env/appliance/Dockerfile 专门警告过不要
        // 把这个端口简化回 22——22 恰恰是掩盖这整类错误的值。
        assert_eq!(Config::default().appliance.port, 61001);
    }

    #[test]
    fn default_config_passes_its_own_validation() {
        // 内置默认值本身也不能是一份会被 validate 拒绝的配置（哪怕地址部分
        // 只是占位符，现场必须改）——防止以后有人把默认值悄悄改成 loopback
        // 或者让 appliance 和 gateway 撞在一起也没人发现。
        assert!(Config::default().validate().is_ok());
    }

    // --- R10：Config::validate 拒绝的两条地址关系规则，在 Command::Start
    // 真正会用到的地方（Task 10 的 Supervisor）必须原样生效。这里钉住的是
    // 那个校验的种子——ValidatedAddresses——本身的行为，Supervisor 是否真的
    // 调用它由 Task 10 的测试负责。---

    #[test]
    fn validated_addresses_rejects_appliance_equal_to_gateway() {
        let gateway: HostPort = "gateway.company.com:443".parse().unwrap();
        let err = ValidatedAddresses::validate(gateway.clone(), gateway).unwrap_err();
        assert!(err.to_string().contains("一体机"), "{err}");
    }

    #[test]
    fn validated_addresses_rejects_loopback_appliance() {
        let gateway: HostPort = "gateway.company.com:443".parse().unwrap();
        let appliance: HostPort = "127.0.0.1:22".parse().unwrap();
        assert!(ValidatedAddresses::validate(gateway, appliance).is_err());
    }

    #[test]
    fn validated_addresses_accepts_distinct_non_loopback_pair() {
        let gateway: HostPort = "gateway.company.com:443".parse().unwrap();
        let appliance: HostPort = "192.168.100.10:22".parse().unwrap();
        let va = ValidatedAddresses::validate(gateway.clone(), appliance.clone()).unwrap();
        assert_eq!(va.gateway(), &gateway);
        assert_eq!(va.appliance(), &appliance);
    }

    #[test]
    fn validated_addresses_for_test_bypasses_validation_for_loopback_fixtures() {
        // 印证 Task 10 的用法：需要在本机假一体机上跑的测试（例如
        // degraded_probe_recovers_when_the_appliance_comes_back，appliance
        // 是 127.0.0.1:{port}）不经过 validate_addresses 那一关，改用
        // for_test 直接构造。这条测试不是在证明"校验被跳过是安全的"，只是
        // 确认这条测试专用的口子本身能用——它在非测试构建里根本不存在
        // （见 ValidatedAddresses::for_test 上的 #[cfg(test)]）。
        let gateway: HostPort = "gateway.company.com:443".parse().unwrap();
        let appliance: HostPort = "127.0.0.1:2222".parse().unwrap();
        let va = ValidatedAddresses::for_test(gateway, appliance.clone());
        assert_eq!(va.appliance(), &appliance);
    }
}
