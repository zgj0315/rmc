#![forbid(unsafe_code)]
//! 运维服务器：一个二进制，只做口令认证与一条反向转发。设计见
//! `docs/superpowers/specs/2026-09-21-rmc-gateway-design.md`。

// **修复轮 2/5，复审建议，已验证为真**：`TunnelGuard::drop` 那个
// 「`if let`/`match` scrutinee 里的 `MutexGuard` 活到 body 结束、锁跨了
// 一次磁盘写」的 bug，正好是 `clippy::significant_drop_in_scrutinee`
// 这条 lint 的教科书场景——用最小复现验过：危险写法
// `if let Some(v) = m.lock().unwrap().remove(&1) { ... }` 会被精确报出
// `temporary with significant Drop in if let scrutinee will live until
// the end of the if let expression`；安全写法（先 `let removed = ...;`
// 再 `if let`）不报，零误报。
//
// **单独开这一条，不开整个 `clippy::nursery` 组**——nursery 组噪音太大，
// 这条之外的其它 nursery lint 跟本项目关心的问题类别不匹配。
//
// **修复轮 3/5，订正上一版这里的一句假话，如实记录**：上一版写的是
// 「加了 `warn` 之后 `-D warnings` 依旧只把它当 warning，不会让构建
// 失败」——**这是错的，而且是当场实测出来的，不是推理**：一开这条
// lint，`cargo clippy --workspace --all-targets -- -D warnings` 立刻
// 报错（命中的是这条测试文件里故意示范危险写法的对照组，见下面
// `server.rs` 那处 `#[allow]`）。原因是 `-D warnings` 会把「当前生效的
// warnings 组」整体降级成 deny，**这不区分默认开着的 lint 和通过
// `#![warn(...)]` 主动开的 lint**——只要它在 warn 级别生效，`-D
// warnings` 就会把它一起升级。
//
// 它默认不在 `clippy::all`/`clippy::pedantic` 里，也不在这个项目原有的
// 任何闸门命令里——开这一行之前它从来没有被真的跑过（这半句是对的）。
// **但开完这一行之后，它跟其它任何 `-D warnings` 覆盖的 lint 一样，
// 报出新东西就会让闸门当场失败**，不是「留给人事后看一眼」。
//
// 那么选 `warn` 而不是 `deny` 到底图什么：**不是为了让它卡不住构建**
// （它一样卡得住），而是**这条规则的强度由闸门命令决定，不由源码写死**
// ——`-D warnings` 在场就是 deny 级的效果；将来这条 lint 升级版本后如果
// 变得吵（误报变多），拿掉这一行、或者在闸门命令里单独 `-A
// clippy::significant_drop_in_scrutinee` 都是一步操作，且那一刻的表现
// 是**一次可见、容易定位的构建失败**，不是「代码里挂着一个不生效的
// `deny` 属性、没人注意到它其实一直被绕过」那种静默失效。
#![warn(clippy::significant_drop_in_scrutinee)]

pub mod accounts;
pub mod audit;
pub mod cidr;
pub mod cli;
pub mod clock;
pub mod config;
pub mod datadir;
pub mod identity;
pub mod server;
pub mod status;
pub mod throttle;

#[cfg(test)]
mod testing_verifier;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO 错误：{0}")]
    Io(#[from] std::io::Error),
    #[error("配置错误：{0}")]
    Config(String),
    #[error("身份密钥：{0}")]
    Identity(String),
    #[error("账号库：{0}")]
    Accounts(String),
    #[error("TLS：{0}")]
    Tls(String),
    #[error("监听失败：{0}")]
    Listen(String),
}

pub type Result<T> = std::result::Result<T, Error>;
