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
// **用 `warn` 不用 `deny`，也不进 `-D warnings` 闸门**——它是 nursery
// lint，还没稳定，未来 clippy 版本升级可能改变它的判定逻辑或误报率；
// 不该让一条仍在打磨中的 lint 有能力卡住跟它无关的构建。它默认不在
// `clippy::all`/`clippy::pedantic` 里，也不在这个项目的任何闸门命令里
// ——开这一行之后它才会真的被跑过，`cargo clippy --workspace
// --all-targets -- -D warnings` 依旧只把它当 warning，不会因为它报了
// 什么就让构建失败；真报出新东西时需要人去看一眼，不是自动拒绝。
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
