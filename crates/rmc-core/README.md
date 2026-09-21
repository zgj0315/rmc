# rmc-core

远程维护客户端的内核。平台无关，在 Linux 上完整可测。设计依据见
`../../docs/方案设计.md` 第 3 章。

## 对外接口

```rust
let (cmd_tx, mut ev_rx) = Supervisor::spawn(config, deps);
cmd_tx.send(Command::Start { username, password, gateway, appliance }).await?;
while let Ok(event) = ev_rx.recv().await {
    // TunnelEvent::State / Preflight / RemoteSessions / HostKey / ConnectedSince
}
```

界面只发 `Command`（`Start`/`Cancel`/`Stop`/`RetryNow`/
`DisconnectRemoteSession`）、只读 `TunnelEvent`，不直接调用内部模块
（`ssh`/`transport`/`preflight`/`audit` 等 `pub mod` 是给本 crate 内部
分层用的，不是设计上打算让 rmc-win 越过 `Supervisor` 直接触碰的接口）。

### Gateway 地址是每次 `Start` 带进来的

方案 §3.8/§3.10 要求 Gateway 地址与端口可以现场修改。`Command::Start`
携带的 `gateway` 就是这条隧道**实际拨号**的那一台，也是 host key 比对、
预检探测、审计日志记录的那一台——四者读的是同一个值，不存在"界面显示
一台、实际连另一台"的可能。改地址只需要再发一条 `Start`，**不需要**
重建 `Supervisor` 或重新注入 `Deps`。

`Config::gateway` 只是界面的初始值/上次使用值，不参与拨号；
`Deps::factory` 里的 `SshTunnelFactory` 也不持有任何 Gateway 地址（它
只有 `Transport` 与 `known_hosts`）。细节与这条约束是怎么被钉住的，见
`tunnel::TunnelParams` 与 `ssh::SshTunnelFactory` 上的 R96 说明，以及
`supervisor` 里的
`start_passes_the_commanded_gateway_all_the_way_to_the_factory`。

### 还没有生产装配点

把一份 `Config` 变成 `Transport` + `KnownHosts` + `SshTunnelFactory` +
`TransportPreflight` + `Deps` 这件事，本 crate 里目前**没有任何地方
做过**：`Deps { .. }` 的唯一构造点在 `#[cfg(test)]` 里，
`SshTunnelFactory::new` 的唯一调用点在 `tests/common/mod.rs`，
`TransportPreflight::new` 全树零调用，`Config::known_hosts_path` 零
读取。rmc-app 接上来的时候应当加一个 `Deps::production(cfg,
platform...)` 把这条路径收进 core 自己（反向端口范围校验也归它），
而不是让每个调用方各拼一遍。

## 平台能力注入

`platform.rs` 中的三个 trait 由 rmc-win 实现：`ProxyResolver`、
`ProxyAuthenticator`、`SystemEvents`。口令存储不在 core 内，界面填好口令后
经 `Command::Start` 下发。Linux 测试用同文件里的 `NoProxy`、`NoProxyAuth`、
`NoSystemEvents`。

## 测试

```bash
cargo test -p rmc-core                    # 单元与假隧道测试，不碰外部网络
cargo test -p rmc-gateway                 # 含 tests/e2e.rs：真客户端内核 ↔ 真运维服务器
```

**没有 `#[ignore]` 的那一档了，也不需要 docker。** 这一节原来写的是
「起 `gateway/test-env` 的 docker compose、跑 `fetch-harness-cert.sh`、
再 `cargo test -p rmc-core -- --ignored --test-threads=1` 那 17 条」。
那 17 条在 Task 10 随着「客户端 TLS 改成核对连接码指纹」一起删掉了
（它们描述的是旧的公共 CA / known_hosts 世界），`fetch-harness-cert.sh`
也不在了；Task 12 又把 CI 里那个 `integration` job 整个拿掉。

顶替它们的是 `crates/rmc-gateway/tests/e2e.rs`：同一条链路（Transport →
TLS 指纹钉扣 → russh → 反向端口 → pump → Supervisor）对着一台**进程内
起起来的真运维服务器**跑，不需要 docker、不需要 `/etc/hosts` 里那行
`gateway.test`、也不需要任何人记得传 `--ignored`。它跑在每一次
`cargo test` 里，CI 的 `core.yml`（Linux）与 `app.yml`（Windows）都会执行。

## 口令处理

口令只以 `Zeroizing<String>` 存在于内存，`TunnelParams` 与 `Command` 的
`Debug` 实现都把它替换为 `<redacted>`，`tests/ssh_tunnel.rs` 与
`supervisor.rs` 的 `#[cfg(test)]` 里都有用例断言口令不会出现在审计日志
或 `Debug` 输出中。
