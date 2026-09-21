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

### 运维服务器的地址是每次 `Start` 带进来的

方案 §3.8 今天要求可现场修改的是**一体机**地址；运维服务器那一台的
地址、端口、账号与指纹全部来自现场人员粘贴的**连接码**，不是四个可编辑
的字段。`Command::Start` 携带的就是这条隧道**实际拨号**的那一台，也是
指纹比对、预检探测、审计日志记录的那一台——四者读的是同一个值，不存在
"界面显示一台、实际连另一台"的可能。换一台只需要粘一条新连接码再发一条
`Start`，**不需要**重建 `Supervisor` 或重新注入 `Deps`。

`Deps::factory` 里的 `SshTunnelFactory` 不持有任何服务器地址，也不持有
任何本地状态——**它只有一个 `transport` 字段**（`KnownHosts` 随 Task 10
一起删除，host key 校验换成核对 `params.fingerprint`）。细节与这条约束
是怎么被钉住的，见 `tunnel::TunnelParams` 与 `ssh::SshTunnelFactory`
上的 R96 说明，以及 `supervisor` 里的
`start_passes_the_commanded_gateway_all_the_way_to_the_factory`。

`Config` 里那个同名字段今天是**死字段**：没有任何生产读取方
（`AppPaths::config()` 只取 `log_dir`）。删掉它会牵到 `Config::validate`
与 `ValidatedAddresses` 一串，记在 `docs/交付前还剩什么.md` 的 B 档。

### 生产装配点在 rmc-app

（这一节原来叫「还没有生产装配点」，说的是 Task 4 那会儿的事：当时
`Deps { .. }` 的唯一构造点在 `#[cfg(test)]` 里，`SshTunnelFactory::new`
只在 `tests/common/mod.rs` 被调，`TransportPreflight::new` 全树零调用。
**那已经是过去时**——「全树零调用」是一句可以被 `grep` 当场证否的现行
断言，所以改掉而不是留着。）

今天这条路径的唯一装配点是 `crates/rmc-app/src/wiring.rs`（约 427-432
行）：它在那里造 `SshTunnelFactory::new(transport)`、
`TransportPreflight::new(transport)`，连同 `Deps { .. }` 一起交给
`Supervisor::spawn`。`KnownHosts` 与 `Config::known_hosts_path` 都不在
这条链路上了——前者已删，后者这个字段不再存在。反向端口范围校验也不归
任何人管了：端口由服务端分配、客户端只读回。

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
也不在了；Task 12 又把 CI 里那个 `integration` job 整个拿掉；**Task 13 把
`gateway/` 整个目录（含 `test-env/` 的 docker compose 与那批 python 测试）
`git rm -r` 掉了**，所以上面那句话里提到的东西现在一件都不在仓库里。

顶替它们的是 `crates/rmc-gateway/tests/e2e.rs`：同一条链路（Transport →
TLS 指纹钉扣 → russh → 反向端口 → pump → Supervisor）对着一台**进程内
起起来的真运维服务器**跑，不需要 docker、不需要 `/etc/hosts` 里那行
`gateway.test`、也不需要任何人记得传 `--ignored`。它跑在每一次
`cargo test` 里，CI 的 `core.yml`（Linux）与 `app.yml`（Windows）都会执行。

## 口令处理

口令只以 `Zeroizing<String>` 存在于内存，`TunnelParams` 与 `Command` 的
`Debug` 实现都把它替换为 `<redacted>`，`supervisor.rs` 与 `tunnel.rs` 的
`#[cfg(test)]` 里都有用例断言口令不会出现在审计日志或 `Debug` 输出中。
（这里原来还点名 `tests/ssh_tunnel.rs`——那份集成测试已随旧 docker 夹具
一起删除，见上一节。）
