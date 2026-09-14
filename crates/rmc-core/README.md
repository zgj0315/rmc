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

## 平台能力注入

`platform.rs` 中的三个 trait 由 rmc-win 实现：`ProxyResolver`、
`ProxyAuthenticator`、`SystemEvents`。口令存储不在 core 内，界面填好口令后
经 `Command::Start` 下发。Linux 测试用同文件里的 `NoProxy`、`NoProxyAuth`、
`NoSystemEvents`。

## 测试

```bash
cargo test -p rmc-core                    # 单元与假隧道测试，不碰网络
cd ../../gateway/test-env && docker compose up -d --build
../../crates/rmc-core/tests/fetch-harness-cert.sh
cargo test -p rmc-core -- --ignored --test-threads=1   # 真实链路，17 条
```

`--test-threads=1` 是必须的：多个集成用例会争抢同一个反向端口。

CI（`.github/workflows/core.yml`）跑这 17 条 `--ignored` 用例时，测试
进程本身跑在一个临时容器里（`--network host` + `--add-host
gateway.test:127.0.0.1`），不需要 sudo、不需要改宿主的
`/etc/hosts`——本机手动复现时同理，不用先给自己账号加 `/etc/hosts` 的
写权限。docker compose 发布到 `127.0.0.1` 的端口在 `--network host`
下原样可达，上面第二行的裸 `docker compose up -d --build` 已经够用；
只有在容器化 CI 的那种隔离网络里才需要 `--add-host`。

## 口令处理

口令只以 `Zeroizing<String>` 存在于内存，`TunnelParams` 与 `Command` 的
`Debug` 实现都把它替换为 `<redacted>`，`tests/ssh_tunnel.rs` 与
`supervisor.rs` 的 `#[cfg(test)]` 里都有用例断言口令不会出现在审计日志
或 `Debug` 输出中。
