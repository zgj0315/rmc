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

17 条里有 15 条按主机名拨 `gateway.test:8443`（`tests/common/mod.rs`
与 `tests/transport.rs`/`tests/preflight.rs` 各自的
`gateway_tls()`/`gateway()`），需要这台机器能把 `"gateway.test"`
解析到 `127.0.0.1`——本机手动跑上面最后一行，最直接的办法是在
`/etc/hosts` 里加一行 `127.0.0.1 gateway.test`（需要能写这个文件的
权限）。只有另外 2 条（`tests/transport.rs` 里的
`wrap_tls_accepts_the_harness_cert_when_the_extra_root_is_trusted`/
`wrap_tls_rejects_the_harness_cert_without_the_extra_root`）按 IP
拨号、只把 `"gateway.test"` 当 TLS SNI 传，不摸 DNS，这两条在没有
`/etc/hosts` 权限的机器上也能跑。

CI（`.github/workflows/core.yml`）不写宿主的 `/etc/hosts`：跑这 17
条测试的进程本身在一个临时容器里（`--network host` + `--add-host
gateway.test:127.0.0.1`），`--add-host` 只给这一个容器自己的
`/etc/hosts` 加一行、容器退出即消失。**需要它的原因是"要把
`gateway.test` 解析到一个地址"这件事本身，跟这个容器用
`--network host` 还是别的网络模式无关**——哪怕换成加入 docker
compose 的隔离网络，一样需要给 `gateway.test` 一个主机名映射，只是
映射到的地址不同（发布端口那台机器的 IP，而不是 `127.0.0.1`）。这台
开发机没有 `/etc/hosts` 写权限时，最直接的本机复现方式就是照抄 CI
那一步：起一个 `--network host --add-host gateway.test:127.0.0.1`
的容器，在容器里跑 `cargo test`，不需要碰宿主的 `/etc/hosts`。

## 口令处理

口令只以 `Zeroizing<String>` 存在于内存，`TunnelParams` 与 `Command` 的
`Debug` 实现都把它替换为 `<redacted>`，`tests/ssh_tunnel.rs` 与
`supervisor.rs` 的 `#[cfg(test)]` 里都有用例断言口令不会出现在审计日志
或 `Debug` 输出中。
