# Maintenance Gateway

远程维护的汇聚点。不含自研服务端程序，由 haproxy 与一个隧道专用的 sshd 实例组成。
设计依据见 `../docs/方案设计.md` 第 4 章。

## 组成

| 端口 | 组件 | 作用 |
|---|---|---|
| 443 | haproxy | 终止 TLS，转给 `127.0.0.1:2222` |
| 127.0.0.1:2222 | sshd-tunnel | 只服务 `tunnel-*` 账号，只允许建立一个指定端口的反向端口 |
| 22000-22999 | 反向端口 | 由 sshd-tunnel 按在线隧道创建，绑 `0.0.0.0`，工程师直连 |

`sshd-tunnel` 的配置文件、host key、pid 文件都与主机系统自带的 sshd 完全独立，互不干扰。

## 反向端口是公网可达的

`sshd-tunnel` 配的是 `GatewayPorts yes`，所以每条在线隧道的反向端口绑在 `0.0.0.0` 上，互联网上任何人都能连到它，连上之后面对的就是客户一体机的 sshd。这是明确的取舍：先把功能打通，把安全收紧排在后面。部署这台机器之前请确认知道这一点。

- 拦在前面的只有一体机自己的动态 root 口令，所以它的强度与轮换周期直接决定了安全边界；
- 端口在 22000-22999 内连号分配，可以被顺序枚举；
- Gateway 不记录谁在什么时间访问了哪台一体机，也没有逐工程师的凭据可吊销。

把端口绑回内网网卡或限定来源网段、在一体机之前恢复认证与审计点、把端口号打散，都记在方案 7.3 的后续加固里。

## 部署

```bash
sudo install -m 600 sshd_tunnel_config /etc/ssh/sshd_tunnel_config
sudo install -m 644 haproxy.cfg /etc/haproxy/haproxy.cfg
sudo install -m 644 systemd/sshd-tunnel.service /etc/systemd/system/
sudo ssh-keygen -t ed25519 -N '' -f /etc/ssh/tunnel_host_ed25519_key
# 证书用公共 CA 签发，合成 fullchain+key 放到下面这个路径
sudo install -m 600 gateway.pem /etc/haproxy/certs/gateway.pem
sudo systemctl daemon-reload
sudo systemctl enable --now sshd-tunnel haproxy
```

记下 `/etc/ssh/tunnel_host_ed25519_key.pub` 的指纹，客户端首次连接时要核对：

```bash
ssh-keygen -lf /etc/ssh/tunnel_host_ed25519_key.pub
```

## 受管配置区段：勿手工编辑

`sshd_tunnel_config` 里 `# BEGIN RMC MANAGED` 到 `# END RMC MANAGED` 之间的区段（逐账号的 `Match User` / `PermitListen` 块）是 `enroll-account.sh` 与 `revoke-account.sh` 依 `registry.toml` 整体重写生成的，标记之外的内容原样保留。手工改动这段区段没有意义：下一次任何账号的 enroll 或 revoke 都会把它整段覆盖掉。要变更某个账号的端口放行，改 `registry.toml` 再跑 enroll，不要直接编辑配置文件。

## 三个脚本的运行身份

| 脚本 | 运行身份 | 原因 |
|---|---|---|
| `enroll-account.sh` | root（`sudo`） | 要创建系统用户、写系统口令、改写 `/etc/ssh/sshd_tunnel_config` 并 reload sshd |
| `revoke-account.sh` | root（`sudo`） | 要锁定系统口令、改写受管配置、踢掉在线会话 |
| `tunnel-status.sh` | 任意登录用户，**不需要 root** | 只读 `registry.toml` 与进程表，不改动任何系统状态；脚本本身刻意不做 root 检查 |

## 开通账号

1. 在 `registry.toml` 中新增一条 `[[tunnel_account]]`，端口在 22000-22999 内且不与现有记录重复；
2. `python3 scripts/registry.py validate` 校验；
3. `sudo scripts/enroll-account.sh <username>`，把打印出的初始口令交给现场人员；
4. `scripts/tunnel-status.sh` 确认端口已登记（不需要 `sudo`）。

`enroll-account.sh` 每次运行结束都会扫描整张登记表，对**口令已锁定但仍在册**的账号打印警告，例如：

```
警告：tunnel-li 的口令处于锁定状态，但仍在 registry.toml 里，端口放行已经/将会为它重新生成。若这是一次吊销，请从 registry.toml 中删除该账号的记录。
```

这条警告的含义：`revoke-account.sh` 只锁口令、摘端口、踢会话，故意不碰 `registry.toml`；只要记录还留在登记表里，往后任何一次 enroll——哪怕是给完全不相关的另一个账号跑的——都会把这个已吊销账号的端口放行重新生成出来。锁着的口令是当时唯一还挡着的东西。看到这条警告，操作员要做的就是从 `registry.toml` 中删除该账号的记录，而不是忽略它。

## 吊销账号

```bash
sudo scripts/revoke-account.sh <username>
```

`revoke-account.sh` 会锁定口令、从受管配置中移除该账号的端口放行、踢掉在线会话，但**不会**修改 `registry.toml`——登记表是人工维护的唯一事实来源，不由吊销脚本代劳编辑。吊销之后务必手工从 `registry.toml` 删除该账号的记录；在删除之前，下一次任何账号的 enroll 都会把它的端口放行重新生成出来（见上一节的警告）。

## 退出码

三个脚本的退出码含义不完全相同，同一个数字在不同脚本里代表不同的事，按脚本分别查：

### `enroll-account.sh`

| 退出码 | 含义 |
|---|---|
| 1 | 未以 root 运行 |
| 2 | 用法错误（参数个数不对） |
| 3 | 用户名不在 `registry.toml` 里（经 `registry_get` 判定） |
| 4 | 登记表读取失败 / 登记表不合法 |
| 5 | 生成的受管配置未通过 `sshd -t` |

`enroll-account.sh` 不校验用户名前缀本身（不调用 `require_tunnel_username`）：`registry.toml` 里本就不允许非 `tunnel-*` 的记录存在，所以一个非隧道用户名要么在登记表里查不到（退出码 3），要么因登记表整体不合法而退出码 4，不会走到退出码 6。

### `revoke-account.sh`

| 退出码 | 含义 |
|---|---|
| 1 | 未以 root 运行 |
| 2 | 用法错误（参数个数不对） |
| 3 | 系统里没有这个用户（`getent passwd` 查不到，与登记表无关） |
| 4 | 登记表读取失败 / 登记表不合法（重写受管配置时触发） |
| 5 | 生成的受管配置未通过 `sshd -t` |
| 6 | 用户名不是 `tunnel-` 前缀——本脚本第一步就会拒绝，防止对非隧道账号（例如 `root`）执行 `passwd -l` / `pkill -u` |

### `tunnel-status.sh`

| 退出码 | 含义 |
|---|---|
| 2 | 用法错误（本脚本不接受任何参数） |

其余失败（登记表读取失败等）直接来自 `registry.py`，随对应子命令的输出与退出码原样传导。

## 工程师登录一体机

```bash
ssh -p 22001 root@gateway.company.com
```

工程师在 Gateway 上不需要账号，直连反向端口即可。口令是该设备的动态 root 口令，从公司内部口令服务按设备编号取。

首次连接必须核对一体机的 host key 指纹：直连时 `known_hosts` 记的是 Gateway 的地址与端口，而不同一体机会先后复用同一个端口，host key 变更告警会变成常态。现场人员的客户端界面上「复制」按钮给出的就是命令加该设备的指纹。

## 常见故障

| 现象 | 原因 | 处理 |
|---|---|---|
| 客户端报端口占用 | 上一条隧道静默断开，端口未回收 | 等约 90 秒（回收实测约 80 秒，非 30 秒，见 `docs/方案设计.md` §4.2），客户端会在 120 秒重试上限内自动重试；`tunnel-status.sh` 可看在线状态 |
| 客户端认证失败 | 口令错误或账号被锁 | `passwd -S <username>` 看锁定状态 |
| 工程师连 22001 连不上 | 隧道不在线，端口尚未创建 | `tunnel-status.sh` 看该账号是否 online，再让现场人员开启远程维护 |
| 工程师连上 22001 但立即断开 | 隧道在线但一体机不可达 | 让现场人员看客户端是否为橙色的一体机不可达 |
| haproxy 起不来 | 证书路径或权限不对 | `haproxy -c -f /etc/haproxy/haproxy.cfg` |

## 本地测试

```bash
python3 -m venv .venv && .venv/bin/pip install -r tests/requirements.txt
cd test-env && docker compose up -d --build
cd .. && .venv/bin/python -m pytest tests -v
```

脚本测试（19 条 bats 用例）在容器内运行，因为它们会创建系统账号、改写 sshd 配置：

```bash
cd test-env && docker compose exec -T gateway bats /gateway/tests/test_scripts.bats
```
