# Gateway 与集成测试环境 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 搭出一台 Gateway，让隧道账号用口令经 TLS:443 登录并注册 loopback 反向端口，工程师从 22 端口跳转即可到达一体机；同时给出一套 docker compose 测试环境，供 CI 与后续客户端开发复用。

**Architecture:** 不写服务端程序。Gateway 由 haproxy 做 443 的 TLS 终止，转给只监听 loopback 的 `sshd-tunnel` 实例；另一个 `sshd-engineer` 实例守 22 端口，工程师无 shell 只能 ProxyJump。账号与端口的唯一事实来源是 `gateway/registry.toml`，由 `registry.py` 解析、三个 shell 脚本消费。测试环境用 docker compose 起 gateway 与 appliance 两个容器，本计划阶段用 `ssh` 与一段 python 写的 TLS 中继充当客户端，因此 Gateway 的正确性不依赖 Rust 代码。

**Tech Stack:** Debian 12、OpenSSH 9.2p1、haproxy 2.6、python3 3.11（tomllib 为标准库，宿主低于 3.11 时回退到 tomli）、pytest、bats-core、docker compose v2、socat（仅 gateway 容器内使用）

**Spec:** `docs/方案设计.md`，本计划实现第 4 章全部、第 6 章的登记与吊销流程、第 8 章中与 Gateway 相关的用例。

## Global Constraints

- 反向端口只允许绑定 loopback，由服务端 `GatewayPorts no` 强制，不信任客户端传入的地址。
- 隧道账号用户名必须匹配 `tunnel-*`，shell 为 `/usr/sbin/nologin`，`ForceCommand /bin/false`。
- 隧道账号只允许 remote forwarding，端口由 `Match User` 块的 `PermitListen` 逐账号限定。
- `ClientAliveInterval 10` 与 `ClientAliveCountMax 3`，异常断线后 30 秒内回收反向端口。
- `LoginGraceTime 20`、`MaxAuthTries 3`。
- 工程师账号在 `sshd-engineer` 上只允许 local forwarding 到 `127.0.0.1:*`，`PermitTTY no`，`ForceCommand /bin/false`。
- V1 不做 pam_faillock 与 haproxy 按来源 IP 限速，见方案 7.3。
- 两个 sshd 实例的配置文件、host key、pid 文件必须完全独立。
- 所有脚本以 `set -euo pipefail` 开头，非 root 运行时立即退出。

---

### Task 1: registry.py 解析与校验

`registry.toml` 是账号与端口的唯一事实来源，三个运维脚本都从它取值。先把解析和校验做对，后面脚本才有依据。

**Files:**
- Create: `gateway/registry.toml`
- Create: `gateway/scripts/registry.py`
- Create: `gateway/tests/requirements.txt`
- Modify: `.gitignore`
- Test: `gateway/tests/test_registry.py`

**Interfaces:**
- Consumes: 无
- Produces:
  - `registry.py list-usernames` → 每行一个用户名，退出码 0
  - `registry.py get <username>` → `username\towner\tport\tappliances`（appliances 用逗号连接），未找到时 stderr 报错并退出码 3
  - `registry.py validate` → 校验通过退出码 0，失败时 stderr 报出发现的第一个问题并退出码 4（`load` 遇错即抛，三个运维脚本也都在首个错误处中止）
  - Python 层：`load(path: Path) -> list[Account]`，`Account` 为 dataclass，字段 `username: str, owner: str, port: int, appliances: list[str]`

- [ ] **Step 1: 写下失败的测试**

创建 `gateway/tests/test_registry.py`：

```python
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "registry.py"
sys.path.insert(0, str(SCRIPT.parent))

from registry import Account, RegistryError, load  # noqa: E402


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "registry.toml"
    p.write_text(text, encoding="utf-8")
    return p


GOOD = """
[[tunnel_account]]
username   = "tunnel-zhang"
owner      = "张三"
port       = 22001
appliances = ["c0001-a1"]

[[tunnel_account]]
username   = "tunnel-li"
owner      = "李四"
port       = 22002
appliances = []
"""


def test_load_returns_accounts_in_file_order(tmp_path):
    accounts = load(write(tmp_path, GOOD))
    assert accounts == [
        Account("tunnel-zhang", "张三", 22001, ["c0001-a1"]),
        Account("tunnel-li", "李四", 22002, []),
    ]


def test_username_must_have_tunnel_prefix(tmp_path):
    bad = GOOD.replace('username   = "tunnel-li"', 'username   = "li"')
    with pytest.raises(RegistryError, match="tunnel-"):
        load(write(tmp_path, bad))


def test_duplicate_username_is_rejected(tmp_path):
    bad = GOOD.replace('username   = "tunnel-li"', 'username   = "tunnel-zhang"')
    with pytest.raises(RegistryError, match="重复的用户名"):
        load(write(tmp_path, bad))


def test_duplicate_port_is_rejected(tmp_path):
    bad = GOOD.replace("port       = 22002", "port       = 22001")
    with pytest.raises(RegistryError, match="重复的端口"):
        load(write(tmp_path, bad))


def test_port_must_be_in_allowed_range(tmp_path):
    bad = GOOD.replace("port       = 22002", "port       = 80")
    with pytest.raises(RegistryError, match="22000"):
        load(write(tmp_path, bad))


def test_missing_field_is_rejected(tmp_path):
    bad = GOOD.replace('owner      = "李四"\n', "")
    with pytest.raises(RegistryError, match="owner"):
        load(write(tmp_path, bad))


def test_cli_list_usernames(tmp_path):
    p = write(tmp_path, GOOD)
    out = subprocess.run(
        [sys.executable, str(SCRIPT), "list-usernames"],
        env={"RMC_REGISTRY": str(p), "PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, check=True,
    )
    assert out.stdout.split() == ["tunnel-zhang", "tunnel-li"]


def test_cli_get_emits_tab_separated_fields(tmp_path):
    p = write(tmp_path, GOOD)
    out = subprocess.run(
        [sys.executable, str(SCRIPT), "get", "tunnel-zhang"],
        env={"RMC_REGISTRY": str(p), "PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, check=True,
    )
    assert out.stdout.strip() == "tunnel-zhang\t张三\t22001\tc0001-a1"


def test_cli_get_unknown_username_exits_3(tmp_path):
    p = write(tmp_path, GOOD)
    out = subprocess.run(
        [sys.executable, str(SCRIPT), "get", "tunnel-nobody"],
        env={"RMC_REGISTRY": str(p), "PATH": "/usr/bin:/bin"},
        capture_output=True, text=True,
    )
    assert out.returncode == 3
    assert "tunnel-nobody" in out.stderr
```

- [ ] **Step 2: 运行测试确认失败**

宿主 python 不带 pytest，先建一个只给测试用的 venv（正式依赖清单在 Step 3 落盘）：

```bash
cd gateway
python3 -m venv .venv
.venv/bin/pip install -q pytest==8.3.4
.venv/bin/python -m pytest tests/test_registry.py -v
```

预期：collection error，`ModuleNotFoundError: No module named 'registry'`。

- [ ] **Step 3: 写最小实现**

创建 `gateway/registry.toml`：

```toml
# Gateway 隧道账号登记表，账号与反向端口的唯一事实来源。
# 新增账号后运行 scripts/enroll-account.sh <username>。
# 端口范围 22000-22999，逐账号唯一。

[[tunnel_account]]
username   = "tunnel-zhang"
owner      = "张三"
port       = 22001
appliances = ["c0001-a1"]
```

创建 `gateway/scripts/registry.py`：

```python
#!/usr/bin/env python3
"""读取并校验 gateway/registry.toml。

用法：
  registry.py list-usernames
  registry.py get <username>
  registry.py validate

登记表路径默认为本文件上一级目录下的 registry.toml，可用环境变量
RMC_REGISTRY 覆盖。
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # python 3.11 之前标准库没有 tomllib，回退到 tomli
    import tomli as tomllib  # type: ignore[no-redef]

PORT_MIN = 22000
PORT_MAX = 22999
USERNAME_PREFIX = "tunnel-"


class RegistryError(Exception):
    """登记表内容不合法。"""


@dataclass
class Account:
    username: str
    owner: str
    port: int
    appliances: list[str] = field(default_factory=list)


def default_path() -> Path:
    env = os.environ.get("RMC_REGISTRY")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[1] / "registry.toml"


def load(path: Path | None = None) -> list[Account]:
    path = path or default_path()
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RegistryError(f"找不到登记表 {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise RegistryError(f"登记表 TOML 语法错误：{exc}") from exc

    entries = raw.get("tunnel_account", [])
    if not entries:
        raise RegistryError("登记表中没有任何 [[tunnel_account]]")

    accounts: list[Account] = []
    seen_users: dict[str, int] = {}
    seen_ports: dict[int, str] = {}

    for index, entry in enumerate(entries, start=1):
        for key in ("username", "owner", "port"):
            if key not in entry:
                raise RegistryError(f"第 {index} 条记录缺少字段 {key}")

        username = entry["username"]
        if not isinstance(username, str) or not username.startswith(USERNAME_PREFIX):
            raise RegistryError(f"第 {index} 条记录的用户名必须以 {USERNAME_PREFIX} 开头：{username}")
        if username in seen_users:
            raise RegistryError(f"重复的用户名 {username}，见第 {seen_users[username]} 条")
        seen_users[username] = index

        port = entry["port"]
        if not isinstance(port, int) or isinstance(port, bool):
            raise RegistryError(f"{username} 的端口必须是整数：{port!r}")
        if not PORT_MIN <= port <= PORT_MAX:
            raise RegistryError(f"{username} 的端口 {port} 超出允许范围 {PORT_MIN}-{PORT_MAX}")
        if port in seen_ports:
            raise RegistryError(f"重复的端口 {port}，已被 {seen_ports[port]} 占用")
        seen_ports[port] = username

        appliances = entry.get("appliances", [])
        if not isinstance(appliances, list) or any(not isinstance(a, str) for a in appliances):
            raise RegistryError(f"{username} 的 appliances 必须是字符串列表")

        accounts.append(Account(username, entry["owner"], port, list(appliances)))

    return accounts


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    command = argv[1]
    try:
        accounts = load()
    except RegistryError as exc:
        print(f"登记表不合法：{exc}", file=sys.stderr)
        return 4

    if command == "validate":
        return 0
    if command == "list-usernames":
        for a in accounts:
            print(a.username)
        return 0
    if command == "get":
        if len(argv) != 3:
            print("用法：registry.py get <username>", file=sys.stderr)
            return 2
        wanted = argv[2]
        for a in accounts:
            if a.username == wanted:
                print(f"{a.username}\t{a.owner}\t{a.port}\t{','.join(a.appliances)}")
                return 0
        print(f"登记表中没有账号 {wanted}", file=sys.stderr)
        return 3
    print(f"未知子命令 {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

创建 `gateway/tests/requirements.txt`。`tomli` 只在低于 3.11 的解释器上安装，部署目标 Debian 12 是 python3.11，用标准库的 tomllib：

```
pytest==8.3.4
tomli; python_version < "3.11"
```

把测试用的 venv 目录加进仓库根的 `.gitignore`：

```bash
cd "$(git rev-parse --show-toplevel)" && printf 'gateway/.venv/\n' >> .gitignore
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cd gateway
python3 -m venv .venv
.venv/bin/pip install -q -r tests/requirements.txt
chmod +x scripts/registry.py
.venv/bin/python -m pytest tests/test_registry.py -v
```

预期：9 passed。此后各任务一律用 `.venv/bin/python -m pytest` 跑测试。

- [ ] **Step 5: 提交**

```bash
git add .gitignore gateway/registry.toml gateway/scripts/registry.py \
        gateway/tests/requirements.txt gateway/tests/test_registry.py
git commit -m "feat(gateway): registry.toml 解析与校验"
```

---

### Task 2: docker compose 测试环境与 sshd-tunnel 基本连通

先让口令认证和反向端口在容器里跑通，暂不接 TLS。此后所有 Gateway 行为都用这套环境断言。

**Files:**
- Create: `gateway/sshd_tunnel_config`
- Create: `gateway/sshd_engineer.conf`（占位，Task 5 替换内容）
- Create: `gateway/haproxy.cfg`（占位，Task 4 替换内容）
- Create: `gateway/systemd/sshd-tunnel.service`
- Create: `gateway/test-env/docker-compose.yml`
- Create: `gateway/test-env/gateway/Dockerfile`
- Create: `gateway/test-env/gateway/entrypoint.sh`
- Create: `gateway/test-env/appliance/Dockerfile`
- Create: `gateway/test-env/.gitignore`
- Create: `gateway/tests/conftest.py`
- Test: `gateway/tests/test_tunnel.py`

**Interfaces:**
- Consumes: 无。本任务不依赖 Task 1 的任何产物：entrypoint 直接用 `useradd` 建账号，不读登记表。
- Produces:
  - compose 服务 `gateway`，宿主端口 `127.0.0.1:2422` → 容器内 socat 的 `2223`（再转给只监听 loopback 的 `sshd-tunnel` `127.0.0.1:2222`），`127.0.0.1:2022` → `sshd-engineer`，`127.0.0.1:8443` → haproxy（Task 4 接上）
  - compose 服务 `appliance`，宿主端口 `127.0.0.1:2322` → 容器内 sshd:22，账号 `root`，口令 `appliance-dynamic-pw`
  - `gateway/tests/conftest.py` 是全部测试模块唯一的共享层，测试模块之间不互相 import。它提供：
    - 常量 `ENV_DIR`、`HOST`、`TUNNEL_SSHD`、`ENGINEER_SSHD`、`HAPROXY`、`APPLIANCE_SSHD`、`TUNNEL_USER`、`TUNNEL_PW`、`TUNNEL_PORT`、`APPLIANCE_PW`、`ENG_KEY`、`SSH_COMMON`、`ENG_COMMON`，每个只在这里定义一次
    - 辅助函数 `compose()`、`wait_port()`、`port_listening_in_gateway()`、`engineer_proxy_option()`
    - 口令认证辅助 `askpass_env()`、`run_ssh_password()`、`popen_ssh_password()`、`run_sftp_password()`：口令经 OpenSSH 自带的 `SSH_ASKPASS` 机制传入，不依赖宿主装第三方工具
    - 固件 `harness`（session 作用域，拉起 compose、等待就绪、结束时销毁）与 `tunnel`
  - 测试常量：`TUNNEL_USER = "tunnel-zhang"`、`TUNNEL_PW = "tunnel-init-pw"`、`TUNNEL_PORT = 22001`

**说明：** 方案 4.2 的配置片段没有列出 `HostKey`、`PidFile` 与 `Subsystem`。第二个 sshd 实例必须有独立的 host key 与 pid 文件，本任务补上这三行；实现完成后把它们补进方案 4.2。

- [ ] **Step 1: 写下失败的测试**

创建 `gateway/tests/conftest.py`：

```python
from __future__ import annotations

import hashlib
import os
import shlex
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

ENV_DIR = Path(__file__).resolve().parents[1] / "test-env"

TUNNEL_USER = "tunnel-zhang"
TUNNEL_PW = "tunnel-init-pw"
TUNNEL_PORT = 22001
APPLIANCE_PW = "appliance-dynamic-pw"

HOST = "127.0.0.1"
TUNNEL_SSHD = 2422
ENGINEER_SSHD = 2022
HAPROXY = 8443
APPLIANCE_SSHD = 2322

ENG_KEY = ENV_DIR / "engineer-keys" / "eng_ed25519"

# 口令认证用的公共选项。限定 password 一种认证方式、只允许一次口令提示，
# 免得失败时 ssh 反复重试或退回其他方式，让断言的含义变模糊。
SSH_COMMON = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "PreferredAuthentications=password",
    "-o", "NumberOfPasswordPrompts=1",
    "-o", "ConnectTimeout=10",
]

# 工程师入口用公钥认证。
ENG_COMMON = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "IdentitiesOnly=yes",
    "-i", str(ENG_KEY),
    "-o", "ConnectTimeout=10",
]

_ASKPASS_DIR = Path(tempfile.gettempdir()) / f"rmc-askpass-{os.getuid()}"


def askpass_env(password: str) -> dict[str, str]:
    """生成一个只打印口令的脚本，并通过 SSH_ASKPASS 交给 ssh。

    OpenSSH 8.4+ 支持 SSH_ASKPASS_REQUIRE=force：不管有没有 tty 与 DISPLAY，
    都从该脚本读口令。宿主与 CI 用的 OpenSSH 都满足，因此不需要 sshpass 一类
    的第三方工具。调用方必须把 ssh 的 stdin 关掉（stdin=DEVNULL），否则 ssh
    会先向终端要口令。
    """
    _ASKPASS_DIR.mkdir(mode=0o700, exist_ok=True)
    script = _ASKPASS_DIR / f"{hashlib.sha256(password.encode()).hexdigest()[:16]}.sh"
    if not script.exists():
        script.write_text(
            f"#!/bin/sh\nprintf '%s\\n' {shlex.quote(password)}\n", encoding="utf-8"
        )
        script.chmod(0o700)
    env = dict(os.environ)
    env["SSH_ASKPASS"] = str(script)
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env.pop("SSH_AUTH_SOCK", None)
    return env


def run_ssh_password(password: str, *args: str, timeout: int = 25) -> subprocess.CompletedProcess:
    """跑一条口令认证的 ssh 并等它结束。"""
    return subprocess.run(
        ["ssh", *SSH_COMMON, *args],
        env=askpass_env(password), stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=timeout,
    )


def popen_ssh_password(password: str, *args: str) -> subprocess.Popen:
    """起一条常驻的口令认证 ssh（例如 -N -T 的隧道），收尾由调用方负责。"""
    return subprocess.Popen(
        ["ssh", *SSH_COMMON, *args],
        env=askpass_env(password), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def run_sftp_password(password: str, *args: str, timeout: int = 25) -> subprocess.CompletedProcess:
    """口令认证的 sftp，用来断言 sftp 子系统不可用。"""
    return subprocess.run(
        ["sftp", *SSH_COMMON, *args],
        env=askpass_env(password), stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=timeout,
    )


def engineer_proxy_option() -> list[str]:
    """经工程师入口跳到 Gateway loopback 的 ProxyCommand。

    ssh 的 -J 不会把命令行上的 -i 传给跳板那一跳，所以这里显式写 ProxyCommand，
    让跳板连接用 test-env/engineer-keys 里的私钥做公钥认证。

工程师密钥对不入库：整个 `engineer-keys/` 目录被忽略，由 `conftest.py` 的
`ensure_engineer_keypair()` 在 `harness` 起环境前按需生成，缺失时才生成。
只提交公钥会让新克隆拿到一把配不上私钥的公钥，所有工程师入口测试必然失败。
    """
    return ["-o", "ProxyCommand=ssh {} -W %h:%p -p {} eng@{}".format(
        " ".join(ENG_COMMON), ENGINEER_SSHD, HOST)]


def wait_port(port: int, timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=2):
                return
        except OSError as exc:
            last = exc
            time.sleep(0.5)
    raise TimeoutError(f"端口 {port} 在 {timeout} 秒内没有就绪：{last}")


def compose(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=ENV_DIR, check=check, capture_output=True, text=True,
    )


def port_listening_in_gateway(port: int) -> bool:
    out = compose("exec", "-T", "gateway", "ss", "-ltn", check=False)
    return f"127.0.0.1:{port}" in out.stdout


@pytest.fixture(scope="session")
def harness():
    compose("down", "-v", check=False)
    ensure_engineer_keypair()
    # 不用 check=True：那样 docker 的真实报错会被 capture_output 吞掉，
    # 只剩一个不带上下文的 CalledProcessError。Tasks 3-7 都依赖这个固件。
    up = compose("up", "-d", "--build", check=False)
    if up.returncode != 0:
        raise RuntimeError(
            "docker compose up 失败（退出码 %d）\n--- stdout ---\n%s\n--- stderr ---\n%s"
            % (up.returncode, up.stdout, up.stderr)
        )
    try:
        wait_port(TUNNEL_SSHD)
        wait_port(ENGINEER_SSHD)
        wait_port(APPLIANCE_SSHD)
        yield
    finally:
        if os.environ.get("RMC_KEEP_ENV") != "1":
            compose("down", "-v", check=False)


@pytest.fixture
def tunnel(harness):
    """以 tunnel-zhang 建立反向端口，yield 期间隧道在线。"""
    proc = popen_ssh_password(
        TUNNEL_PW,
        "-N", "-T",
        "-p", str(TUNNEL_SSHD),
        "-o", "ExitOnForwardFailure=yes",
        # -R 的目标地址由跑在宿主上的 ssh 客户端解析，宿主不在 compose 网络里，
        # 所以这里只能写一体机已发布到宿主的端口，不能写 compose 服务名。
        "-R", f"127.0.0.1:{TUNNEL_PORT}:{HOST}:{APPLIANCE_SSHD}",
        f"{TUNNEL_USER}@{HOST}",
    )
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            if proc.poll() is not None:
                pytest.fail(f"隧道进程提前退出：{proc.communicate()[1]}")
            if port_listening_in_gateway(TUNNEL_PORT):
                break
            time.sleep(0.5)
        else:
            pytest.fail(f"反向端口 {TUNNEL_PORT} 未在 Gateway 上出现")
        yield proc
    finally:
        proc.terminate()
        proc.wait(timeout=10)
```

创建 `gateway/tests/test_tunnel.py`：

```python
import socket

import pytest

from conftest import (
    APPLIANCE_PW, HOST, TUNNEL_PORT, TUNNEL_PW, TUNNEL_SSHD, TUNNEL_USER,
    engineer_proxy_option, port_listening_in_gateway, run_ssh_password,
)


def test_tunnel_account_authenticates_with_password(harness):
    out = run_ssh_password(
        TUNNEL_PW, "-p", str(TUNNEL_SSHD), f"{TUNNEL_USER}@{HOST}", "true")
    # ForceCommand /bin/false 会让命令失败，但认证必须通过。
    assert "Permission denied" not in out.stderr
    assert "Authentication failed" not in out.stderr


def test_wrong_password_is_rejected(harness):
    out = run_ssh_password(
        "wrong-pw", "-p", str(TUNNEL_SSHD), f"{TUNNEL_USER}@{HOST}", "true")
    assert out.returncode != 0
    assert "Permission denied" in out.stderr


def test_reverse_port_appears_on_gateway_loopback(tunnel):
    assert port_listening_in_gateway(TUNNEL_PORT)


def test_reverse_port_is_not_bound_on_a_wildcard_address(tunnel):
    """GatewayPorts no 必须把监听限制在 loopback。

    直接查 gateway 容器的监听表：22001 只能出现在 127.0.0.1 上，
    不得出现 0.0.0.0 或 :: 的通配绑定。断言宿主连不上该端口是没有
    约束力的，因为该端口本来就没有在 compose 中发布。
    """
    table = gateway_listen_table()
    assert f"127.0.0.1:{TUNNEL_PORT}" in table, table
    for wildcard in (f"0.0.0.0:{TUNNEL_PORT}", f"*:{TUNNEL_PORT}", f"[::]:{TUNNEL_PORT}"):
        assert wildcard not in table, f"反向端口被绑到了通配地址 {wildcard}：\n{table}"


def test_engineer_reaches_appliance_through_reverse_port(tunnel):
    out = run_ssh_password(
        APPLIANCE_PW,
        *engineer_proxy_option(),
        "-o", "HostKeyAlias=c0001-a1",
        "-p", str(TUNNEL_PORT), "root@127.0.0.1", "cat /etc/appliance-id",
        timeout=40,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "c0001-a1"
```

注：判断反向端口是否只绑 loopback，必须查 gateway 容器内的监听表，而不是断言宿主连不上该端口。后者没有约束力，因为该端口本来就没有在 compose 中发布，无论 `GatewayPorts` 怎么设都连不上。`conftest.py` 因此提供 `gateway_listen_table()` 回传容器内 `ss -ltn` 的原文，`port_listening_in_gateway()` 在其上**逐行解析 Local Address:Port 字段并整值比较**。不能用子串判断：查 22 会命中 `127.0.0.1:2222`，查 22 或 443 时会得到假通过。

- [ ] **Step 2: 运行测试确认失败**

```bash
cd gateway && .venv/bin/python -m pytest tests/test_tunnel.py -v
```

预期：`harness` 固件失败，`docker compose up` 报找不到 `test-env/docker-compose.yml`。

- [ ] **Step 3: 写最小实现**

创建 `gateway/sshd_tunnel_config`：

```
# /etc/ssh/sshd_tunnel_config
# 隧道专用 sshd 实例。只服务 tunnel-* 账号，只允许建立一个 loopback 反向端口。
# systemd: sshd-tunnel.service
ListenAddress 127.0.0.1:2222
HostKey /etc/ssh/tunnel_host_ed25519_key
PidFile /run/sshd-tunnel.pid
Subsystem sftp /bin/false

UsePAM yes
AuthenticationMethods password
PasswordAuthentication yes
PubkeyAuthentication no
PermitRootLogin no
AllowUsers tunnel-*

ClientAliveInterval 10
ClientAliveCountMax 3
LoginGraceTime 20
MaxAuthTries 3

GatewayPorts no
AllowTcpForwarding remote
PermitOpen none
PermitTTY no
X11Forwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
ForceCommand /bin/false

# 以下 Match 块由 scripts/enroll-account.sh 依 registry.toml 生成，勿手工编辑。
# BEGIN RMC MANAGED
Match User tunnel-zhang
    PermitListen 127.0.0.1:22001
# END RMC MANAGED
```

创建 `gateway/systemd/sshd-tunnel.service`：

```ini
[Unit]
Description=OpenSSH tunnel-only instance for Remote Maintenance
After=network.target
Requires=sshd-keygen-tunnel.service

[Service]
Type=notify
ExecStartPre=/usr/sbin/sshd -t -f /etc/ssh/sshd_tunnel_config
ExecStart=/usr/sbin/sshd -D -f /etc/ssh/sshd_tunnel_config
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

创建 `gateway/test-env/appliance/Dockerfile`：

```dockerfile
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /run/sshd \
 && echo "root:appliance-dynamic-pw" | chpasswd \
 && echo "c0001-a1" > /etc/appliance-id \
 && printf '%s\n' \
      'PermitRootLogin yes' \
      'PasswordAuthentication yes' \
      'UsePAM yes' \
    > /etc/ssh/sshd_config.d/appliance.conf \
 && ssh-keygen -A
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
```

创建 `gateway/test-env/gateway/Dockerfile`：

```dockerfile
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-server haproxy socat iproute2 procps openssl python3 \
 && rm -rf /var/lib/apt/lists/*

# 构建上下文是 gateway/（见 compose 的 context: ..），以下路径都相对它书写。
# sshd_tunnel_config 等直接取仓库里的那一份，生产与测试共用同一个配置文件。
COPY sshd_tunnel_config /etc/ssh/sshd_tunnel_config
COPY sshd_engineer.conf /etc/ssh/sshd_config.d/engineer.conf
COPY haproxy.cfg /etc/haproxy/haproxy.cfg
COPY test-env/gateway/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN mkdir -p /run/sshd \
 && ssh-keygen -A \
 && ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/tunnel_host_ed25519_key \
 && chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22 443 2223
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
```

创建 `gateway/test-env/gateway/entrypoint.sh`：

```bash
#!/bin/bash
# 测试环境入口：建账号、起两个 sshd 与 haproxy，并把 loopback 上的
# sshd-tunnel 通过 socat 暴露到容器网卡的 2223，使宿主的测试能直连它。
set -euo pipefail

useradd --system --shell /usr/sbin/nologin --no-create-home tunnel-zhang
echo 'tunnel-zhang:tunnel-init-pw' | chpasswd

groupadd engineers
useradd --shell /usr/sbin/nologin --no-create-home --gid engineers eng
mkdir -p /home/eng/.ssh
cp /engineer-keys/authorized_keys /home/eng/.ssh/authorized_keys
chown -R eng:engineers /home/eng
chmod 700 /home/eng/.ssh
chmod 600 /home/eng/.ssh/authorized_keys

/usr/sbin/sshd -t -f /etc/ssh/sshd_tunnel_config
/usr/sbin/sshd -f /etc/ssh/sshd_tunnel_config
/usr/sbin/sshd -t
/usr/sbin/sshd

# 测试用旁路：把容器网卡 2223 转到 loopback 2222。监听端口必须与 sshd-tunnel
# 的 127.0.0.1:2222 不同，否则 socat 绑 0.0.0.0:2222 会撞上 EADDRINUSE。
# 生产环境没有这一条。
socat TCP-LISTEN:2223,reuseaddr,fork TCP:127.0.0.1:2222 &

exec haproxy -W -db -f /etc/haproxy/haproxy.cfg
```

创建占位的工程师入口与 haproxy 配置，Task 4 与 Task 5 会替换内容。`gateway/sshd_engineer.conf`：

```
# /etc/ssh/sshd_config.d/engineer.conf
PasswordAuthentication no
```

`gateway/haproxy.cfg`：

```
global
    log stdout format raw local0
defaults
    mode tcp
    timeout connect 5s
    timeout client 1h
    timeout server 1h
frontend placeholder
    bind 127.0.0.1:9999
    default_backend sshd_tunnel
backend sshd_tunnel
    server local 127.0.0.1:2222
```

创建 `gateway/test-env/docker-compose.yml`：

```yaml
name: rmc-gateway-test

services:
  appliance:
    build: ./appliance
    ports:
      - "127.0.0.1:2322:22"

  gateway:
    build:
      context: ..
      dockerfile: test-env/gateway/Dockerfile
    depends_on:
      - appliance
    volumes:
      - ./engineer-keys:/engineer-keys:ro
    ports:
      - "127.0.0.1:2422:2223"
      - "127.0.0.1:2022:22"
      - "127.0.0.1:8443:443"
```

忽略整个工程师密钥目录，密钥对由 `conftest.py` 的 `ensure_engineer_keypair()` 按需生成，不入库：

```bash
printf 'engineer-keys/\n' > gateway/test-env/.gitignore
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cd gateway && .venv/bin/python -m pytest tests/test_tunnel.py -v
```

预期：5 passed，全部通过。

注意 `test_engineer_reaches_appliance_through_reverse_port` 在本任务就会通过，尽管
`sshd_engineer.conf` 此时只是个只设了 `PasswordAuthentication no` 的占位：默认 sshd
仍允许公钥认证与 TCP 转发，而 `ssh -W` 不需要 shell，所以跳板此刻是通的。它此时的绿
不构成对工程师入口的验证，Task 5 装上真正的配置后必须重跑它，那才是它真正把关的时刻。

- [ ] **Step 5: 提交**

```bash
git add gateway/sshd_tunnel_config gateway/sshd_engineer.conf gateway/haproxy.cfg \
        gateway/systemd gateway/test-env gateway/tests/conftest.py gateway/tests/test_tunnel.py
git commit -m "test(gateway): docker 测试环境与 sshd-tunnel 口令认证连通"
```

---

### Task 3: 隧道账号的权限边界

隧道口令一旦泄露，攻击者能做什么完全取决于这些限制。每一条都要有一个断言失败的测试。

**Files:**
- Modify: `gateway/sshd_tunnel_config`（如测试暴露缺项）
- Test: `gateway/tests/test_tunnel_restrictions.py`

**Interfaces:**
- Consumes: Task 2 的 `conftest.py`：`harness` 固件与口令 ssh 辅助函数 `run_ssh_password()` / `run_sftp_password()`
- Produces: 无新接口

- [ ] **Step 1: 写下失败的测试**

创建 `gateway/tests/test_tunnel_restrictions.py`：

```python
import subprocess

from conftest import (
    APPLIANCE_SSHD, HOST, TUNNEL_PORT, TUNNEL_PW, TUNNEL_SSHD, TUNNEL_USER,
    run_sftp_password, run_ssh_password,
)


def test_no_shell_and_no_command_execution(harness):
    out = run_ssh_password(TUNNEL_PW, "-p", str(TUNNEL_SSHD),
                           f"{TUNNEL_USER}@{HOST}", "id")
    assert out.returncode != 0
    assert "uid=" not in out.stdout


def test_no_pty(harness):
    out = run_ssh_password(TUNNEL_PW, "-tt", "-p", str(TUNNEL_SSHD),
                           f"{TUNNEL_USER}@{HOST}")
    assert out.returncode != 0
    assert "PTY allocation request failed" in out.stderr


def test_local_forwarding_is_refused(harness):
    """AllowTcpForwarding remote 必须禁掉 -L。"""
    # -L 的目标由服务端解析，gateway 容器在 compose 网络里，写服务名是对的。
    out = run_ssh_password(TUNNEL_PW, "-N", "-T", "-p", str(TUNNEL_SSHD),
                           "-o", "ExitOnForwardFailure=yes",
                           "-L", "127.0.0.1:19099:appliance:22",
                           f"{TUNNEL_USER}@{HOST}")
    assert out.returncode != 0
    assert "administratively prohibited" in out.stderr


def test_reverse_port_outside_permitlisten_is_refused(harness):
    """PermitListen 只放行 22001，别的端口必须被拒。"""
    # -R 的目标地址由跑在宿主上的 ssh 客户端解析，宿主不在 compose 网络里，
    # 所以只能写一体机已发布到宿主的端口，不能写 compose 服务名。
    out = run_ssh_password(TUNNEL_PW, "-N", "-T", "-p", str(TUNNEL_SSHD),
                           "-o", "ExitOnForwardFailure=yes",
                           "-R", f"127.0.0.1:22002:{HOST}:{APPLIANCE_SSHD}",
                           f"{TUNNEL_USER}@{HOST}")
    assert out.returncode != 0
    assert "remote port forwarding failed" in out.stderr.lower()


def test_reverse_port_on_wildcard_address_is_refused(harness):
    """客户端传 0.0.0.0 时，PermitListen 与 GatewayPorts no 都应拦住。"""
    # 同上：-R 的目标地址由宿主的 ssh 客户端解析，不能写 compose 服务名。
    out = run_ssh_password(TUNNEL_PW, "-N", "-T", "-p", str(TUNNEL_SSHD),
                           "-o", "ExitOnForwardFailure=yes",
                           "-R", f"0.0.0.0:{TUNNEL_PORT}:{HOST}:{APPLIANCE_SSHD}",
                           f"{TUNNEL_USER}@{HOST}")
    assert out.returncode != 0


def test_sftp_subsystem_is_unavailable(harness):
    out = run_sftp_password(TUNNEL_PW, "-P", str(TUNNEL_SSHD),
                            f"{TUNNEL_USER}@{HOST}")
    assert out.returncode != 0


def test_agent_forwarding_is_refused(harness):
    out = run_ssh_password(TUNNEL_PW, "-A", "-N", "-T", "-p", str(TUNNEL_SSHD),
                           f"{TUNNEL_USER}@{HOST}")
    assert out.returncode != 0


def test_pubkey_auth_is_disabled(harness):
    out = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "PreferredAuthentications=publickey",
         "-o", "ConnectTimeout=10",
         "-p", str(TUNNEL_SSHD), f"{TUNNEL_USER}@{HOST}"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=25,
    )
    assert out.returncode != 0
    assert "Permission denied" in out.stderr
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cd gateway && .venv/bin/python -m pytest tests/test_tunnel_restrictions.py -v
```

预期：至少 `test_sftp_subsystem_is_unavailable` 与 `test_no_pty` 的报错文本与断言不符，逐条对照 sshd 实际输出修正断言或补配置。

- [ ] **Step 3: 按测试结果补齐配置**

依失败项修改 `gateway/sshd_tunnel_config`。常见两处：

- sftp 未被禁：确认 `Subsystem sftp /bin/false` 在文件里且位于任何 `Match` 块之前。
- `-R` 到未放行端口时 ssh 只打印 warning 并继续：必须靠客户端的 `ExitOnForwardFailure=yes`，测试已带该选项；服务端无需改动。

改完重新 build：

```bash
cd gateway/test-env && docker compose up -d --build gateway
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cd gateway && .venv/bin/python -m pytest tests/test_tunnel_restrictions.py -v
```

预期：8 passed。

- [ ] **Step 5: 提交**

```bash
git add gateway/sshd_tunnel_config gateway/tests/test_tunnel_restrictions.py
git commit -m "test(gateway): 隧道账号权限边界的负向测试"
```

---

### Task 4: haproxy 在 443 终止 TLS

客户端出网只走 443，且要能穿过只放行 TLS 的审计设备，所以 SSH 必须裹在 TLS 里。

**Files:**
- Modify: `gateway/haproxy.cfg`
- Modify: `gateway/test-env/gateway/Dockerfile`（生成自签证书）
- Modify: `gateway/tests/conftest.py`（追加 TLS 中继固件）
- Test: `gateway/tests/test_tls_frontend.py`

**Interfaces:**
- Consumes: Task 2 的 `conftest.py`：`harness` 固件与口令 ssh 辅助函数
- Produces:
  - 宿主 `127.0.0.1:8443` 提供 TLS，SNI 与证书 CN 均为 `gateway.test`
  - `conftest.py` 中的测试固件 `tls_wrap`：用 python asyncio 在宿主起一个明文端口，把字节裹进 TLS 送到 8443，yield 该端口号。不依赖宿主装 socat

- [ ] **Step 1: 写下失败的测试**

先在 `gateway/tests/conftest.py` 的 import 段补上 `import asyncio`、`import contextlib`、`import ssl`、`import threading`，再在文件末尾追加 TLS 中继与 `tls_wrap` 固件：

```python
async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (OSError, ssl.SSLError):
        pass
    finally:
        with contextlib.suppress(Exception):
            writer.close()


class _TlsRelay:
    """把宿主上的明文 TCP 连接裹进 TLS 转给 haproxy 的 443。

    只用标准库，宿主不需要装 socat。SNI 固定为 gateway.test，证书是自签的
    所以不校验证书链，与原先 socat 的 verify=0,snihost=gateway.test 等价。
    """

    def __init__(self, host: str, port: int, sni: str) -> None:
        self._target = (host, port)
        self._sni = sni
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._server = None

    def start(self) -> int:
        """起监听，返回实际分配到的本地明文端口。"""
        self._thread.start()
        self._server = asyncio.run_coroutine_threadsafe(
            asyncio.start_server(self._handle, HOST, 0), self._loop
        ).result(timeout=10)
        return self._server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer) -> None:
        try:
            up_r, up_w = await asyncio.open_connection(
                *self._target, ssl=self._ctx, server_hostname=self._sni
            )
        except OSError:
            writer.close()
            return
        await asyncio.gather(_pump(reader, up_w), _pump(up_r, writer))

    def stop(self) -> None:
        async def _close() -> None:
            self._server.close()
            await self._server.wait_closed()

        asyncio.run_coroutine_threadsafe(_close(), self._loop).result(timeout=10)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=10)
        self._loop.close()


@pytest.fixture
def tls_wrap(harness):
    """yield 宿主上的一个明文端口，写进去的字节会裹进 TLS 送到 haproxy 的 443。"""
    relay = _TlsRelay(HOST, HAPROXY, "gateway.test")
    port = relay.start()
    try:
        yield port
    finally:
        relay.stop()
```

创建 `gateway/tests/test_tls_frontend.py`：

```python
import socket
import ssl
import time

import pytest

from conftest import (
    APPLIANCE_SSHD, HAPROXY, HOST, TUNNEL_PORT, TUNNEL_PW, TUNNEL_USER,
    popen_ssh_password, port_listening_in_gateway,
)


def test_tls_handshake_succeeds_and_presents_gateway_test_cert(harness):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((HOST, HAPROXY), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname="gateway.test") as tls:
            assert tls.version().startswith("TLSv1.")
            cn = dict(x[0] for x in tls.getpeercert(binary_form=False)["subject"])
            assert cn["commonName"] == "gateway.test"


def test_ssh_banner_arrives_through_tls(harness):
    """TLS 之内必须是 sshd-tunnel 的 banner。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((HOST, HAPROXY), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname="gateway.test") as tls:
            tls.settimeout(10)
            assert tls.recv(64).startswith(b"SSH-2.0-")


def test_reverse_tunnel_works_over_tls(tls_wrap):
    proc = popen_ssh_password(
        TUNNEL_PW, "-N", "-T", "-p", str(tls_wrap),
        "-o", "ExitOnForwardFailure=yes",
        # -R 的目标地址由跑在宿主上的 ssh 客户端解析，宿主不在 compose 网络里，
        # 所以只能写一体机已发布到宿主的端口，不能写 compose 服务名。
        "-R", f"127.0.0.1:{TUNNEL_PORT}:{HOST}:{APPLIANCE_SSHD}",
        f"{TUNNEL_USER}@{HOST}",
    )
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            if port_listening_in_gateway(TUNNEL_PORT):
                break
            time.sleep(0.5)
        else:
            pytest.fail(f"经 TLS 建立的反向端口未出现：{proc.stderr.read()}")
    finally:
        proc.terminate()
        proc.wait(timeout=10)
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cd gateway && .venv/bin/python -m pytest tests/test_tls_frontend.py -v
```

预期：TLS 握手失败，8443 上没有 TLS 服务。

- [ ] **Step 3: 写最小实现**

替换 `gateway/haproxy.cfg`：

```
# /etc/haproxy/haproxy.cfg
# 443 上终止 TLS 后转给只监听 loopback 的 sshd-tunnel。
# sshd 看到的来源恒为 127.0.0.1，客户端真实来源 IP 以本文件的日志为准。
global
    log stdout format raw local0
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384

defaults
    mode tcp
    log global
    option tcplog
    timeout connect 5s
    timeout client 1h
    timeout server 1h

frontend tunnel_in
    bind :443 ssl crt /etc/haproxy/certs/gateway.pem
    default_backend sshd_tunnel

backend sshd_tunnel
    server local 127.0.0.1:2222
```

`timeout client/server` 取 1 小时，必须长于客户端的 keepalive 周期（10 秒 × 3），否则 haproxy 会在空闲隧道上先掐断连接。

在 `gateway/test-env/gateway/Dockerfile` 的 `RUN` 里追加自签证书生成：

```dockerfile
RUN mkdir -p /etc/haproxy/certs \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -subj "/CN=gateway.test" \
      -addext "subjectAltName=DNS:gateway.test" \
      -keyout /tmp/k.pem -out /tmp/c.pem 2>/dev/null \
 && cat /tmp/c.pem /tmp/k.pem > /etc/haproxy/certs/gateway.pem \
 && rm /tmp/k.pem /tmp/c.pem \
 && chmod 600 /etc/haproxy/certs/gateway.pem
```

生产环境用公共 CA 签发的证书，放在同一路径，不使用自签。

- [ ] **Step 4: 运行测试确认通过**

```bash
cd gateway/test-env && docker compose up -d --build gateway
cd .. && .venv/bin/python -m pytest tests/test_tls_frontend.py -v
```

预期：3 passed。

- [ ] **Step 5: 提交**

```bash
git add gateway/haproxy.cfg gateway/test-env/gateway/Dockerfile \
        gateway/tests/conftest.py gateway/tests/test_tls_frontend.py
git commit -m "feat(gateway): haproxy 在 443 终止 TLS 并转给 sshd-tunnel"
```

---

### Task 5: 工程师入口

工程师在 Gateway 上必须没有 shell，只能跳到 loopback 上的隧道端口。

**Files:**
- Modify: `gateway/sshd_engineer.conf`
- Test: `gateway/tests/test_engineer_entry.py`

**Interfaces:**
- Consumes: Task 2 的 `conftest.py`：`harness`、`tunnel` 固件，常量 `ENG_KEY` / `ENG_COMMON` 与 `engineer_proxy_option()`，以及 `test-env/engineer-keys/eng_ed25519`
- Produces: 宿主 `127.0.0.1:2022` 为工程师入口，账号 `eng`，公钥认证

- [ ] **Step 1: 写下失败的测试**

创建 `gateway/tests/test_engineer_entry.py`：

```python
import subprocess

from conftest import (
    APPLIANCE_PW, ENG_COMMON, ENGINEER_SSHD, HOST, TUNNEL_PORT,
    engineer_proxy_option, run_ssh_password,
)


def test_engineer_cannot_get_a_shell(harness):
    out = subprocess.run(
        ["ssh", *ENG_COMMON, "-p", str(ENGINEER_SSHD), f"eng@{HOST}", "id"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=25,
    )
    assert out.returncode != 0
    assert "uid=" not in out.stdout


def test_engineer_cannot_forward_to_non_loopback(harness):
    # -L 的目标由服务端解析，gateway 容器在 compose 网络里，写服务名是对的；
    # PermitOpen 127.0.0.1:* 必须把这种非 loopback 目标拦住。
    out = subprocess.run(
        ["ssh", *ENG_COMMON, "-N", "-T", "-p", str(ENGINEER_SSHD),
         "-o", "ExitOnForwardFailure=yes",
         "-L", "127.0.0.1:19098:appliance:22", f"eng@{HOST}"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=25,
    )
    assert out.returncode != 0
    assert "administratively prohibited" in out.stderr


def test_engineer_password_auth_is_disabled(harness):
    out = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "PreferredAuthentications=password",
         "-o", "ConnectTimeout=10",
         "-p", str(ENGINEER_SSHD), f"eng@{HOST}"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=25,
    )
    assert out.returncode != 0


def test_engineer_jumps_to_appliance_and_runs_command(tunnel):
    out = run_ssh_password(
        APPLIANCE_PW,
        *engineer_proxy_option(),
        "-o", "HostKeyAlias=c0001-a1",
        "-p", str(TUNNEL_PORT), "root@127.0.0.1",
        "cat /etc/appliance-id",
        timeout=40,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "c0001-a1"
```

- [ ] **Step 2: 运行测试确认失败**

```bash
cd gateway && .venv/bin/python -m pytest tests/test_engineer_entry.py -v
```

预期：`test_engineer_cannot_get_a_shell` 失败，占位配置没有限制 shell。

- [ ] **Step 3: 写最小实现**

替换 `gateway/sshd_engineer.conf`：

```
# /etc/ssh/sshd_config.d/engineer.conf
# 工程师入口。无 shell，只能把本地端口跳到 loopback 上的隧道端口。
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no

Match Group engineers
    AllowTcpForwarding local
    PermitOpen 127.0.0.1:*
    PermitListen none
    PermitTTY no
    X11Forwarding no
    AllowAgentForwarding no
    AllowStreamLocalForwarding no
    ForceCommand /bin/false
```

`PermitOpen 127.0.0.1:*` 让工程师能跳到任意隧道端口，但到不了客户网络里的任何地址；`PermitListen none` 阻止工程师反向开端口。

- [ ] **Step 4: 运行测试确认通过**

```bash
cd gateway/test-env && docker compose up -d --build gateway
cd .. && .venv/bin/python -m pytest tests/test_engineer_entry.py tests/test_tunnel.py -v
```

预期：全部通过，含 Task 2 里先前失败的 `test_engineer_reaches_appliance_through_reverse_port`。

- [ ] **Step 5: 提交**

```bash
git add gateway/sshd_engineer.conf gateway/tests/test_engineer_entry.py
git commit -m "feat(gateway): 工程师入口仅允许跳转到 loopback 隧道端口"
```

---

### Task 6: 僵尸端口回收

客户端在 Wi-Fi 切换或休眠时会静默断开，Gateway 若不及时回收端口，客户端重连会一直撞在端口占用上。这是现场最常见的故障，必须有测试守住。

**Files:**
- Modify: `gateway/sshd_tunnel_config`（补预算注释）
- Test: `gateway/tests/test_zombie_port.py`

**Interfaces:**
- Consumes: Task 2 的 `conftest.py`：`harness` 固件、`port_listening_in_gateway()` 与 `popen_ssh_password()`
- Produces: 无新接口

- [ ] **Step 1: 写下失败的测试**

创建 `gateway/tests/test_zombie_port.py`：

```python
import signal
import subprocess
import time

import pytest

from conftest import (
    APPLIANCE_SSHD, HOST, TUNNEL_PORT, TUNNEL_PW, TUNNEL_SSHD, TUNNEL_USER,
    popen_ssh_password, port_listening_in_gateway,
)

RECLAIM_BUDGET = 45  # ClientAliveInterval 10 × CountMax 3 再留余量


def start_tunnel() -> subprocess.Popen:
    proc = popen_ssh_password(
        TUNNEL_PW, "-N", "-T", "-p", str(TUNNEL_SSHD),
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=0",
        # -R 的目标地址由跑在宿主上的 ssh 客户端解析，宿主不在 compose 网络里，
        # 所以只能写一体机已发布到宿主的端口，不能写 compose 服务名。
        "-R", f"127.0.0.1:{TUNNEL_PORT}:{HOST}:{APPLIANCE_SSHD}",
        f"{TUNNEL_USER}@{HOST}",
    )
    deadline = time.time() + 20
    while time.time() < deadline:
        if port_listening_in_gateway(TUNNEL_PORT):
            return proc
        time.sleep(0.5)
    proc.kill()
    pytest.fail("反向端口未建立")


def test_frozen_client_port_is_reclaimed_within_budget(harness):
    """SIGSTOP 冻结客户端，模拟静默断线；ClientAlive 必须回收端口。"""
    proc = start_tunnel()
    try:
        proc.send_signal(signal.SIGSTOP)
        deadline = time.time() + RECLAIM_BUDGET
        while time.time() < deadline:
            if not port_listening_in_gateway(TUNNEL_PORT):
                return
            time.sleep(1)
        pytest.fail(f"端口 {TUNNEL_PORT} 在 {RECLAIM_BUDGET} 秒内未被回收")
    finally:
        proc.send_signal(signal.SIGCONT)
        proc.terminate()
        proc.wait(timeout=10)


def test_port_can_be_rebound_after_reclaim(harness):
    """回收之后同一端口必须能重新注册，这是客户端重连成功的前提。"""
    first = start_tunnel()
    first.send_signal(signal.SIGSTOP)
    try:
        deadline = time.time() + RECLAIM_BUDGET
        while time.time() < deadline and port_listening_in_gateway(TUNNEL_PORT):
            time.sleep(1)
        assert not port_listening_in_gateway(TUNNEL_PORT), "端口未回收，后续断言无意义"
        second = start_tunnel()
        second.terminate()
        second.wait(timeout=10)
    finally:
        first.send_signal(signal.SIGCONT)
        first.terminate()
        first.wait(timeout=10)
```

- [ ] **Step 2: 运行测试确认失败或通过**

```bash
cd gateway && .venv/bin/python -m pytest tests/test_zombie_port.py -v
```

若 Task 2 的 `ClientAliveInterval 10` / `ClientAliveCountMax 3` 已生效，这两个用例应当直接通过。把 `gateway/sshd_tunnel_config` 里两行临时改成 `ClientAliveInterval 0` 重新 build，确认测试会失败，再改回来，以此证明测试确实在守这两个参数。

- [ ] **Step 3: 记录预算**

在 `gateway/sshd_tunnel_config` 的 ClientAlive 两行上方加注释：

```
# 客户端静默断线后 30 秒内回收反向端口。改动这两行会拉长现场重连时间，
# 由 tests/test_zombie_port.py 守护。
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cd gateway/test-env && docker compose up -d --build gateway
cd .. && .venv/bin/python -m pytest tests/test_zombie_port.py -v
```

预期：2 passed，单个用例耗时约 40 秒。

- [ ] **Step 5: 提交**

```bash
git add gateway/sshd_tunnel_config gateway/tests/test_zombie_port.py
git commit -m "test(gateway): 僵尸反向端口在 30 秒内被回收"
```

---

### Task 7: enroll / revoke / status 三个运维脚本

**Files:**
- Create: `gateway/scripts/lib.sh`
- Create: `gateway/scripts/enroll-account.sh`
- Create: `gateway/scripts/revoke-account.sh`
- Create: `gateway/scripts/tunnel-status.sh`
- Test: `gateway/tests/test_scripts.bats`

**Interfaces:**
- Consumes: Task 1 的 `registry.py`，Task 2 的 `sshd_tunnel_config` 中的 `BEGIN RMC MANAGED` / `END RMC MANAGED` 标记
- Produces:
  - `enroll-account.sh <username>`：建系统用户、设随机初始口令并打印一次、依 registry 重写受管 Match 块、`sshd -t` 校验后 reload
  - `revoke-account.sh <username>`：锁定口令、移除该用户的 Match 块、踢掉其在线会话
  - `tunnel-status.sh`：逐行输出 `<username> <port> <online|offline> <pid>`

- [ ] **Step 1: 写下失败的测试**

创建 `gateway/tests/test_scripts.bats`：

```bash
#!/usr/bin/env bats
# 在 gateway 容器内运行：
#   docker compose exec -T gateway bats /gateway/tests/test_scripts.bats

setup() {
    export RMC_REGISTRY=/tmp/registry.toml
    export RMC_SSHD_CONFIG=/tmp/sshd_tunnel_config
    export RMC_RELOAD_CMD=true
    cat > "$RMC_REGISTRY" <<'TOML'
[[tunnel_account]]
username   = "tunnel-zhang"
owner      = "zhang"
port       = 22001
appliances = ["c0001-a1"]

[[tunnel_account]]
username   = "tunnel-new"
owner      = "new"
port       = 22007
appliances = []
TOML
    cat > "$RMC_SSHD_CONFIG" <<'CONF'
ListenAddress 127.0.0.1:2222
# BEGIN RMC MANAGED
Match User tunnel-zhang
    PermitListen 127.0.0.1:22001
# END RMC MANAGED
CONF
}

teardown() {
    userdel tunnel-new 2>/dev/null || true
}

@test "enroll 拒绝不在登记表里的用户名" {
    run /gateway/scripts/enroll-account.sh tunnel-ghost
    [ "$status" -eq 3 ]
    [[ "$output" == *"tunnel-ghost"* ]]
}

@test "enroll 创建 nologin 系统用户" {
    run /gateway/scripts/enroll-account.sh tunnel-new
    [ "$status" -eq 0 ]
    run getent passwd tunnel-new
    [ "$status" -eq 0 ]
    [[ "$output" == *"/usr/sbin/nologin"* ]]
}

@test "enroll 打印一次初始口令" {
    run /gateway/scripts/enroll-account.sh tunnel-new
    [[ "$output" == *"初始口令"* ]]
    # 口令至少 20 字符
    pw=$(printf '%s\n' "$output" | sed -n 's/.*初始口令: //p')
    [ "${#pw}" -ge 20 ]
}

@test "enroll 依登记表重写受管 Match 块并保留块外内容" {
    run /gateway/scripts/enroll-account.sh tunnel-new
    [ "$status" -eq 0 ]
    grep -q "^ListenAddress 127.0.0.1:2222$" "$RMC_SSHD_CONFIG"
    grep -q "PermitListen 127.0.0.1:22001" "$RMC_SSHD_CONFIG"
    grep -q "PermitListen 127.0.0.1:22007" "$RMC_SSHD_CONFIG"
    # 受管标记只出现一次
    [ "$(grep -c 'BEGIN RMC MANAGED' "$RMC_SSHD_CONFIG")" -eq 1 ]
}

@test "enroll 幂等，重复执行不重复写 Match 块" {
    /gateway/scripts/enroll-account.sh tunnel-new
    before=$(md5sum "$RMC_SSHD_CONFIG" | cut -d' ' -f1)
    /gateway/scripts/enroll-account.sh tunnel-new
    after=$(md5sum "$RMC_SSHD_CONFIG" | cut -d' ' -f1)
    [ "$before" = "$after" ]
}

@test "revoke 锁定口令并移除 Match 块" {
    /gateway/scripts/enroll-account.sh tunnel-new
    run /gateway/scripts/revoke-account.sh tunnel-new
    [ "$status" -eq 0 ]
    run passwd -S tunnel-new
    [[ "$output" == *" L "* ]]
    ! grep -q "PermitListen 127.0.0.1:22007" "$RMC_SSHD_CONFIG"
}

@test "status 列出登记表中每个账号及其端口" {
    run /gateway/scripts/tunnel-status.sh
    [ "$status" -eq 0 ]
    [[ "$output" == *"tunnel-zhang 22001"* ]]
    [[ "$output" == *"tunnel-new 22007"* ]]
}

@test "非 root 运行立即退出" {
    run runuser -u nobody -- /gateway/scripts/enroll-account.sh tunnel-new
    [ "$status" -ne 0 ]
    [[ "$output" == *"root"* ]]
}
```

- [ ] **Step 2: 运行测试确认失败**

在 `gateway/test-env/gateway/Dockerfile` 的 apt 安装列表里加 `bats`，并在 compose 的 gateway 服务上挂载仓库：`- ..:/gateway:ro`。重新 build 后：

```bash
cd gateway/test-env && docker compose up -d --build gateway
docker compose exec -T gateway bats /gateway/tests/test_scripts.bats
```

预期：全部失败，脚本不存在。

- [ ] **Step 3: 写最小实现**

创建 `gateway/scripts/lib.sh`：

```bash
# 三个运维脚本共用的工具函数。不要直接执行本文件。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY_PY="$SCRIPT_DIR/registry.py"
SSHD_CONFIG="${RMC_SSHD_CONFIG:-/etc/ssh/sshd_tunnel_config}"
RELOAD_CMD="${RMC_RELOAD_CMD:-systemctl reload sshd-tunnel}"
BEGIN_MARK="# BEGIN RMC MANAGED"
END_MARK="# END RMC MANAGED"

die() { printf '%s\n' "$*" >&2; exit "${2:-1}"; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die "本脚本必须以 root 运行" 1
}

# 校验登记表并确认用户名在册，回显 "username owner port appliances"
registry_get() {
    local username="$1" line
    if ! line="$(python3 "$REGISTRY_PY" get "$username" 2>&1)"; then
        die "$line" 3
    fi
    printf '%s\n' "$line"
}

# 依登记表整体重写受管 Match 块，块外内容原样保留。
rewrite_match_block() {
    local tmp
    tmp="$(mktemp)"
    awk -v begin="$BEGIN_MARK" -v end="$END_MARK" '
        $0 == begin { skipping = 1; next }
        $0 == end   { skipping = 0; next }
        !skipping   { print }
    ' "$SSHD_CONFIG" > "$tmp"

    {
        printf '%s\n' "$BEGIN_MARK"
        printf '# 由 scripts/enroll-account.sh 依 registry.toml 生成，勿手工编辑。\n'
        while IFS= read -r username; do
            local port
            port="$(python3 "$REGISTRY_PY" get "$username" | cut -f3)"
            printf 'Match User %s\n    PermitListen 127.0.0.1:%s\n' "$username" "$port"
        done < <(python3 "$REGISTRY_PY" list-usernames)
        printf '%s\n' "$END_MARK"
    } >> "$tmp"

    if ! /usr/sbin/sshd -t -f "$tmp" 2>/dev/null; then
        local err
        err="$(/usr/sbin/sshd -t -f "$tmp" 2>&1 || true)"
        rm -f "$tmp"
        die "生成的配置未通过 sshd -t，已放弃改动：$err" 5
    fi

    if cmp -s "$tmp" "$SSHD_CONFIG"; then
        rm -f "$tmp"
        return 1   # 无变化
    fi
    cat "$tmp" > "$SSHD_CONFIG"
    rm -f "$tmp"
    return 0
}

reload_sshd() {
    # shellcheck disable=SC2086
    $RELOAD_CMD
}
```

创建 `gateway/scripts/enroll-account.sh`：

```bash
#!/bin/bash
# 依 registry.toml 开通一个隧道账号。
# 用法：enroll-account.sh <username>
# 幂等：已存在的用户不会被重建，配置无变化时不 reload。
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_root
[ $# -eq 1 ] || die "用法：$0 <username>" 2
username="$1"

registry_get "$username" > /dev/null

if getent passwd "$username" > /dev/null; then
    printf '用户 %s 已存在，跳过创建。\n' "$username"
else
    useradd --system --shell /usr/sbin/nologin --no-create-home "$username"
    password="$(head -c 18 /dev/urandom | base64 | tr -d '\n')"
    printf '%s:%s\n' "$username" "$password" | chpasswd
    printf '用户 %s 已创建。初始口令: %s\n' "$username" "$password"
    printf '口令只显示这一次，请当面或经既有安全渠道交给现场人员，并要求首次连接后修改。\n'
fi

if rewrite_match_block; then
    reload_sshd
    printf 'sshd-tunnel 配置已更新并 reload。\n'
else
    printf 'sshd-tunnel 配置无变化。\n'
fi
```

创建 `gateway/scripts/revoke-account.sh`：

```bash
#!/bin/bash
# 吊销一个隧道账号：锁口令、移除端口放行、踢掉在线会话。
# 用法：revoke-account.sh <username>
# 注意：本脚本不改 registry.toml，请在吊销后手工删除对应记录。
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_root
[ $# -eq 1 ] || die "用法：$0 <username>" 2
username="$1"

getent passwd "$username" > /dev/null || die "系统里没有用户 $username" 3

passwd -l "$username" > /dev/null
printf '已锁定 %s 的口令。\n' "$username"

if rewrite_match_block; then
    reload_sshd
    printf '已移除端口放行并 reload。\n'
fi

if pkill -u "$username" 2>/dev/null; then
    printf '已踢掉 %s 的在线会话。\n' "$username"
else
    printf '%s 当前没有在线会话。\n' "$username"
fi

printf '请从 registry.toml 中删除 %s 的记录，再次运行 enroll 以对齐配置。\n' "$username"
```

创建 `gateway/scripts/tunnel-status.sh`：

```bash
#!/bin/bash
# 汇总登记表中每个账号的端口与在线状态。
# 输出：<username> <port> <online|offline> <pid|->
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ $# -eq 0 ] || die "用法：$0" 2

while IFS= read -r username; do
    port="$(python3 "$REGISTRY_PY" get "$username" | cut -f3)"
    pid="$(pgrep -u "$username" -n sshd 2>/dev/null || true)"
    if [ -n "$pid" ]; then
        printf '%s %s online %s\n' "$username" "$port" "$pid"
    else
        printf '%s %s offline -\n' "$username" "$port"
    fi
done < <(python3 "$REGISTRY_PY" list-usernames)
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cd gateway && chmod +x scripts/*.sh
cd test-env && docker compose up -d --build gateway
docker compose exec -T gateway bats /gateway/tests/test_scripts.bats
```

预期：8 passed。

- [ ] **Step 5: 提交**

```bash
git add gateway/scripts gateway/tests/test_scripts.bats \
        gateway/test-env/gateway/Dockerfile gateway/test-env/docker-compose.yml
git commit -m "feat(gateway): enroll/revoke/status 运维脚本"
```

---

### Task 8: CI 与运维手册

**Files:**
- Create: `.github/workflows/gateway.yml`
- Create: `gateway/README.md`
- Modify: `docs/方案设计.md`（补 4.2 的三行）

**Interfaces:**
- Consumes: 前七个任务的全部测试
- Produces: CI 工作流 `gateway`，在 push 与 PR 上跑全部 Gateway 测试

- [ ] **Step 1: 写下失败的检查**

`gateway/tests/requirements.txt` 已在 Task 1 Step 3 创建，这里只引用它。

创建 `.github/workflows/gateway.yml`：

```yaml
name: gateway

on:
  push:
    paths: ["gateway/**", ".github/workflows/gateway.yml"]
  pull_request:
    paths: ["gateway/**", ".github/workflows/gateway.yml"]

jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4

      - name: 安装测试依赖
        run: |
          sudo apt-get update
          sudo apt-get install -y openssh-client
          python3 -m venv gateway/.venv
          gateway/.venv/bin/pip install -r gateway/tests/requirements.txt

      - name: 单元测试
        run: cd gateway && .venv/bin/python -m pytest tests/test_registry.py -v

      - name: 集成测试
        run: cd gateway && .venv/bin/python -m pytest tests -v -x --ignore=tests/test_registry.py

      - name: 脚本测试
        run: |
          cd gateway/test-env
          docker compose exec -T gateway bats /gateway/tests/test_scripts.bats

      - name: 失败时导出容器日志
        if: failure()
        run: cd gateway/test-env && docker compose logs --no-color
```

- [ ] **Step 2: 在本地跑一遍 CI 的全部步骤**

```bash
cd gateway && .venv/bin/python -m pytest tests -v
```

预期：全部通过。若 `test_zombie_port.py` 超时，把 CI 的 `timeout-minutes` 调到 30。

- [ ] **Step 3: 写运维手册并回填方案**

创建 `gateway/README.md`：

```markdown
# Maintenance Gateway

远程维护的汇聚点。不含自研服务端程序，由 haproxy 与两个独立的 sshd 实例组成。
设计依据见 `../docs/方案设计.md` 第 4 章。

## 组成

| 端口 | 组件 | 作用 |
|---|---|---|
| 443 | haproxy | 终止 TLS，转给 `127.0.0.1:2222` |
| 127.0.0.1:2222 | sshd-tunnel | 只服务 `tunnel-*` 账号，只允许建立一个 loopback 反向端口 |
| 22 | sshd-engineer | 工程师入口，无 shell，只能跳到 loopback 隧道端口 |

## 部署

```bash
install -m 600 sshd_tunnel_config /etc/ssh/sshd_tunnel_config
install -m 644 sshd_engineer.conf /etc/ssh/sshd_config.d/engineer.conf
install -m 644 haproxy.cfg /etc/haproxy/haproxy.cfg
install -m 644 systemd/sshd-tunnel.service /etc/systemd/system/
ssh-keygen -t ed25519 -N '' -f /etc/ssh/tunnel_host_ed25519_key
# 证书用公共 CA 签发，合成 fullchain+key 放到下面这个路径
install -m 600 gateway.pem /etc/haproxy/certs/gateway.pem
systemctl daemon-reload
systemctl enable --now sshd-tunnel haproxy
systemctl reload ssh
```

记下 `/etc/ssh/tunnel_host_ed25519_key.pub` 的指纹，客户端首次连接时要核对：

```bash
ssh-keygen -lf /etc/ssh/tunnel_host_ed25519_key.pub
```

## 开通账号

1. 在 `registry.toml` 中新增一条 `[[tunnel_account]]`，端口在 22000-22999 内且不与现有记录重复；
2. `python3 scripts/registry.py validate` 校验；
3. `sudo scripts/enroll-account.sh <username>`，把打印出的初始口令交给现场人员；
4. `sudo scripts/tunnel-status.sh` 确认端口已登记。

## 吊销账号

```bash
sudo scripts/revoke-account.sh <username>
# 然后从 registry.toml 删除该记录，再跑一次 enroll 对齐配置
```

## 工程师登录一体机

```bash
ssh -J eng@gateway.company.com -p 22001 \
    -o HostKeyAlias=c0001-a1 \
    root@127.0.0.1
```

口令是该设备的动态 root 口令，从公司内部口令服务按设备编号取。`HostKeyAlias` 用设备编号，避免不同设备复用同一端口时的 host key 变更告警。

## 常见故障

| 现象 | 原因 | 处理 |
|---|---|---|
| 客户端报端口占用 | 上一条隧道静默断开，端口未回收 | 等 30 秒，客户端会自动重试；`tunnel-status.sh` 可看在线状态 |
| 客户端认证失败 | 口令错误或账号被锁 | `passwd -S <username>` 看锁定状态 |
| 工程师连上端口但被拒 | 一体机不可达 | 让现场人员看客户端是否为橙色的一体机不可达 |
| haproxy 起不来 | 证书路径或权限不对 | `haproxy -c -f /etc/haproxy/haproxy.cfg` |

## 本地测试

```bash
python3 -m venv .venv && .venv/bin/pip install -r tests/requirements.txt
cd test-env && docker compose up -d --build
cd .. && .venv/bin/python -m pytest tests -v
```
```

把 Task 2 给 4.2 补的三行回填到方案：在 `docs/方案设计.md` 的 `sshd_tunnel_config` 代码块中 `ListenAddress` 之后加入

```
HostKey /etc/ssh/tunnel_host_ed25519_key
PidFile /run/sshd-tunnel.pid
Subsystem sftp /bin/false
```

并在该节的要点列表末尾补一条：`- 第二个 sshd 实例必须有独立的 host key 与 pid 文件；sftp 子系统指向 /bin/false。`

- [ ] **Step 4: 确认全绿并推分支验证 CI**

```bash
cd gateway && .venv/bin/python -m pytest tests -v
git push -u origin HEAD
gh run watch
```

预期：CI 的 gateway 工作流通过。

- [ ] **Step 5: 提交**

```bash
git add .github/workflows/gateway.yml gateway/README.md docs/方案设计.md
git commit -m "ci(gateway): Gateway 测试工作流与运维手册"
```

---

## 自检

**规格覆盖**

| 方案条目 | 对应任务 |
|---|---|
| 4.1 拓扑 | Task 2、4、5 |
| 4.2 sshd-tunnel 配置与要点 | Task 2、3、6 |
| 4.2 haproxy TLS 终止 | Task 4 |
| 4.3 sshd-engineer 与 ProxyJump | Task 5 |
| 4.4 registry.toml | Task 1 |
| 4.4 enroll / revoke / status | Task 7 |
| 6 新增与吊销流程 | Task 7、8 |
| 8 Gateway 相关用例（僵尸端口、口令错误） | Task 3、6 |
| 7.3 明确不做 pam_faillock 与来源 IP 限速 | 全局约束已列 |

未覆盖且属于本计划范围之外的：一体机侧无改动（方案第 5 章），工程师账号的批量管理（方案 4.4 末句说明单独管理）。

**遗留给客户端计划的接口**

- 客户端测试要复用 `gateway/test-env`，宿主端口约定见 Task 2 的 Interfaces。
- 客户端 known_hosts 的首次记录要核对 `tunnel_host_ed25519_key.pub` 的指纹，获取方式见 `gateway/README.md`。
- haproxy 的 `timeout client/server` 为 1 小时，客户端 keepalive 周期必须远小于它。
