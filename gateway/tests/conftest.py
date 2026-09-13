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


def gateway_listen_table() -> str:
    """Gateway 容器里 `ss -ltn` 的原始输出。

    断言监听地址的用例都从这里取表，失败时把整张表贴进断言消息，才看得出
    端口到底绑在哪个地址上。
    """
    return compose("exec", "-T", "gateway", "ss", "-ltn", check=False).stdout


def port_listening_in_gateway(port: int) -> bool:
    """Gateway 容器里是否有监听套接字精确绑在 `127.0.0.1:<port>` 上。

    必须逐行解析、把 Local Address:Port 整列当一个值来比，不能在整张表上做子串
    匹配。具体的坑：子串查端口 22 会命中 `127.0.0.1:2222` 那一行，于是这个
    helper 会报告一个根本不存在的监听端口，让调用它的用例在什么都没验证的情况
    下变绿。Task 3 到 7 共用这个 helper，443 与 22 这类短端口号都会被查到，所以
    别把它简化回 `in` 匹配。
    """
    want = str(port)
    for line in gateway_listen_table().splitlines():
        fields = line.split()
        # ss 的列：State / Recv-Q / Send-Q / Local Address:Port / Peer Address:Port。
        # 表头与任何解析不出地址的行一律跳过，不让它抛异常。
        if len(fields) < 4:
            continue
        addr, sep, listen_port = fields[3].rpartition(":")
        if not sep:
            continue
        if addr == HOST and listen_port == want:
            return True
    return False


def ensure_engineer_keypair() -> None:
    """缺失时生成工程师测试密钥。

    私钥不入库，所以新 clone 出来的仓库里 engineer-keys/ 是空的。必须在
    compose 起容器之前生成：compose 把这个目录挂进 gateway 容器，
    entrypoint 要从里面读 authorized_keys。
    """
    if ENG_KEY.exists():
        return
    ENG_KEY.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(ENG_KEY)],
        check=True, capture_output=True, text=True,
    )
    (ENG_KEY.parent / "authorized_keys").write_bytes(
        ENG_KEY.with_suffix(".pub").read_bytes())


@pytest.fixture(scope="session")
def harness():
    ensure_engineer_keypair()
    compose("down", "-v", check=False)
    # 不用 check=True：它与 capture_output=True 一起会把构建失败变成一个不带
    # 输出的 CalledProcessError，docker 真正的报错完全看不到。Task 3 到 7 都
    # 依赖这个固件，这里必须把 docker 的 stdout/stderr 原样抛出来。
    up = compose("up", "-d", "--build", check=False)
    if up.returncode != 0:
        raise RuntimeError(
            f"docker compose up 失败，退出码 {up.returncode}\n"
            f"--- stdout ---\n{up.stdout}\n--- stderr ---\n{up.stderr}"
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
