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


def popen_ssh_password(password: str, *args: str, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE) -> subprocess.Popen:
    """起一条常驻的口令认证 ssh（例如 -N -T 的隧道），收尾由调用方负责。

    默认把输出接到管道，适合马上就会退出的短命进程。要长期留着的进程请改接
    临时文件（见 tunnel 固件）：没人读的管道写满缓冲区会把 ssh 卡死，而且进程
    还活着时也读不出里面已有的内容，失败信息就报不出来。
    """
    return subprocess.Popen(
        ["ssh", *SSH_COMMON, *args],
        env=askpass_env(password), stdin=subprocess.DEVNULL,
        stdout=stdout, stderr=stderr, text=True,
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
    # ENG_COMMON 要拼成一条由 shell 解析的命令行，逐项 shlex.quote：
    # 私钥路径里只要有空格（仓库被 clone 到带空格的目录下），不加引号就会被拆开。
    opts = " ".join(shlex.quote(item) for item in ENG_COMMON)
    return ["-o", "ProxyCommand=ssh {} -W %h:%p -p {} eng@{}".format(
        opts, ENGINEER_SSHD, HOST)]


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


def compose(*args: str, check: bool = True,
            timeout: float | None = None) -> subprocess.CompletedProcess:
    """跑一条 docker compose 子命令。

    `timeout` 默认 None，也就是不限时——`compose("up", "-d", "--build")` 动辄几分钟，
    统一加上限会把构建杀掉。要限时的是那些本该秒回的调用，由调用方自己指定
    （见 gateway_listen_table）。
    """
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=ENV_DIR, check=check, capture_output=True, text=True, timeout=timeout,
    )


# `ss -ltn` 是秒回的命令，20 秒足够宽松。
_LISTEN_TABLE_TIMEOUT = 20.0


def gateway_listen_table() -> str:
    """Gateway 容器里 `ss -ltn` 的原始输出。

    断言监听地址的用例都从这里取表，失败时把整张表贴进断言消息，才看得出
    端口到底绑在哪个地址上。

    `docker compose exec` 失败时必须抛出来，不能把返回码和 stderr 丢掉后交回
    一张空表：空表会让 tunnel 固件白等二十秒，最后报一句「反向端口未出现」，
    把 docker 的问题伪装成 sshd 的问题。

    这里也是整个取表路径上唯一该限时的地方。`compose()` 默认不限时（构建要几分钟），
    但本函数被 tunnel 固件的启动等待、收尾轮询以及 Task 3 到 6 的每次端口查询反复调用；
    一旦某次 `docker compose exec` 卡住，没有超时就会永远挂着——`_stop_tunnel` 的
    15 秒期限只在两次调用之间判定，进不到下一轮就永远判不到，venv 里也没有
    pytest-timeout 从外面兜。两层守卫分工不同：这里的单次超时管一次卡死的调用，
    那边的循环期限管一连串飞快返回却始终不满足条件的调用。
    """
    cmd = ("exec", "-T", "gateway", "ss", "-ltn")
    try:
        out = compose(*cmd, check=False, timeout=_LISTEN_TABLE_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"取 gateway 监听表超时：docker compose {' '.join(cmd)} "
            f"超过 {_LISTEN_TABLE_TIMEOUT} 秒没有返回"
        ) from exc
    if out.returncode != 0:
        raise RuntimeError(
            f"取 gateway 监听表失败，docker compose exec 退出码 {out.returncode}\n"
            f"--- stdout ---\n{out.stdout}\n--- stderr ---\n{out.stderr}"
        )
    return out.stdout


def parse_listen_table(text: str) -> set[tuple[str, int]]:
    """把 `ss -ltn` 的输出解析成 `{(地址, 端口)}` 集合，端口是 int。

    纯函数，不碰 docker，所以能用固定样本做单元测试（见 test_listen_table.py）。
    查监听端口必须走这里的整值比较，别退回在整张表上做子串匹配——这个 helper
    因为同一个结构性原因错过两次：子串查端口 22 会命中 `127.0.0.1:2222` 那一行，
    查 999 会命中 `127.0.0.1:9999`，于是调用方会拿到一个根本不存在的监听端口，
    让用例在什么都没验证的情况下变绿。Task 4 要查 443、Task 5 要动 22，正是这类
    短端口号。

    地址按 `ss` 打印的原样保留，包括 IPv6 的方括号（`[::]`）与通配的 `*`；
    IPv6 地址自带冒号，所以端口从最后一个冒号切开。表头与任何解析不出地址的行
    一律跳过，不抛异常。
    """
    entries: set[tuple[str, int]] = set()
    for line in text.splitlines():
        fields = line.split()
        # ss 的列：State / Recv-Q / Send-Q / Local Address:Port / Peer Address:Port。
        if len(fields) < 4:
            continue
        addr, sep, port = fields[3].rpartition(":")
        if not sep or not addr:
            continue
        try:
            entries.add((addr, int(port)))
        except ValueError:
            continue
    return entries


def port_listening_in_gateway(port: int, address: str = HOST, *,
                              table: str | None = None) -> bool:
    """Gateway 容器里是否有监听套接字精确绑在 `address:port` 上。

    `address` 默认 loopback。要断言某端口绑在通配地址上（Task 4 的 443、
    Task 5 的 22），传 `address="0.0.0.0"` / `"*"` / `"[::]"`，而不要去匹配
    地址字面量的子串。

    `table` 给单元测试用：传入一段固定的 `ss` 文本就直接解析它，不去容器取表。
    两个真实 bug 都出在这个函数身上（而不是 parse_listen_table 里），所以它必须
    能脱离 docker 被覆盖——否则谁把这里改回 `f"{address}:{port}" in ...`，
    十几个解析器用例还会全绿。见 test_listen_table.py。
    """
    if table is None:
        table = gateway_listen_table()
    return (address, port) in parse_listen_table(table)


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


def _stop_tunnel(proc: subprocess.Popen) -> None:
    """收掉隧道进程，并等 Gateway 上的反向端口真的消失。

    wait 必须带兜底：TimeoutExpired 从 finally 里抛出去，会留下一个还活着的 ssh
    占着 TUNNEL_PORT，而下一个 tunnel 用 ExitOnForwardFailure=yes 连同一个端口，
    于是后面每个用例都被毒到。

    客户端退出也不等于 sshd 立刻释放监听。Task 6 要测反向端口的回收时延，
    连着跑的用例之间必须等端口消失再返回，否则会互相干扰。
    """
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
    deadline = time.time() + 15
    while time.time() < deadline:
        if not port_listening_in_gateway(TUNNEL_PORT):
            return
        time.sleep(0.5)
    raise RuntimeError(
        f"隧道进程已退出，但反向端口 {TUNNEL_PORT} 仍留在 Gateway 上；"
        f"后续用例会被它干扰"
    )


@pytest.fixture
def tunnel(harness):
    """以 tunnel-zhang 建立反向端口，yield 期间隧道在线。"""
    # 输出写临时文件而不是管道：常驻的 ssh 没人读管道，写满就卡死；而且用文件
    # 才能在进程还活着时把 stderr 读出来，「端口没出现」那条失败路径才报得出原因。
    log = tempfile.TemporaryFile()
    proc = popen_ssh_password(
        TUNNEL_PW,
        "-N", "-T",
        "-p", str(TUNNEL_SSHD),
        "-o", "ExitOnForwardFailure=yes",
        # -R 的目标地址由跑在宿主上的 ssh 客户端解析，宿主不在 compose 网络里，
        # 所以这里只能写一体机已发布到宿主的端口，不能写 compose 服务名。
        "-R", f"127.0.0.1:{TUNNEL_PORT}:{HOST}:{APPLIANCE_SSHD}",
        f"{TUNNEL_USER}@{HOST}",
        stdout=log, stderr=subprocess.STDOUT,
    )

    def output() -> str:
        log.seek(0)
        return log.read().decode("utf-8", "replace").strip()

    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            if proc.poll() is not None:
                pytest.fail(
                    f"隧道进程提前退出（退出码 {proc.returncode}）：{output()}")
            if port_listening_in_gateway(TUNNEL_PORT):
                break
            time.sleep(0.5)
        else:
            pytest.fail(
                f"反向端口 {TUNNEL_PORT} 未在 Gateway 上出现；ssh 输出：{output()}")
        yield proc
    finally:
        try:
            _stop_tunnel(proc)
        finally:
            log.close()
