from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import shlex
import socket
import ssl
import subprocess
import tempfile
import threading
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
HAPROXY = 8443
APPLIANCE_SSHD = 2322

# 口令认证用的公共选项。限定 password 一种认证方式、只允许一次口令提示，
# 免得失败时 ssh 反复重试或退回其他方式，让断言的含义变模糊。
SSH_COMMON = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "PreferredAuthentications=password",
    "-o", "NumberOfPasswordPrompts=1",
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


# `ss -ltn` 与 `openssl x509` 都是秒回的命令，20 秒都算宽松。
_LISTEN_TABLE_TIMEOUT = 20.0
_CERT_FETCH_TIMEOUT = 20.0


def _compose_capture(*cmd: str, timeout: float, purpose: str) -> str:
    """跑一条限时的 `docker compose` 子命令，把输出原样捕获返回。

    `gateway_listen_table()` 与 `gateway_tls_cert_pem()` 都要「秒回的容器内
    命令，超时或非零退出码都必须把 docker 真正的输出带出来，不能吞掉」——
    第三次抄这段逻辑就不该再抄，收进这一个函数里。`purpose` 只进错误文案
    （例如「取 gateway 监听表」「取 gateway 证书」），不影响命令本身。
    """
    try:
        out = compose(*cmd, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"{purpose}超时：docker compose {' '.join(cmd)} "
            f"超过 {timeout} 秒没有返回"
        ) from exc
    if out.returncode != 0:
        raise RuntimeError(
            f"{purpose}失败，docker compose exec 退出码 {out.returncode}\n"
            f"--- stdout ---\n{out.stdout}\n--- stderr ---\n{out.stderr}"
        )
    return out.stdout


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
    return _compose_capture(
        "exec", "-T", "gateway", "ss", "-ltn",
        timeout=_LISTEN_TABLE_TIMEOUT, purpose="取 gateway 监听表",
    )


def parse_listen_table(text: str) -> set[tuple[str, int]]:
    """把 `ss -ltn` 的输出解析成 `{(地址, 端口)}` 集合，端口是 int。

    纯函数，不碰 docker，所以能用固定样本做单元测试（见 test_listen_table.py）。
    查监听端口必须走这里的整值比较，别退回在整张表上做子串匹配——这个 helper
    因为同一个结构性原因错过两次：子串查端口 22 会命中 `127.0.0.1:2222` 那一行，
    查 999 会命中 `127.0.0.1:9999`，于是调用方会拿到一个根本不存在的监听端口，
    让用例在什么都没验证的情况下变绿。Task 4 要查 443，正是这类短端口号。

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

    `address` 默认 loopback。要断言某端口绑在通配地址上（Task 4 的 443），传
    `address="0.0.0.0"` / `"*"` / `"[::]"`，而不要去匹配地址字面量的子串。

    `table` 给单元测试用：传入一段固定的 `ss` 文本就直接解析它，不去容器取表。
    两个真实 bug 都出在这个函数身上（而不是 parse_listen_table 里），所以它必须
    能脱离 docker 被覆盖——否则谁把这里改回 `f"{address}:{port}" in ...`，
    十几个解析器用例还会全绿。见 test_listen_table.py。
    """
    if table is None:
        table = gateway_listen_table()
    return (address, port) in parse_listen_table(table)


# 反向端口的绑定地址。GatewayPorts yes 强制通配绑定，`ss` 把 IPv4 通配打成
# 0.0.0.0；`*` 与 `[::]` 是同一件事的另外两种拼法，一并认。
# 反向端口绑在哪个地址上，整个测试套件里只有这一处知道。方案 7.3 推后的加固要
# 把这些端口从公网挪到内网网卡时，改的是这个常量与下面那个函数，不是每个调用点。
REVERSE_BIND_ADDRS = ("0.0.0.0", "*", "[::]")


def reverse_port_registered(port: int, *, table: str | None = None) -> bool:
    """Gateway 上是否已经注册了反向端口 `port`。

    查反向端口一律走这里，别直接调 port_listening_in_gateway()：后者是通用原语，
    默认地址是 loopback，而反向端口在 GatewayPorts yes 之下绑的是通配地址，用它
    的默认值去问恒为假。Task 4 的 TLS 用例与 Task 6 的回收用例也都走这个函数，
    不必各自把 "0.0.0.0" 抄一遍。

    `table` 原样透给 port_listening_in_gateway()，给不起容器的单测注入固定的
    `ss` 文本用；为 None 时只取一次监听表，三种拼法在同一张表上比对。
    """
    if table is None:
        table = gateway_listen_table()
    return any(port_listening_in_gateway(port, address=addr, table=table)
               for addr in REVERSE_BIND_ADDRS)


@pytest.fixture(scope="session")
def harness():
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
        if not reverse_port_registered(TUNNEL_PORT):
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
            if reverse_port_registered(TUNNEL_PORT):
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
            # 还在飞的每连接 _handle（以及它内部 gather 出来的 _pump 子任务）
            # 在这里主动取消并收尾，不然 loop.close() 会把它们晾在「pending」
            # 状态上，asyncio 在垃圾回收时报 "Task was destroyed but it is
            # pending!"。return_exceptions=True 把 cancel() 引发的
            # CancelledError 收进结果列表，不让它从这里再抛出去。
            current = asyncio.current_task()
            pending = [t for t in asyncio.all_tasks() if t is not current]
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

        # 收尾的三步必须无论如何都跑完：_close() 或它的 result(timeout=10)
        # 一旦抛出，若不用 try/finally 包住后面几步，stop()/join()/close() 会被
        # 跳过，daemon 线程会带着 run_forever() 陪到整个会话结束。
        # join 超时的分支单独处理：这时 loop 仍在跑，loop.close() 会抛
        # "Cannot close a running event loop"，那是一条误导性的第二异常，
        # 不能盖过原始错误——所以只在线程真正停下之后才关 loop。
        error: Exception | None = None
        try:
            asyncio.run_coroutine_threadsafe(_close(), self._loop).result(timeout=10)
        except Exception as exc:
            error = exc
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=10)
            if not self._thread.is_alive():
                self._loop.close()
            elif error is None:
                error = RuntimeError(
                    "TLS 中继的事件循环线程在 10 秒内没有停下，"
                    "已跳过 loop.close() 以避免遮盖这个超时"
                )
        if error is not None:
            raise error


@pytest.fixture
def tls_wrap(harness):
    """yield 宿主上的一个明文端口，写进去的字节会裹进 TLS 送到 haproxy 的 443。"""
    relay = _TlsRelay(HOST, HAPROXY, "gateway.test")
    port = relay.start()
    try:
        yield port
    finally:
        relay.stop()


@pytest.fixture(scope="session")
def gateway_tls_cert_pem(harness) -> str:
    """Gateway 自签证书的 PEM 文本（不含私钥），现取自正在跑的容器。

    证书是自签的，正好拿它自己当信任锚去做一次真正校验的握手：
    `/etc/haproxy/certs/gateway.pem` 是证书和私钥拼在一起的一份文件，
    `openssl x509 -in` 只认 `-----BEGIN CERTIFICATE-----` 那一段，
    私钥不会被读出来、更不会流出容器。

    session 作用域：每次跑测试只问容器要一次。镜像重建会重新生成证书，
    这里现取而不是把证书内容抄进代码里，测试就不会钉死在某个指纹上。
    """
    return _compose_capture(
        "exec", "-T", "gateway", "openssl", "x509",
        "-in", "/etc/haproxy/certs/gateway.pem",
        timeout=_CERT_FETCH_TIMEOUT, purpose="取 gateway 证书",
    )
