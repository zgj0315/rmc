import subprocess
import tempfile
import time

import pytest

from conftest import (
    APPLIANCE_PW, APPLIANCE_SSHD, HOST, TUNNEL_PORT, TUNNEL_PW, TUNNEL_SSHD,
    TUNNEL_USER, _stop_tunnel, gateway_listen_table, gateway_tunnel_status,
    parse_listen_table, popen_ssh_password, reverse_port_registered,
    run_ssh_password,
)


def test_tunnel_account_authenticates_with_password(harness):
    """认证成功必须有正面证据，不能只断言 stderr 里没有某几个字符串。

    「没有 Permission denied」是假绿的温床：连接被拒、被 reset、超时，或者
    OpenSSH 改了措辞，stderr 里都不会有那两个字符串，用例照样绿。这里的风险是
    真实存在的——wait_port(TUNNEL_SSHD) 连的是 socat 旁路，而 socat 在 2223 上
    照单全收，不管 sshd 到底有没有起来听 2222。

    正面证据用会话本身的输出：账号的 shell 是 nologin、配置里又有
    ForceCommand /bin/false，认证一旦通过、会话一旦建立，nologin 就会打印
    This account is currently not available. 并以 1 退出。这句话只有在认证
    真的过了之后才可能出现，连不上的连接不会有任何 stdout。
    """
    out = run_ssh_password(
        TUNNEL_PW, "-p", str(TUNNEL_SSHD), f"{TUNNEL_USER}@{HOST}", "true")
    assert "This account is currently not available" in out.stdout, (
        f"rc={out.returncode} stdout={out.stdout!r} stderr={out.stderr!r}")
    assert out.returncode == 1, out.stderr


def test_wrong_password_is_rejected(harness):
    out = run_ssh_password(
        "wrong-pw", "-p", str(TUNNEL_SSHD), f"{TUNNEL_USER}@{HOST}", "true")
    assert out.returncode != 0
    assert "Permission denied" in out.stderr


def test_reverse_port_is_registered_on_gateway(tunnel):
    """原名叫 ..._appears_on_gateway_loopback，loopback 已经不成立了。

    用 reverse_port_registered() 而不是 port_listening_in_gateway()：反向端口绑
    在哪个地址上只有那个 helper 知道，这里只关心它注册上了没有。
    """
    assert reverse_port_registered(TUNNEL_PORT), gateway_listen_table()


def test_reverse_port_is_bound_on_a_wildcard_address(tunnel):
    """GatewayPorts yes 必须把反向端口绑到通配地址上，不能留在 loopback。

    这是原先 test_reverse_port_is_not_bound_on_a_wildcard_address 的反面。反向
    端口现在要让公司工程师从互联网直连，绑在 loopback 上就等于谁也连不进来。

    仍然只能进容器查监听表，不能改成「从宿主连 TUNNEL_PORT，连上就算通过」：
    compose 已经把 22001 发布到宿主，docker-proxy 在宿主上一直监听，宿主那一侧
    连得上完全说明不了端口在容器里绑的是哪个地址。

    也别匹配地址字面量的子串（`"0.0.0.0:22001" in table`）：那种写法对 22001
    恰好成立但不可移植，查 222 会命中 `0.0.0.0:2223`。这里走
    parse_listen_table() 的整值比较。

    `ss` 打通配地址有 `0.0.0.0`、`*`、`[::]` 三种拼法，落哪一种取决于容器的
    IPv6 情况，所以只要求三者中至少出现一个；同时明确要求 loopback 那一行不再
    出现，否则「绑到了通配地址」这句话没被真正钉住。
    """
    table = gateway_listen_table()
    entries = parse_listen_table(table)
    bound = [w for w in ("0.0.0.0", "*", "[::]") if (w, TUNNEL_PORT) in entries]
    assert bound, table
    assert (HOST, TUNNEL_PORT) not in entries, table


def test_tunnel_status_reports_online_while_a_real_tunnel_is_up(tunnel):
    """tunnel-status.sh 的 online 分支从来没有真的被命中过一次。

    Task 7 的 bats 套件整套都在容器内跑，从不建立真实的 ssh 会话，所以那边
    十几条用例只验证过 offline 分支的格式——如果 `pgrep -u <user> -n sshd`
    从来不命中任何进程，`tunnel-status.sh` 会把所有账号永远报成 offline，
    而 bats 那边全绿，因为它压根没有能力制造一个在线的会话去戳穿这件事。

    这不是假设的风险：OpenSSH 9.8 起把每个会话的进程名从 `sshd` 改成了
    `sshd-session`，这个仓库现在锁的是 9.2p1（见 `ssh -V`），将来悄悄升级
    基础镜像就会让这个脚本失去 online 检测能力却不报任何错——`pgrep` 找不到
    进程和"没有在线会话"在退出码和输出格式上完全一样。

    `tunnel` 固件建立的是一条真实的、认证过的反向端口连接，此刻 tunnel-zhang
    名下确实有一个 sshd 子进程在服务这个会话，这是全套件唯一能提供这个前提
    的地方，因此这条断言只能放在这里，不能补进 bats。
    """
    out = gateway_tunnel_status()
    lines = {line.split()[0]: line for line in out.splitlines() if line.strip()}
    assert TUNNEL_USER in lines, out
    fields = lines[TUNNEL_USER].split()
    assert fields[:3] == [TUNNEL_USER, str(TUNNEL_PORT), "online"], out
    assert fields[3].isdigit(), out


def test_reverse_request_without_a_bind_address_is_accepted(harness):
    """现场那条 `-R` 不写绑定地址，服务端必须照收——裸端口 PermitListen 的作用。

    现场的隧道命令是 `ssh -R 22001:127.0.0.1:61001 tunnel-zhang@gateway`：只给
    端口，不给绑定地址。OpenSSH 客户端据此请求的监听主机是 "localhost"，而
    `PermitListen` 只做字面比较、不解析也不做模式匹配，所以
    `PermitListen 127.0.0.1:22001` 那种带地址的写法会把这条请求拒掉，服务端记
    `to remote forward to host localhost port 22001, but the request was denied`；
    只有裸端口形式 `PermitListen 22001` 才收。

    这条用例存在的唯一理由，就是让「必须写成裸端口形式」这件事有人盯着：套件里
    另外两条活的反向转发（`tunnel` 固件与 TLS 用例）请求的都是
    `127.0.0.1:22001` 这种带地址的形式，带地址的放行项照收不误；两条 PermitListen
    边界用例请求的是 22002，两种写法都会拒。也就是说，在这条用例之前，把配置
    退回 `PermitListen 127.0.0.1:22001` 整套 53 个用例仍然全绿，而现场的命令已经
    连不上了。

    刻意没有塞进 `tunnel` 固件，也没有改固件里 `-R` 的写法：固件里的失败会以
    fixture ERROR 的形式炸成一片，而不是某一条用例红着说出坏掉的是哪条性质；
    Task 6 紧接着也要用这个固件，这么晚改共享行为会一次动到四个任务的测试。
    新加一条用例只做加法。

    失败路径必须报得出来：常驻 ssh 的输出接临时文件而不是管道（没人读的管道写满
    会把 ssh 卡死，进程还活着时也读不出已有内容），并且每轮先看 `proc.poll()`
    ——请求被拒时 `ExitOnForwardFailure=yes` 会让 ssh 立刻退出，这一条就直接
    带着 `remote port forwarding failed` 报红，不用等满 20 秒。
    """
    log = tempfile.TemporaryFile()
    proc = popen_ssh_password(
        TUNNEL_PW, "-N", "-T", "-p", str(TUNNEL_SSHD),
        "-o", "ExitOnForwardFailure=yes",
        # 不写绑定地址，与现场命令的形状一致；-R 的目标地址仍由宿主上的 ssh
        # 客户端解析，所以只能写一体机已发布到宿主的端口。
        "-R", f"{TUNNEL_PORT}:{HOST}:{APPLIANCE_SSHD}",
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
                    f"不带绑定地址的 -R 请求被拒或隧道提前退出"
                    f"（退出码 {proc.returncode}）：{output()}")
            if reverse_port_registered(TUNNEL_PORT):
                break
            time.sleep(0.5)
        else:
            pytest.fail(
                f"不带绑定地址的 -R 请求没能把反向端口 {TUNNEL_PORT} 注册上；"
                f"ssh 输出：{output()}")
    finally:
        try:
            _stop_tunnel(proc)
        finally:
            log.close()


def test_engineer_connects_to_appliance_directly(tunnel):
    """工程师一条命令直连：没有 -J，没有跳板，也没有 Gateway 账号。

    生产上这条命令是 `ssh -p 22001 root@gateway.company.com`。测试里 Gateway
    容器的 22001 由 compose 发布到宿主的同一个端口，所以只把主机名换成
    127.0.0.1，端口与认证方式都与现场一致：口令就是一体机的动态 root 口令。
    """
    out = run_ssh_password(
        APPLIANCE_PW,
        "-p", str(TUNNEL_PORT), f"root@{HOST}", "cat /etc/appliance-id",
        timeout=40,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "c0001-a1"
