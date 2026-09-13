from conftest import (
    APPLIANCE_PW, HOST, TUNNEL_PORT, TUNNEL_PW, TUNNEL_SSHD, TUNNEL_USER,
    gateway_listen_table, parse_listen_table, reverse_port_registered,
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
