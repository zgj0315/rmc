import socket
import subprocess
import tempfile

import pytest

from conftest import (
    APPLIANCE_SSHD, HOST, TUNNEL_PW, TUNNEL_SSHD, TUNNEL_USER,
    compose, popen_ssh_password, run_sftp_password, run_ssh_password, wait_port,
)


def test_no_shell_and_no_command_execution(harness):
    """ForceCommand /bin/false 必须挡掉客户端指定的命令。

    正面证据：账号 shell 是 nologin，认证一过、会话一建立，nologin 就会打印
    `This account is currently not available.` 并以 1 退出（同 test_tunnel.py 里
    `test_tunnel_account_authenticates_with_password` 的证据）。这句话只有认证
    真的成功之后才可能出现；如果只断言 stdout 里没有 "uid="、returncode != 0，
    连接失败（错口令、连不上）也会让两条断言一起成立，测试就成了假绿。
    """
    out = run_ssh_password(TUNNEL_PW, "-p", str(TUNNEL_SSHD),
                           f"{TUNNEL_USER}@{HOST}", "id")
    assert "This account is currently not available" in out.stdout, (
        f"rc={out.returncode} stdout={out.stdout!r} stderr={out.stderr!r}")
    assert out.returncode != 0
    assert "uid=" not in out.stdout


def test_no_pty(harness):
    out = run_ssh_password(TUNNEL_PW, "-tt", "-p", str(TUNNEL_SSHD),
                           f"{TUNNEL_USER}@{HOST}")
    assert out.returncode != 0
    assert "PTY allocation request failed" in out.stderr


def test_local_forwarding_is_refused(harness):
    """AllowTcpForwarding remote（连同 PermitOpen none）必须禁掉 -L。

    按原样只跑 `ssh -N -T -L ...` 会挂到超时：`-L` 的本地监听由客户端自己在
    本机绑定，这一步永远成功，跟服务端毫无关系；服务端只在真的有连接穿过隧道、
    客户端据此发出 direct-tcpip 通道请求时才会检查 AllowTcpForwarding /
    PermitOpen 并拒绝。`ExitOnForwardFailure=yes` 只覆盖「绑监听失败」这一种
    情况，管不到「通道被服务端拒」，所以光起转发不去用它，进程会一直挂着——
    这正是最初一次运行时两个用例超时的原因。这里改成把 ssh 起成后台进程，
    等本地端口真的开始监听后主动往里连一次，用这次连接触发服务端的拒绝，
    再从常驻进程的日志里读拒绝原因。

    `data == b""`（连接被直接关掉、读不到任何转发数据）是结构性的证据：只要
    服务端拒绝了通道，无论遣词造句如何，客户端都不可能把数据转发过来。
    `"administratively prohibited"` 才是真正定位到具体原因的断言——已经实测：
    只放开 AllowTcpForwarding（改成 all）而不动 PermitOpen，仍然是这行报错；
    两边都放开后，服务端才会真的去连目标，之后要么转发成功、要么因为目标
    不可达报 "connect failed"，都不会再是 "administratively prohibited"。
    """
    log = tempfile.TemporaryFile()
    proc = popen_ssh_password(
        TUNNEL_PW, "-N", "-T", "-p", str(TUNNEL_SSHD),
        "-o", "ExitOnForwardFailure=yes",
        "-L", "127.0.0.1:19099:appliance:61001",
        f"{TUNNEL_USER}@{HOST}",
        stdout=log, stderr=subprocess.STDOUT,
    )
    try:
        wait_port(19099, timeout=15)
        with socket.create_connection(("127.0.0.1", 19099), timeout=5) as sock:
            data = sock.recv(4096)
        assert data == b"", f"预期通道被服务端拒绝、读不到数据，却收到了 {data!r}"
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        log.seek(0)
        output = log.read().decode("utf-8", "replace")
        log.close()
    assert "administratively prohibited" in output, output


def test_reverse_port_outside_permitlisten_is_refused(harness):
    """裸端口形式的 `PermitListen 22001` 只放行 22001 这一个端口，别的必须被拒。

    地址部分已不再受限（`GatewayPorts yes` 强制通配绑定），所以本用例只管端口，
    不对绑定地址作任何断言。
    """
    # -R 的目标地址由跑在宿主上的 ssh 客户端解析，宿主不在 compose 网络里，
    # 所以只能写一体机已发布到宿主的端口，不能写 compose 服务名。
    out = run_ssh_password(TUNNEL_PW, "-N", "-T", "-p", str(TUNNEL_SSHD),
                           "-o", "ExitOnForwardFailure=yes",
                           "-R", f"127.0.0.1:22002:{HOST}:{APPLIANCE_SSHD}",
                           f"{TUNNEL_USER}@{HOST}")
    assert out.returncode != 0
    assert "remote port forwarding failed" in out.stderr.lower()


def test_reverse_port_outside_permitlisten_is_refused_on_a_wildcard_address_too(harness):
    """换个绑定地址也绕不过端口限制。

    这个用例原先断言的是「客户端传 0.0.0.0 就被拦住」，那条性质已经作废：
    反向端口现在就是要绑通配地址。它守的改成端口那一半——`PermitListen` 钉住的
    是端口，不是地址，所以换成通配地址请求一个未放行的端口，照样必须被拒。
    """
    # 同上：-R 的目标地址由宿主的 ssh 客户端解析，不能写 compose 服务名。
    out = run_ssh_password(TUNNEL_PW, "-N", "-T", "-p", str(TUNNEL_SSHD),
                           "-o", "ExitOnForwardFailure=yes",
                           "-R", f"0.0.0.0:22002:{HOST}:{APPLIANCE_SSHD}",
                           f"{TUNNEL_USER}@{HOST}")
    assert out.returncode != 0
    assert "remote port forwarding failed" in out.stderr.lower()


def test_sftp_subsystem_is_unavailable(harness):
    """sftp 子系统必须不可用。

    只断言 returncode != 0 分不清「认证根本没过」和「认证过了、sftp 被挡」——
    错口令走 sftp 一样会以非零退出。已实测两者的 stderr 完全不同：错口令是
    `Permission denied (password).`；账号真的认证成功、但子系统被顶到
    `/bin/false` 时，sftp 客户端收不到合法的协议握手，报的是
    `Received message too long ...`。断言这条特征文本，才是「认证过了、
    子系统被挡」的正面证据。

    另外实测发现：这条防线其实有两层——就算删掉 `Subsystem sftp /bin/false`
    这一行，未声明的子系统请求会被 sshd 直接拒绝（"subsystem request failed"）；
    就算把它换成真正的 `/usr/lib/openssh/sftp-server`，顶层的
    `ForceCommand /bin/false` 也会覆盖掉子系统执行，报的还是这同一条
    "Received message too long"。两层里删掉任何一层单独都不会让 sftp 变得可用，
    所以这个用例事实上同时钉住了 ForceCommand 与 Subsystem 两处配置的组合效果。
    """
    out = run_sftp_password(TUNNEL_PW, "-P", str(TUNNEL_SSHD),
                            f"{TUNNEL_USER}@{HOST}")
    assert out.returncode != 0
    assert "Permission denied" not in out.stderr, out.stderr
    assert "Received message too long" in out.stderr, out.stderr


def test_agent_forwarding_is_refused(harness):
    """AllowAgentForwarding no 必须生效——但这条在客户端这边完全看不出来。

    已实测：`-A` 发出的 auth-agent-req@openssh.com 通道请求，OpenSSH 客户端
    发送时 confirm=0（协议里就是 fire-and-forget），服务端准不准都不回任何东西，
    `ssh -vvv` 的日志里也只看得到「Requesting agent forwarding」，看不到任何
    成功/失败的回执。账号又挂着 ForceCommand /bin/false、shell 是 nologin，
    没有远端 shell 能拿来检查转发出来的 agent socket 到底能不能用。原
    Step 1 里 `-A -N -T` 的写法还有另一个问题：`-N` 根本不打开 session 通道，
    agent forwarding 请求依附在 session 通道上发出，于是连请求都不会发，
    ssh 只会一直空等到超时（实测复现）。

    这条限制因此在「连接层面」不可观测，只能问 sshd 自己怎么解析配置：
    `sshd -T -C user=...` 把 Match 块解析完之后，这个账号连接时会实际生效的
    选项打出来，这正是 sshd 在真实连接里做判断时查的同一份结果。已用删除
    `AllowAgentForwarding no` 这一行做过对照：删掉后 `sshd -T` 输出从
    `allowagentforwarding no` 变成默认的 `allowagentforwarding yes`，
    证明这条断言确实钉住了这一行配置。
    """
    out = compose("exec", "-T", "gateway", "sshd", "-T",
                  "-f", "/etc/ssh/sshd_tunnel_config",
                  "-C", f"user={TUNNEL_USER},host=test,addr=127.0.0.1",
                  check=False, timeout=20)
    assert out.returncode == 0, f"sshd -T 失败：{out.stderr}"
    assert "allowagentforwarding no" in out.stdout.lower(), out.stdout


def test_pubkey_auth_is_disabled(harness):
    """PubkeyAuthentication no 必须生效。

    只断言「有 Permission denied」区分不了「pubkey 被服务端整体禁用」和
    「pubkey 本来就允许、只是没有一把授权过的公钥可用」——tunnel-zhang 根本
    没有配置 authorized_keys，即便服务端允许 pubkey，客户端手上现成的公钥
    也不会通过，一样会以 "Permission denied" 收场，这条断言原样不会因为删掉
    `PubkeyAuthentication no` 而变红。

    已实测两种场景的 stderr 有明确区别：对 engineer 的 sshd（默认允许
    pubkey）用同样的选项连接，服务端会先答复
    "Authentications that can continue: publickey"，client 拿出私钥去试、
    失败后报 "Permission denied (publickey)."；对 tunnel 的 sshd，服务端从
    一开始就只答复 "Authentications that can continue: password"（pubkey
    从未被列为可继续的方法），最终报的是 "Permission denied (password)."——
    这个「password」后缀就是服务端压根没把 pubkey 当一种可用认证方式的
    直接证据，删掉 `PubkeyAuthentication no` 这一行会让它变回
    "(publickey)"，断言即会失败。
    """
    out = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "PreferredAuthentications=publickey",
         "-o", "ConnectTimeout=10",
         "-p", str(TUNNEL_SSHD), f"{TUNNEL_USER}@{HOST}"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=25,
    )
    assert out.returncode != 0
    assert "Permission denied (password)." in out.stderr, out.stderr


@pytest.fixture(scope="module")
def tunnel_effective_config(harness):
    """tunnel-zhang 在这份配置下、sshd 自己解析出来的有效配置（转小写后整段返回）。

    跟 test_agent_forwarding_is_refused 用的是同一个查法：带 `-C user=...` 让
    Match 块真的被解析，输出反映的是账号连接时 sshd 实际会查到的值，而不是
    源文件里的原始文本。
    """
    out = compose("exec", "-T", "gateway", "sshd", "-T",
                  "-f", "/etc/ssh/sshd_tunnel_config",
                  "-C", f"user={TUNNEL_USER},host=test,addr=127.0.0.1",
                  check=False, timeout=20)
    assert out.returncode == 0, f"sshd -T 失败：{out.stderr}"
    return out.stdout.lower()


# 下面这张表钉住的都是「行为测试测的是端到端可观察结果，而不是某一行配置」
# 暴露出来的盲区：两组指令里任何一条单独被删掉，对应的行为测试都不会变红，
# 因为另一层还在，端到端现象（refuse 的具体文本）完全没变——已经逐条用
# sshd -T 实测过删除效果（见 task-3-report.md），确认这四条各自单独删掉时
# effective config 都会变成默认值，因而都会让下面的断言真的变红：
#
# - sftp：`Subsystem sftp /bin/false` 与顶层 `ForceCommand /bin/false` 二选一
#   在场，test_sftp_subsystem_is_unavailable 报的都是同一句
#   "Received message too long"；只删 Subsystem 那一行，未声明的子系统请求会被
#   sshd 直接拒绝（"subsystem request failed"，行为测试的断言依然会因为文本
#   变了而失败，但那是巧合，不是这条测试在把关）；只删 ForceCommand、换成真正
#   的 sftp-server，sftp 会变得可用，行为测试才会失败。也就是说光靠行为测试，
#   删掉 Subsystem 这一行本身完全可能被巧合地接住，删掉 ForceCommand 这一行
#   则接不住（因为 test_no_shell_and_no_command_execution 会先接住它——但那是
#   另一个测试在关另一件事，不是这条测试的问题）。
# - 本地转发：`AllowTcpForwarding remote` 与 `PermitOpen none` 二选一在场，
#   test_local_forwarding_is_refused 报的都是同一句 "administratively
#   prohibited"；只放宽其中一条、留着另一条，实测过报错文本完全不变，行为
#   测试会继续通过，看不出少了一层。
#
# `nologin` 登录 shell（test_no_shell_and_no_command_execution 的另一层保险）
# 不在这张表里：那是测试环境建账号时给的 `--shell /usr/sbin/nologin`
# （见 test-env/gateway/entrypoint.sh），不是 sshd_tunnel_config 里的指令，
# `sshd -T` 查不到，也不归这份配置管。
_LAYERED_DIRECTIVES = [
    pytest.param("forcecommand /bin/false", id="ForceCommand"),
    pytest.param("subsystem sftp /bin/false", id="Subsystem-sftp"),
    pytest.param("allowtcpforwarding remote", id="AllowTcpForwarding"),
    pytest.param("permitopen none", id="PermitOpen"),
]


@pytest.mark.parametrize("expected_line", _LAYERED_DIRECTIVES)
def test_layered_directive_is_still_individually_in_effect(
        tunnel_effective_config, expected_line):
    """防止「删掉双重保险里的一层，因为另一层还在、行为测试仍然全绿」的静默退化。

    这条测试跟上面的行为测试做的是不同的事：行为测试证明边界端到端仍然挡得住，
    这条测试证明挡住它的每一层配置本身还都在——两者都要，缺一个都会漏掉一种
    退化路径。谁把这张表里的某一行从 sshd_tunnel_config 删掉，行为测试可能因为
    另一层backstop（或者别的测试碰巧接住）而继续全绿，这条测试会先变红，
    而且失败信息直接就是「哪一条指令没了」，不用像行为测试那样先去猜是不是
    connection 层面出了别的问题。
    """
    assert expected_line in tunnel_effective_config, tunnel_effective_config
