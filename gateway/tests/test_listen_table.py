"""`parse_listen_table()` 与 `port_listening_in_gateway()` 的单元测试。

这个文件刻意不用 harness 固件、不碰 docker：解析 `ss` 输出与比对端口是纯字符串
逻辑，而它正是出过两次错的地方。能在不起容器的前提下跑，改动这段逻辑时才能秒级
发现回归。样本取自 gateway 容器里 `ss -ltn` 的真实输出（列对齐按原样保留）。

注意两组用例的分工：`parse_*` 覆盖解析，`test_lookup_*` 覆盖
`port_listening_in_gateway()` 本身——两个真实 bug 都出在后者，只测解析器的话，
谁把它改回 `f"{address}:{port}" in table` 也不会有任何用例变红。
"""

from conftest import parse_listen_table, port_listening_in_gateway

# gateway 容器实际的 `ss -ltn` 输出。最后一行的 `*:8080` 是手工补的：
# port_listening_in_gateway() 的 docstring 向 Task 4 / Task 5 宣传了
# address="*" 这种写法，得有用例把这个拼法钉住。
SAMPLE = """\
State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
LISTEN 0      5            0.0.0.0:2223       0.0.0.0:*
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*
LISTEN 0      4096      127.0.0.11:39375      0.0.0.0:*
LISTEN 0      4096       127.0.0.1:9999       0.0.0.0:*
LISTEN 0      128        127.0.0.1:2222       0.0.0.0:*
LISTEN 0      128             [::]:22            [::]:*
LISTEN 0      128                *:8080             *:*
"""

MALFORMED = """\
State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
LISTEN 0      128        127.0.0.1:2222       0.0.0.0:*
LISTEN 0      128
LISTEN 0      128      no-colon-at-all        0.0.0.0:*
LISTEN 0      128    127.0.0.1:not-a-port     0.0.0.0:*
LISTEN 0      128              :2222          0.0.0.0:*

garbage
"""

# 两张只有一条监听的表，专门用来盯前缀碰撞。
ONLY_2222 = (
    "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
    "LISTEN 0      128        127.0.0.1:2222       0.0.0.0:*\n"
)
ONLY_9999 = (
    "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
    "LISTEN 0      4096       127.0.0.1:9999       0.0.0.0:*\n"
)


def test_header_line_is_skipped():
    addresses = {addr for addr, _ in parse_listen_table(SAMPLE)}
    assert "Local" not in addresses
    assert "Address" not in addresses


def test_ipv4_loopback_entries_are_parsed():
    entries = parse_listen_table(SAMPLE)
    assert ("127.0.0.1", 2222) in entries
    assert ("127.0.0.1", 9999) in entries


def test_ipv4_wildcard_entries_are_parsed():
    entries = parse_listen_table(SAMPLE)
    assert ("0.0.0.0", 22) in entries
    assert ("0.0.0.0", 2223) in entries


def test_bare_star_wildcard_entry_is_parsed():
    """`ss` 也会把通配地址打成 `*`，别让这个拼法悄悄失效。"""
    assert ("*", 8080) in parse_listen_table(SAMPLE)


def test_bracketed_ipv6_wildcard_entry_is_parsed():
    """IPv6 地址自带冒号，端口必须从最后一个冒号切开，方括号按原样保留。"""
    assert ("[::]", 22) in parse_listen_table(SAMPLE)


def test_docker_resolver_address_is_not_confused_with_loopback():
    """`127.0.0.11` 与 `127.0.0.1` 是两个地址，不能混。"""
    entries = parse_listen_table(SAMPLE)
    assert ("127.0.0.11", 39375) in entries
    assert ("127.0.0.1", 39375) not in entries


def test_port_is_an_int_not_a_string():
    entries = parse_listen_table(SAMPLE)
    assert ("127.0.0.1", 2222) in entries
    assert ("127.0.0.1", "2222") not in entries


def test_sample_yields_exactly_its_listeners():
    assert parse_listen_table(SAMPLE) == {
        ("0.0.0.0", 2223),
        ("0.0.0.0", 22),
        ("127.0.0.11", 39375),
        ("127.0.0.1", 9999),
        ("127.0.0.1", 2222),
        ("[::]", 22),
        ("*", 8080),
    }


def test_malformed_lines_are_skipped_without_raising():
    """列数不足、没有冒号、端口不是数字、地址为空的行都跳过，只留下能解析的那条。"""
    assert parse_listen_table(MALFORMED) == {("127.0.0.1", 2222)}


def test_empty_text_yields_no_entries():
    assert parse_listen_table("") == set()


def test_querying_22_does_not_match_a_line_for_2222():
    """回归：子串写法查 22 会命中 `127.0.0.1:2222`，报告一个不存在的监听端口。

    这个用例与下一个用例的唯一职责是：谁把 parse_listen_table() 简化回子串匹配，
    立刻就会红。Task 5 要查的正是 22。
    """
    entries = parse_listen_table(ONLY_2222)
    assert ("127.0.0.1", 2222) in entries
    assert ("127.0.0.1", 22) not in entries


def test_querying_999_does_not_match_a_line_for_9999():
    """回归：子串写法查 999 会命中 `127.0.0.1:9999`。"""
    entries = parse_listen_table(ONLY_9999)
    assert ("127.0.0.1", 9999) in entries
    assert ("127.0.0.1", 999) not in entries


# --- port_listening_in_gateway() 本身：注入固定表，不碰 docker ---

def test_lookup_finds_a_loopback_listener():
    assert port_listening_in_gateway(2222, table=SAMPLE)
    assert port_listening_in_gateway(9999, table=SAMPLE)


def test_lookup_defaults_to_loopback_address():
    """22 只绑在 0.0.0.0 与 [::] 上，默认地址是 loopback，所以查不到。"""
    assert not port_listening_in_gateway(22, table=SAMPLE)


def test_lookup_accepts_an_explicit_wildcard_address():
    """Task 4 的 443 与 Task 5 的 22 要这样问，而不是去匹配地址字面量的子串。"""
    assert port_listening_in_gateway(22, address="0.0.0.0", table=SAMPLE)
    assert port_listening_in_gateway(22, address="[::]", table=SAMPLE)
    assert port_listening_in_gateway(8080, address="*", table=SAMPLE)


def test_lookup_reports_a_port_nobody_listens_on_as_absent():
    assert not port_listening_in_gateway(1234, table=SAMPLE)


def test_lookup_querying_22_does_not_match_a_line_for_2222():
    """回归，这次盯的是 port_listening_in_gateway 自己：两个真实 bug 都出在它身上。"""
    assert port_listening_in_gateway(2222, table=ONLY_2222)
    assert not port_listening_in_gateway(22, table=ONLY_2222)


def test_lookup_querying_999_does_not_match_a_line_for_9999():
    assert port_listening_in_gateway(9999, table=ONLY_9999)
    assert not port_listening_in_gateway(999, table=ONLY_9999)
