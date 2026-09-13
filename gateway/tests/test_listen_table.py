"""`parse_listen_table()` 的单元测试。

这个文件刻意不用 harness 固件、不碰 docker：解析 `ss` 输出是纯字符串逻辑，
而它正是 port_listening_in_gateway() 两次出错的地方。能在不起容器的前提下跑，
才能在改动这段解析时立刻发现回归。样本取自 gateway 容器里 `ss -ltn` 的真实输出。
"""

from conftest import parse_listen_table

# gateway 容器实际的 `ss -ltn` 输出，原样保留（含尾随空格与表头）。
SAMPLE = """\
State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
LISTEN 0      5            0.0.0.0:2223       0.0.0.0:*
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*
LISTEN 0      4096      127.0.0.11:39375      0.0.0.0:*
LISTEN 0      4096       127.0.0.1:9999       0.0.0.0:*
LISTEN 0      128        127.0.0.1:2222       0.0.0.0:*
LISTEN 0      128             [::]:22            [::]:*
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


def test_sample_yields_exactly_its_six_listeners():
    assert parse_listen_table(SAMPLE) == {
        ("0.0.0.0", 2223),
        ("0.0.0.0", 22),
        ("127.0.0.11", 39375),
        ("127.0.0.1", 9999),
        ("127.0.0.1", 2222),
        ("[::]", 22),
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
    only_2222 = (
        "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
        "LISTEN 0      128        127.0.0.1:2222       0.0.0.0:*\n"
    )
    entries = parse_listen_table(only_2222)
    assert ("127.0.0.1", 2222) in entries
    assert ("127.0.0.1", 22) not in entries


def test_querying_999_does_not_match_a_line_for_9999():
    """回归：子串写法查 999 会命中 `127.0.0.1:9999`。"""
    only_9999 = (
        "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
        "LISTEN 0      4096       127.0.0.1:9999       0.0.0.0:*\n"
    )
    entries = parse_listen_table(only_9999)
    assert ("127.0.0.1", 9999) in entries
    assert ("127.0.0.1", 999) not in entries
