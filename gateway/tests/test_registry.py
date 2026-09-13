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


def test_missing_registry_file_is_rejected(tmp_path):
    """登记表文件根本不存在（不是内容损坏）这条路径此前没有任何测试盯着——
    损坏的 TOML 只在 bats 里端到端测过（test_scripts.bats 的"登记表损坏时…
    响亮失败"两条用例），文件缺失这条分支现在跟它们一样是响亮失败契约的
    一部分，值得一条独立的单元测试，不用起容器也能跑。
    """
    missing = tmp_path / "does-not-exist.toml"
    with pytest.raises(RegistryError, match="找不到登记表"):
        load(missing)


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


def test_cli_missing_registry_file_exits_4(tmp_path):
    """CLI 层面的同一条路径：这是三个运维脚本响亮失败契约依赖的退出码——
    lib.sh 的 registry_get()、tunnel-status.sh 都靠 registry.py 在这种情况下
    返回 4 并把原因写清楚，才能把"登记表读不到"和"用户名不存在"（退出码 3）
    区分开。
    """
    missing = tmp_path / "does-not-exist.toml"
    out = subprocess.run(
        [sys.executable, str(SCRIPT), "list-usernames"],
        env={"RMC_REGISTRY": str(missing), "PATH": "/usr/bin:/bin"},
        capture_output=True, text=True,
    )
    assert out.returncode == 4
    assert "找不到登记表" in out.stderr
