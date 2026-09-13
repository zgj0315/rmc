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
