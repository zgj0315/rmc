#!/bin/bash
# 吊销一个隧道账号：锁口令、移除端口放行、踢掉在线会话。
# 用法：revoke-account.sh <username>
# 注意：本脚本不改 registry.toml，请在吊销后手工删除对应记录。
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_root
[ $# -eq 1 ] || die "用法：$0 <username>" 2
username="$1"

getent passwd "$username" > /dev/null || die "系统里没有用户 $username" 3

passwd -l "$username" > /dev/null
printf '已锁定 %s 的口令。\n' "$username"

if rewrite_match_block "$username"; then
    reload_sshd
    printf '已移除端口放行并 reload。\n'
fi

if pkill -u "$username" 2>/dev/null; then
    printf '已踢掉 %s 的在线会话。\n' "$username"
else
    printf '%s 当前没有在线会话。\n' "$username"
fi

printf '请从 registry.toml 中删除 %s 的记录，再次运行 enroll 以对齐配置。\n' "$username"
