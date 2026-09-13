#!/bin/bash
# 吊销一个隧道账号：锁口令、移除端口放行、踢掉在线会话。
# 用法：revoke-account.sh <username>
# 注意：本脚本不改 registry.toml，请在吊销后手工删除对应记录。
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_root
[ $# -eq 1 ] || die "用法：$0 <username>" 2
username="$1"

# 必须在做任何事之前检查：本脚本不像 enroll 那样经 registry_get 间接挡住
# 非隧道用户名（吊销时账号未必还在登记表里，这正是本脚本存在的场景之一）。
# 少了这一步，`revoke-account.sh root` 会一路跑到 `passwd -l root` 再到
# `pkill -u root`，把宿主上所有 root 拥有的进程——sshd、haproxy、操作员自己
# 当前的会话——全部杀掉。
require_tunnel_username "$username"

getent passwd "$username" > /dev/null || die "系统里没有用户 $username" 3

passwd -l "$username" > /dev/null
printf '已锁定 %s 的口令。\n' "$username"

# 不能再写 `if rewrite_match_block "$username"; then`：原来的写法连 else 都没有，
# "无变化"与"内部出错但没被 if 之外的任何人注意到"完全无法区分，调用方等于
# 把两者都悄悄吞掉了。见 lib.sh 里 rewrite_match_block 上面的注释。
rc=0
rewrite_match_block "$username" || rc=$?
case "$rc" in
    0)
        reload_sshd
        printf '已移除端口放行并 reload。\n'
        ;;
    2)
        printf '端口放行本来就不在（配置无变化）。\n'
        ;;
    *)
        die "重写受管配置返回了意料之外的状态码 $rc" "$rc"
        ;;
esac

if pkill -u "$username" 2>/dev/null; then
    printf '已踢掉 %s 的在线会话。\n' "$username"
else
    printf '%s 当前没有在线会话。\n' "$username"
fi

printf '本脚本不会修改 registry.toml；请手工删除 %s 的记录——在删除之前，下一次任意账号的\nenroll 都会把它的端口放行重新生成出来（届时 enroll 会对仍在册但已锁定的账号发出警告）。\n' "$username"
