#!/bin/bash
# 依 registry.toml 开通一个隧道账号。
# 用法：enroll-account.sh <username>
# 幂等：已存在的用户不会被重建，配置无变化时不 reload。
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_root
[ $# -eq 1 ] || die "用法：$0 <username>" 2
username="$1"

registry_get "$username" > /dev/null

if getent passwd "$username" > /dev/null; then
    printf '用户 %s 已存在，跳过创建。\n' "$username"
else
    useradd --system --shell /usr/sbin/nologin --no-create-home "$username"
    password="$(head -c 18 /dev/urandom | base64 | tr -d '\n')"
    printf '%s:%s\n' "$username" "$password" | chpasswd
    printf '用户 %s 已创建。初始口令: %s\n' "$username" "$password"
    printf '口令只显示这一次，请当面或经既有安全渠道交给现场人员，并要求首次连接后修改。\n'
fi

# 不能再写 `if rewrite_match_block; then`：那种写法会连带把函数体内所有其它
# 命令的 errexit 都挂起（bash 对处于 if 条件位置的命令是这么处理的），见
# lib.sh 里 rewrite_match_block 上面那段注释。用 `|| rc=$?` 取真实返回码，
# 再显式 case 判断——0 和 2 都是正常结果，其它任何值都不该出现（正常失败
# rewrite_match_block 内部已经直接 die() 掉了），落到这里说明函数自己的
# 返回码约定被破坏，同样要响亮地报错，不能被 if 悄悄吞掉。
rc=0
rewrite_match_block || rc=$?
case "$rc" in
    0)
        reload_sshd
        printf 'sshd-tunnel 配置已更新并 reload。\n'
        ;;
    2)
        printf 'sshd-tunnel 配置无变化。\n'
        ;;
    *)
        die "重写受管配置返回了意料之外的状态码 $rc" "$rc"
        ;;
esac

# registry.toml 里可能还留着已经被吊销、口令已锁定的账号——revoke-account.sh
# 故意不碰登记表，上面这次重写就会把它们的 Match 块也一并重新生成出来。
# 锁着的口令是唯一还挡着的东西，这里响亮地提醒操作员。
warn_locked_registry_accounts
