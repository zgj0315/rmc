# 三个运维脚本共用的工具函数。不要直接执行本文件。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY_PY="$SCRIPT_DIR/registry.py"
SSHD_CONFIG="${RMC_SSHD_CONFIG:-/etc/ssh/sshd_tunnel_config}"
RELOAD_CMD="${RMC_RELOAD_CMD:-systemctl reload sshd-tunnel}"
BEGIN_MARK="# BEGIN RMC MANAGED"
END_MARK="# END RMC MANAGED"

# $1 是消息，$2（可选）是退出码。用 "$1" 而不是 "$*"：后者会把 $2 也接进消息
# 文本里，每一条带自定义退出码的报错都会在人话后面莫名多出一个数字
# （例如 "登记表中没有账号 tunnel-ghost 3"），把操作员要看的话弄脏。
die() { printf '%s\n' "$1" >&2; exit "${2:-1}"; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die "本脚本必须以 root 运行" 1
}

# 校验登记表并确认用户名在册，回显 "username owner port appliances"
registry_get() {
    local username="$1" line
    if ! line="$(python3 "$REGISTRY_PY" get "$username" 2>&1)"; then
        die "$line" 3
    fi
    printf '%s\n' "$line"
}

# 依登记表整体重写受管 Match 块，块外内容原样保留。
# 可选参数 exclude：无论登记表里是否还有这个用户名，都不给它生成 Match 块。
# revoke-account.sh 用这个参数——它明确不改 registry.toml（见该脚本注释），
# 若不排除，重写只会照登记表原样重放，吊销当场移除不了这条放行。
rewrite_match_block() {
    local exclude="${1:-}"
    local tmp
    tmp="$(mktemp)"
    awk -v begin="$BEGIN_MARK" -v end="$END_MARK" '
        $0 == begin { skipping = 1; next }
        $0 == end   { skipping = 0; next }
        !skipping   { print }
    ' "$SSHD_CONFIG" > "$tmp"

    {
        printf '%s\n' "$BEGIN_MARK"
        printf '# 由 scripts/enroll-account.sh 依 registry.toml 生成，勿手工编辑。\n'
        # 循环变量特意不叫 username：本函数被 source 进调用方的同一个 shell
        # （不是子进程），不加 local 就会在函数返回后把调用方自己的 $username
        # 覆盖掉。enroll-account.sh 用完 rewrite_match_block 就不再读 $username
        # 了所以没暴露；revoke-account.sh 在调用之后还要拿 $username 打印
        # "已踢掉 xxx 的在线会话" 之类的收尾信息，一旦被覆盖成空串，这几行就会
        # 打印出不带用户名的空话——这不是本函数自己的变量，必须显式 local。
        local u
        while IFS= read -r u; do
            [ "$u" = "$exclude" ] && continue
            local port
            port="$(python3 "$REGISTRY_PY" get "$u" | cut -f3)"
            # PermitListen 写不带地址的裸端口形式。GatewayPorts yes 要把反向端口
            # 绑到通配地址上，而带地址的 PermitListen 会在 GatewayPorts 被读到
            # 之前先一层把通配绑定拒掉。端口仍逐账号只放行一个，只有地址不限。
            printf 'Match User %s\n    PermitListen %s\n' "$u" "$port"
        done < <(python3 "$REGISTRY_PY" list-usernames)
        printf '%s\n' "$END_MARK"
    } >> "$tmp"

    if ! /usr/sbin/sshd -t -f "$tmp" 2>/dev/null; then
        local err
        err="$(/usr/sbin/sshd -t -f "$tmp" 2>&1 || true)"
        rm -f "$tmp"
        die "生成的配置未通过 sshd -t，已放弃改动：$err" 5
    fi

    if cmp -s "$tmp" "$SSHD_CONFIG"; then
        rm -f "$tmp"
        return 1   # 无变化
    fi
    cat "$tmp" > "$SSHD_CONFIG"
    rm -f "$tmp"
    return 0
}

reload_sshd() {
    # shellcheck disable=SC2086
    $RELOAD_CMD
}
