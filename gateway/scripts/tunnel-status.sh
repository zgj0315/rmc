#!/bin/bash
# 汇总登记表中每个账号的端口与在线状态。
# 输出：<username> <port> <online|offline> <pid|->
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ $# -eq 0 ] || die "用法：$0" 2

while IFS= read -r username; do
    port="$(python3 "$REGISTRY_PY" get "$username" | cut -f3)"
    pid="$(pgrep -u "$username" -n sshd 2>/dev/null || true)"
    if [ -n "$pid" ]; then
        printf '%s %s online %s\n' "$username" "$port" "$pid"
    else
        printf '%s %s offline -\n' "$username" "$port"
    fi
done < <(python3 "$REGISTRY_PY" list-usernames)
