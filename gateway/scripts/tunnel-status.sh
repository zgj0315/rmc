#!/bin/bash
# 汇总登记表中每个账号的端口与在线状态。
# 输出：<username> <port> <online|offline> <pid|->
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ $# -eq 0 ] || die "用法：$0" 2

# 不能再用 `done < <(python3 "$REGISTRY_PY" list-usernames)` 这种进程替换喂
# while 循环：进程替换的退出码在 bash 里查不到，见 lib.sh 里
# rewrite_match_block 上面那段注释记录的同一个坑——登记表损坏或缺失时
# list-usernames 直接失败、不产出任何用户名，while 循环读到空输入、一次也
# 不循环，本脚本会打印一张空表后正常退出 0，把"登记表坏了、看不到任何账号"
# 误报成"没有账号在线"。改用命令替换接进变量，失败与否能用 `||` 直接判断，
# 跟 lib.sh 里 registry_get() 的写法一致：两处都要 2>&1，只接 stdout 的话
# 失败时拿到的是空字符串，die() 打出来的消息就成了"什么都没说"。
rc=0
usernames="$(python3 "$REGISTRY_PY" list-usernames 2>&1)" || rc=$?
[ "$rc" -eq 0 ] || die "$usernames" "$rc"

while IFS= read -r username; do
    [ -z "$username" ] && continue
    # 同样不能写成 `python3 ... get "$u" | cut -f3` 这种管道：管道整体的
    # 退出码取自最后一段，get 失败时 cut 面对空输入照样返回 0，端口列会
    # 静默地变成空字符串，四列输出的契约被打破却看不出错在哪一步。
    get_rc=0
    get_out="$(python3 "$REGISTRY_PY" get "$username" 2>&1)" || get_rc=$?
    [ "$get_rc" -eq 0 ] || die "$get_out" "$get_rc"
    port="$(printf '%s\n' "$get_out" | cut -f3)"
    pid="$(pgrep -u "$username" -n sshd 2>/dev/null || true)"
    if [ -n "$pid" ]; then
        printf '%s %s online %s\n' "$username" "$port" "$pid"
    else
        printf '%s %s offline -\n' "$username" "$port"
    fi
done <<< "$usernames"
