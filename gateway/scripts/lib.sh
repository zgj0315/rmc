# 三个运维脚本共用的工具函数。不要直接执行本文件——本文件不需要可执行位，
# 也没有 shebang，只能被 `source`。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY_PY="$SCRIPT_DIR/registry.py"
SSHD_CONFIG="${RMC_SSHD_CONFIG:-/etc/ssh/sshd_tunnel_config}"
RELOAD_CMD="${RMC_RELOAD_CMD:-systemctl reload sshd-tunnel}"
BEGIN_MARK="# BEGIN RMC MANAGED"
END_MARK="# END RMC MANAGED"
# 必须与 registry.py 里的 USERNAME_PREFIX 保持一致——两边各自校验同一条规则，
# 任何一边漏掉都可能让非隧道账号混进受管流程。
TUNNEL_PREFIX="tunnel-"

# $1 是消息，$2（可选）是退出码。用 "$1" 而不是 "$*"：后者会把 $2 也接进消息
# 文本里，每一条带自定义退出码的报错都会在人话后面莫名多出一个数字
# （例如 "登记表中没有账号 tunnel-ghost 3"），把操作员要看的话弄脏。
die() { printf '%s\n' "$1" >&2; exit "${2:-1}"; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die "本脚本必须以 root 运行" 1
}

# 拒绝任何不是 tunnel-* 的用户名。revoke-account.sh 明确不查 registry.toml
# （吊销后账号未必还在登记表里），enroll-account.sh 靠 registry_get 间接挡住
# 非隧道用户名——registry.py 的 load() 本身就不允许非 tunnel-* 前缀的记录存在，
# 所以那条路径天然安全。revoke 没有等价的守卫：`revoke-account.sh root` 会一路
# 跑到 `passwd -l root` 再到 `pkill -u root`，把宿主上所有 root 拥有的进程—
# sshd、haproxy、当前这个操作员自己的会话——全部杀掉。这个检查必须是 revoke
# 脚本里除了参数个数之外第一件做的事，落在任何可能改动系统状态的操作之前。
require_tunnel_username() {
    local username="$1"
    case "$username" in
        "$TUNNEL_PREFIX"*) ;;
        *) die "拒绝对 $username 执行本操作：用户名必须以 $TUNNEL_PREFIX 开头，这不是一个隧道账号" 6 ;;
    esac
}

# 校验登记表并确认用户名在册，回显 "username owner port appliances"。
# registry.py 对同一个 get 子命令有两种不同的失败：登记表本身不合法（退出码 4，
# 在解析阶段就出错，与传的用户名无关）、传的用户名不在表里（退出码 3）。原来
# 这里一律 `die "$line" 3`，把"登记表坏了"误报成"这个账号不存在"——消息文字
# 没错（$line 本身是 registry.py 给的准确原文），退出码却是假的，会误导任何
# 依这个退出码分支处理的调用方。用 `|| rc=$?` 而不是 `if ! ...; then` 接住真实
# 退出码：后者一样会把 -e 为函数体其余部分（这里其实没有其余部分，但下面
# rewrite_match_block 就吃过这个亏，这里一并按同样的规矩写，不留习惯上的口子）。
registry_get() {
    local username="$1" line rc=0
    line="$(python3 "$REGISTRY_PY" get "$username" 2>&1)" || rc=$?
    if [ "$rc" -ne 0 ]; then
        die "$line" "$rc"
    fi
    printf '%s\n' "$line"
}

# 依登记表整体重写受管 Match 块，块外内容原样保留。
#
# 可选参数 exclude：无论登记表里是否还有这个用户名，都不给它生成 Match 块。
# revoke-account.sh 用这个参数——它明确不改 registry.toml（见该脚本注释），
# 若不排除，重写只会照登记表原样重放，吊销当场移除不了这条放行。
#
# 返回码只有两种"正常"结果：0 = 配置已改变并已经落盘；2 = 登记表没有变化，
# 没有落盘、也不需要 reload。除此之外的任何失败都直接调用 die()——立即无条件
# 退出，不依赖 set -e 是否生效。这一点很要紧：两个调用方过去都是
# `if rewrite_match_block; then ... fi` 这种写法，而 bash 对处于 if/&&/||
# 条件位置上的命令，会连带把它整个执行过程中的 -e 都挂起——不仅是这次调用本身
# 的返回值不触发退出，函数体内所有其它命令的失败也一并不触发。这原本只是想
# 分辨"改了"和"没改"，副作用却是给函数体内每一条命令都关上了 -e 这层保险。
# 真出过事：用户名列表原来是拿 `< <(python3 ... list-usernames)` 这种进程替换
# 直接喂给 while 循环的，进程替换的退出码在 bash 里本来就没地方可查——不管
# 有没有被 if 额外挂起 -e，这条子命令失败都不会被任何人注意到。registry.toml
# 一旦损坏或缺失，`list-usernames` 直接失败、不产出任何用户名，while 循环则
# 读到空输入、一次也不循环，于是这个函数会兴高采烈地生成一个只有起止标记、
# 没有任何 Match 块的"合法"受管区段——这样的区段完全能通过 sshd -t（语法上
# 无可指摘），于是被写回、被 reload，脚本正常退出 0，而 **全体账号的
# PermitListen 在这一刻同时消失**。唯一的线索是 registry.py 那句报错飞快地
# 划过 stderr，不会中止任何东西。
#
# 修法是两条都要：用户名列表先用普通的命令替换 `usernames="$(...)"` 接进变量
# （这样失败与否可以用 `||` 直接判断，不再是进程替换那种查不到的状态），并且
# 对它、以及循环体内每一次取端口号的调用都显式判断、显式 die()——不依赖调用方
# 是不是用 if 包着来决定这些检查还生不生效。因此调用方现在必须用
# `rewrite_match_block ... || rc=$?` 取返回码，再显式 case 判断 0 / 2 /
# 其它，不能再写回 `if rewrite_match_block; then`。
rewrite_match_block() {
    local exclude="${1:-}"
    local tmp usernames u port

    # 与目标文件同目录，保证下面的 mv 是同一文件系统内的原子改名，不是跨
    # 文件系统的拷贝；同时避免半途中断时把 /etc/ssh 下的目标文件本身截断成
    # 半份——写的一直是这个临时文件，目标文件只在整份写完并通过 sshd -t 之后
    # 被一次 mv 原子替换。
    tmp="$(mktemp "$(dirname "$SSHD_CONFIG")/.rmc-sshd-tunnel-config.XXXXXX")"

    awk -v begin="$BEGIN_MARK" -v end="$END_MARK" '
        $0 == begin { skipping = 1; next }
        $0 == end   { skipping = 0; next }
        !skipping   { print }
    ' "$SSHD_CONFIG" > "$tmp"

    # 两处都要 2>&1：捕获失败原因是这条修法的重点，只接 stdout 的话，一旦
    # 失败（registry.py 的报错都走 stderr），拿到手的就是空字符串，die() 打印
    # 出来的消息会变成"配置未改动："后面什么都没有——看着像是"改了却不说明
    # 原因"，比根本不打印这条消息还容易让人误判。
    if ! usernames="$(python3 "$REGISTRY_PY" list-usernames 2>&1)"; then
        rm -f "$tmp"
        die "读取登记表用户名列表失败，配置未改动：$usernames" 4
    fi

    {
        printf '%s\n' "$BEGIN_MARK"
        while IFS= read -r u; do
            [ -z "$u" ] && continue
            [ "$u" = "$exclude" ] && continue
            local get_out
            if ! get_out="$(python3 "$REGISTRY_PY" get "$u" 2>&1)"; then
                rm -f "$tmp"
                die "读取账号 $u 的端口失败，配置未改动：$get_out" 4
            fi
            port="$(printf '%s\n' "$get_out" | cut -f3)"
            # PermitListen 写不带地址的裸端口形式。GatewayPorts yes 要把反向端口
            # 绑到通配地址上，而带地址的 PermitListen 会在 GatewayPorts 被读到
            # 之前先一层把通配绑定拒掉。端口仍逐账号只放行一个，只有地址不限。
            printf 'Match User %s\n    PermitListen %s\n' "$u" "$port"
        done <<< "$usernames"
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
        return 2   # 无变化：与"失败"区分开，调用方不必再用 if 吞掉这个分支
    fi
    chmod --reference="$SSHD_CONFIG" "$tmp" 2>/dev/null || chmod 644 "$tmp"
    mv -f "$tmp" "$SSHD_CONFIG"
    return 0
}

# 扫描登记表里眼下仍然存在于系统里的账号，对口令被锁定的账号打印醒目警告。
# revoke-account.sh 故意不碰 registry.toml（登记表是人工维护的唯一事实来源，
# 不该由吊销脚本代劳编辑），于是一条记录只要还留在表里，往后任何一次
# enroll——哪怕是给完全不相关的另一个账号跑的，因为 rewrite_match_block 每次
# 都是照整张登记表重放——都会把它的 Match 块重新生成出来。锁着的口令是唯一
# 还挡在它和一条能用的隧道之间的东西；这个函数让操作员每次 enroll 之后都能
# 看到这一点，不必等到有人碰巧解锁了那个口令才发现端口权限其实一直都在。
# 读用户名列表失败时只警告不中止：这里只是尽力提醒，不该盖过前面已经成功
# 完成的 enroll 本身。
warn_locked_registry_accounts() {
    local u status_line usernames
    if ! usernames="$(python3 "$REGISTRY_PY" list-usernames 2>&1)"; then
        printf '警告：读取登记表用户名列表失败，无法检查是否有已锁定但仍在册的账号：%s\n' "$usernames" >&2
        return 0
    fi
    while IFS= read -r u; do
        [ -z "$u" ] && continue
        getent passwd "$u" > /dev/null 2>&1 || continue
        status_line="$(passwd -S "$u" 2>/dev/null || true)"
        case "$status_line" in
            *" L "*)
                printf '警告：%s 的口令处于锁定状态，但仍在 registry.toml 里，端口放行已经/将会为它重新生成。若这是一次吊销，请从 registry.toml 中删除该账号的记录。\n' "$u" >&2
                ;;
        esac
    done <<< "$usernames"
}

reload_sshd() {
    # shellcheck disable=SC2086
    $RELOAD_CMD
}
