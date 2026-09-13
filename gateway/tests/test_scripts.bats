#!/usr/bin/env bats
# 在 gateway 容器内运行：
#   docker compose exec -T gateway bats /gateway/tests/test_scripts.bats

setup() {
    export RMC_REGISTRY=/tmp/registry.toml
    export RMC_SSHD_CONFIG=/tmp/sshd_tunnel_config
    export RMC_RELOAD_CMD=true
    cat > "$RMC_REGISTRY" <<'TOML'
[[tunnel_account]]
username   = "tunnel-zhang"
owner      = "zhang"
port       = 22001
appliances = ["c0001-a1"]

[[tunnel_account]]
username   = "tunnel-new"
owner      = "new"
port       = 22007
appliances = []
TOML
    # 全局段里的 PermitListen none 是真实 gateway/sshd_tunnel_config 里的默认
    # 拒绝（见方案 4.2）：不写在这里，"重写后全局段原样保留" 这件事就测不出来
    # ——所有账号在测试里都带 Match 块，块内的裸端口放行会掩盖块外默认值
    # 是否还在、是否还是全局的这个问题。
    cat > "$RMC_SSHD_CONFIG" <<'CONF'
ListenAddress 127.0.0.1:2222
PermitListen none
# BEGIN RMC MANAGED
Match User tunnel-zhang
    PermitListen 22001
# END RMC MANAGED
CONF
}

teardown() {
    userdel tunnel-new 2>/dev/null || true
}

@test "enroll 拒绝不在登记表里的用户名" {
    run /gateway/scripts/enroll-account.sh tunnel-ghost
    [ "$status" -eq 3 ]
    [[ "$output" == *"tunnel-ghost"* ]]
    # die() 用 "$1" 打印消息、"$2" 只当退出码用；如果哪天有人手滑改回 "$*"，
    # 退出码会被拼回消息末尾变成 "...tunnel-ghost 3" 这种噪音——用例已经确认
    # 消息非空且含真实内容，这里再确认它没有被退出码污染，不是纯粹测「没有」。
    [[ "$output" != *"tunnel-ghost 3"* ]]
}

@test "enroll 创建 nologin 系统用户" {
    run /gateway/scripts/enroll-account.sh tunnel-new
    [ "$status" -eq 0 ]
    run getent passwd tunnel-new
    [ "$status" -eq 0 ]
    [[ "$output" == *"/usr/sbin/nologin"* ]]
}

@test "enroll 打印一次初始口令" {
    run /gateway/scripts/enroll-account.sh tunnel-new
    [[ "$output" == *"初始口令"* ]]
    # 口令至少 20 字符
    pw=$(printf '%s\n' "$output" | sed -n 's/.*初始口令: //p')
    [ "${#pw}" -ge 20 ]
}

@test "enroll 依登记表重写受管 Match 块并保留块外内容" {
    run /gateway/scripts/enroll-account.sh tunnel-new
    [ "$status" -eq 0 ]
    grep -q "^ListenAddress 127.0.0.1:2222$" "$RMC_SSHD_CONFIG"
    grep -q "^    PermitListen 22001$" "$RMC_SSHD_CONFIG"
    grep -q "^    PermitListen 22007$" "$RMC_SSHD_CONFIG"
    # 受管标记只出现一次
    [ "$(grep -c 'BEGIN RMC MANAGED' "$RMC_SSHD_CONFIG")" -eq 1 ]
}

@test "全局 PermitListen none 经重写后原样留在受管区之外，仍然全局生效" {
    # 这条防的是本任务说明书点名的退化：重写函数如果整份重写文件、挪动了
    # 标记，或者把 Match 块塞到全局指令前面，块外的全局默认拒绝就会消失、
    # 被复制进 Match 块、或者不再位于标记之前——而其余用例全部只看块内
    # 内容，测不出这三种退化中的任何一种。
    run /gateway/scripts/enroll-account.sh tunnel-new
    [ "$status" -eq 0 ]
    # 恰好一次：不多（没被复制/重复），不少（没被删掉）。
    [ "$(grep -c '^PermitListen none$' "$RMC_SSHD_CONFIG")" -eq 1 ]
    # 必须仍在 BEGIN 标记之前，即仍然是全局指令而不是掉进了受管区/Match 块里。
    permit_line="$(grep -n '^PermitListen none$' "$RMC_SSHD_CONFIG" | cut -d: -f1)"
    begin_line="$(grep -n '^# BEGIN RMC MANAGED$' "$RMC_SSHD_CONFIG" | cut -d: -f1)"
    [ -n "$permit_line" ]
    [ -n "$begin_line" ]
    [ "$permit_line" -lt "$begin_line" ]
}

@test "enroll 生成的 PermitListen 是不带地址的裸端口形式" {
    # 带地址的 PermitListen 会在 GatewayPorts 之前一层把通配绑定拒掉，
    # 反向端口就绑不到 0.0.0.0 上，工程师也就连不进来。见全局约束第一条。
    run /gateway/scripts/enroll-account.sh tunnel-new
    [ "$status" -eq 0 ]
    ! grep -q "PermitListen .*:" "$RMC_SSHD_CONFIG"
}

@test "enroll 幂等，重复执行不重复写 Match 块" {
    /gateway/scripts/enroll-account.sh tunnel-new
    before=$(md5sum "$RMC_SSHD_CONFIG" | cut -d' ' -f1)
    /gateway/scripts/enroll-account.sh tunnel-new
    after=$(md5sum "$RMC_SSHD_CONFIG" | cut -d' ' -f1)
    [ "$before" = "$after" ]
}

@test "revoke 锁定口令并移除 Match 块" {
    /gateway/scripts/enroll-account.sh tunnel-new
    run /gateway/scripts/revoke-account.sh tunnel-new
    [ "$status" -eq 0 ]
    run passwd -S tunnel-new
    [[ "$output" == *" L "* ]]
    ! grep -q "PermitListen 22007" "$RMC_SSHD_CONFIG"
}

@test "revoke 的收尾提示报出的是被吊销的用户名，不是空串" {
    # lib.sh 的 rewrite_match_block 内部用同名变量 username 逐行读登记表；
    # revoke-account.sh 与它共用同一个 shell（source，不是子进程），一旦
    # rewrite_match_block 里的循环变量没有 local，函数返回后就会把调用方的
    # $username 覆盖掉——脚本仍然退出 0、Match 块也确实被移除，只是收尾的
    # 几句提示会静默地把用户名打印成空串。前一条用例只查端口和退出码，看不出
    # 这个退化；这里专门断言收尾文案里带着完整用户名。
    /gateway/scripts/enroll-account.sh tunnel-new
    run /gateway/scripts/revoke-account.sh tunnel-new
    [ "$status" -eq 0 ]
    [[ "$output" == *"tunnel-new 当前没有在线会话"* ]]
    [[ "$output" == *"请从 registry.toml 中删除 tunnel-new 的记录"* ]]
}

@test "status 列出登记表中每个账号及其端口" {
    run /gateway/scripts/tunnel-status.sh
    [ "$status" -eq 0 ]
    [[ "$output" == *"tunnel-zhang 22001"* ]]
    [[ "$output" == *"tunnel-new 22007"* ]]
}

@test "status 对没有在线会话的账号完整报出 offline 与占位 pid" {
    # 上一条只查子串 "user port"，online/offline 与 pid 两列完全没人看过——
    # 接口约定的输出是 "<username> <port> <online|offline> <pid>" 四列，
    # 少了这条，格式错了、离线态判断反了都测不出来。这里两个账号在这套
    # bats 环境里都不会真的建立 ssh 会话，offline 是唯一可能的真实状态。
    run /gateway/scripts/tunnel-status.sh
    [ "$status" -eq 0 ]
    [[ "$output" == *"tunnel-zhang 22001 offline -"* ]]
}

@test "非 root 运行立即退出" {
    run runuser -u nobody -- /gateway/scripts/enroll-account.sh tunnel-new
    [ "$status" -ne 0 ]
    [[ "$output" == *"root"* ]]
}
