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

@test "enroll 在已经登记过的真实配置上重跑，是纯粹的空操作" {
    # 仓库里真实的 gateway/sshd_tunnel_config 已经手写好了 tunnel-zhang 的
    # Match 块（端口与 registry.toml 里的一致）。生产上第一次运行
    # enroll-account.sh tunnel-zhang，理应是彻头彻尾的空操作——账号已存在、
    # 端口已经放行——不该有任何字节变化，更不该触发 reload。这条用例曾经在
    # 这里失手过一次：生成器当时会在受管区里额外插入一行"由
    # scripts/enroll-account.sh ... 生成，勿手工编辑"的提醒注释，而真实文件
    # 的受管区里根本没有这一行（那句话已经以说明性文字的形式写在 BEGIN 标记
    # 之前，属于块外保留内容）。结果就是生产上第一次跑 enroll 会平白多出一次
    # 谁都没测过的"改动 + reload"，而不是操作员以为的空操作。已经决定去掉
    # 生成器里那行冗余注释（块外的说明文字已经说过同一句话），让空操作真的
    # 是空操作；这条用例把这个决定钉住。
    # 登记表也换成仓库里真实的那份（只有 tunnel-zhang 一条）：沿用 setup()
    # 里两个账号的假登记表会让 tunnel-new 的块被一并生成出来，那就不是空操作
    # 了，测的也就不是"生产上第一次跑会不会是空操作"这件事。
    cp /gateway/registry.toml "$RMC_REGISTRY"
    cp /gateway/sshd_tunnel_config "$RMC_SSHD_CONFIG"
    pristine=$(md5sum "$RMC_SSHD_CONFIG" | cut -d' ' -f1)
    run /gateway/scripts/enroll-account.sh tunnel-zhang
    [ "$status" -eq 0 ]
    [[ "$output" == *"配置无变化"* ]]
    after=$(md5sum "$RMC_SSHD_CONFIG" | cut -d' ' -f1)
    [ "$pristine" = "$after" ]
}

@test "enroll 在真实的 gateway/sshd_tunnel_config 上添加新账号，全局默认拒绝依然唯一且靠前" {
    # 前面"全局 PermitListen none..."那条用例一直只在 fixture 的两行假全局段上
    # 验证过；真实的 gateway/sshd_tunnel_config 有五十几行，结构复杂得多
    # （HostKey、Subsystem、ClientAlive 等一整段），那条用例保护的其实是
    # fixture，不是真文件。这里直接拿仓库里真实的配置文件当起点，加一个新
    # 账号，确认同样的性质在真实结构上也成立，并且生成结果确实能过
    # sshd -t——不是只在语法简单的 fixture 上凑巧成立。
    cp /gateway/sshd_tunnel_config "$RMC_SSHD_CONFIG"
    run /gateway/scripts/enroll-account.sh tunnel-new
    [ "$status" -eq 0 ]
    [ "$(grep -c '^PermitListen none$' "$RMC_SSHD_CONFIG")" -eq 1 ]
    permit_line="$(grep -n '^PermitListen none$' "$RMC_SSHD_CONFIG" | cut -d: -f1)"
    begin_line="$(grep -n '^# BEGIN RMC MANAGED$' "$RMC_SSHD_CONFIG" | cut -d: -f1)"
    [ -n "$permit_line" ]
    [ -n "$begin_line" ]
    [ "$permit_line" -lt "$begin_line" ]
    [ "$(grep -c 'BEGIN RMC MANAGED' "$RMC_SSHD_CONFIG")" -eq 1 ]
    grep -q "^    PermitListen 22001$" "$RMC_SSHD_CONFIG"
    grep -q "^    PermitListen 22007$" "$RMC_SSHD_CONFIG"
    /usr/sbin/sshd -t -f "$RMC_SSHD_CONFIG"
}

@test "enroll 幂等，重复执行不重复写 Match 块" {
    /gateway/scripts/enroll-account.sh tunnel-new
    before=$(md5sum "$RMC_SSHD_CONFIG" | cut -d' ' -f1)
    /gateway/scripts/enroll-account.sh tunnel-new
    after=$(md5sum "$RMC_SSHD_CONFIG" | cut -d' ' -f1)
    [ "$before" = "$after" ]
}

@test "revoke 拒绝不是 tunnel-* 的用户名" {
    # revoke 不像 enroll 那样经 registry_get 间接被登记表挡住非隧道用户名
    # （吊销时账号未必还在表里，这正是它存在的场景）。没有这条检查，
    # revoke-account.sh root 会一路跑到 passwd -l root 再到 pkill -u root，
    # 把容器里所有 root 拥有的进程——包括正在跑这条用例的 bats 自己——一起杀掉。
    # 用 root 而不是随便一个不存在的名字来测：root 保证存在，能确认拒绝发生在
    # getent/passwd/pkill 任何一步之前，而不是恰好因为"账号不存在"才退出。
    run /gateway/scripts/revoke-account.sh root
    [ "$status" -eq 6 ]
    [[ "$output" == *"root"* ]]
}

@test "revoke 锁定口令并移除 Match 块" {
    /gateway/scripts/enroll-account.sh tunnel-new
    run /gateway/scripts/revoke-account.sh tunnel-new
    [ "$status" -eq 0 ]
    run passwd -S tunnel-new
    [[ "$output" == *" L "* ]]
    ! grep -q "PermitListen 22007" "$RMC_SSHD_CONFIG"
}

@test "revoke 只移除目标账号的 Match 块，其它账号的放行原样保留" {
    # exclude 参数如果写错——比如条件写反、或者只要 exclude 非空就跳过所有
    # 账号——最容易犯的错是把全体账号的块一起清空，而不是只清目标账号那一个。
    # 前一条用例只查被吊销账号自己的端口消失了没有，测不出这种退化：清空
    # 全部块之后，tunnel-new 的端口自然也不在了，那条用例照样绿。
    /gateway/scripts/enroll-account.sh tunnel-new
    run /gateway/scripts/revoke-account.sh tunnel-new
    [ "$status" -eq 0 ]
    grep -q "^Match User tunnel-zhang$" "$RMC_SSHD_CONFIG"
    grep -q "^    PermitListen 22001$" "$RMC_SSHD_CONFIG"
}

@test "登记表损坏时 revoke 响亮失败，配置一个字节都不改" {
    # rewrite_match_block 原来靠 `< <(python3 ... list-usernames)` 这种进程
    # 替换喂 while 循环：registry.toml 损坏时 list-usernames 直接失败、不产出
    # 任何用户名，循环读到空输入、一次也不循环，函数会生成一个只有起止标记、
    # 没有任何 Match 块的"合法"区段——通过 sshd -t、被写回、被 reload，
    # 全体账号（不只是正在被吊销的这一个）同时失去 PermitListen，脚本还正常
    # 退出 0。这里先靠正常的 enroll 让两个账号的块都真实存在，再弄坏登记表，
    # 断言 revoke 必须响亮失败、且配置文件字节不变——不能是"看起来退出码不对
    # 但反正端口都没了"这种半吊子失败。
    /gateway/scripts/enroll-account.sh tunnel-new
    before=$(md5sum "$RMC_SSHD_CONFIG" | cut -d' ' -f1)
    printf 'this is not valid toml [[[' > "$RMC_REGISTRY"
    run /gateway/scripts/revoke-account.sh tunnel-new
    [ "$status" -eq 4 ]
    [[ "$output" == *"读取登记表用户名列表失败"* ]]
    after=$(md5sum "$RMC_SSHD_CONFIG" | cut -d' ' -f1)
    [ "$before" = "$after" ]
    grep -q "^    PermitListen 22001$" "$RMC_SSHD_CONFIG"
    grep -q "^    PermitListen 22007$" "$RMC_SSHD_CONFIG"
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

@test "enroll 处理不相关账号时，对仍在登记表却已被锁定的账号发出警告" {
    # revoke 故意不改 registry.toml，锁着的口令是吊销之后唯一还挡着的东西。
    # 只要那条记录还在表里，随便哪次 enroll——哪怕是给 tunnel-zhang 这个完全
    # 不相关的账号跑的，因为 rewrite_match_block 每次都是照整张登记表重放——
    # 都会把 tunnel-new 的 Match 块也一并重新生成出来。这里断言的是"警告
    # 出现了"：端口放行被重新生成是设计如此（吊销没有改登记表，就不能指望
    # enroll 知道该排除它），警告是唯一的补救，没有它这个退化会完全无声。
    /gateway/scripts/enroll-account.sh tunnel-new
    /gateway/scripts/revoke-account.sh tunnel-new
    run /gateway/scripts/enroll-account.sh tunnel-zhang
    [ "$status" -eq 0 ]
    [[ "$output" == *"tunnel-new"* ]]
    [[ "$output" == *"锁定"* ]]
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

@test "status 不改动任何系统状态，非 root 也能正常跑" {
    # tunnel-status.sh 只读登记表和进程表，要求它也必须 root 运行买不到任何
    # 安全性，只会训练操作员在所有命令前面无脑加 sudo。这是计划文档里显式
    # 拍板的设计，不是遗漏——这条用例把它钉住，免得日后有人"顺手"给它也加上
    # require_root。
    run runuser -u nobody -- /gateway/scripts/tunnel-status.sh
    [ "$status" -eq 0 ]
    [[ "$output" == *"tunnel-zhang 22001"* ]]
}
