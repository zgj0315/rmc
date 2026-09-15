# SDD ledger — plan: docs/superpowers/plans/2026-09-13-gateway-and-test-harness.md

Worktree: .worktrees/gateway，分支 feat/gateway，base 263623f
Spec: docs/方案设计.md（可达，已读）

## 环境基线

宿主 darwin。可用：docker 29.4.0（守护进程在跑）、python3 3.9.6、ssh。
缺失：tomllib（3.11+ 才有）、pytest、socat、sshpass、bats。
bats 按计划在 gateway 容器内运行，不需要宿主安装。

## 预检冲突扫描

### 每个任务自身是否自洽

| 任务 | 检查 | 结果 |
|---|---|---|
| T1 | 测试用 tomllib，宿主 python 3.9 无此模块 | 冲突，见 R1 |
| T1 | registry.toml 内容与测试里的 GOOD 样本字段一致 | 一致 |
| T2 | Dockerfile 的 COPY 路径与 compose 的 build context（gateway/）是否匹配 | 不匹配，见 R7 |
| T2 | entrypoint 里 socat 监听 2222，而 sshd-tunnel 已绑 127.0.0.1:2222 | 端口冲突，见 R4 |
| T2 | 测试从宿主发起 ssh -R，转发目标写 appliance:22，由客户端解析 | 宿主无法解析，见 R5 |
| T2 | Interfaces 声称消费 T1 的 registry.py，但 entrypoint 直接建账号 | 声明有误，见 R8 |
| T2 | 测试依赖宿主 sshpass | 缺失，见 R2 |
| T3 | 八条负向断言与 sshd_tunnel_config 的指令逐条对应 | 一致 |
| T4 | tls_wrap 固件依赖宿主 socat | 缺失，见 R3 |
| T4 | haproxy timeout 1h 长于客户端 keepalive 30s | 一致 |
| T5 | engineer.conf 的 PermitOpen 与测试断言一致 | 一致 |
| T6 | RECLAIM_BUDGET 45s 覆盖 ClientAlive 10×3 | 一致 |
| T7 | lib.sh 的 RMC_SSHD_CONFIG 与 bats setup 注入的变量一致 | 一致 |
| T7 | bats 在 gateway 容器内跑，需 Dockerfile 装 bats 并挂载仓库 | 计划已含 |
| T8 | CI 安装的宿主依赖与实际需要一致 | 随 R2/R3 变化 |

### 任务之间共享文件与接口

| 任务对 | 共享物 | 生产方 → 消费方 | 结果 |
|---|---|---|---|
| T1→T7 | scripts/registry.py 的三个子命令 | T1 产出，T7 的 lib.sh 调用 | 一致 |
| T2→T3 | sshd_tunnel_config | T2 创建，T3 依测试补齐 | 一致 |
| T2→T3,T4,T5,T6 | harness 固件、sshpass 辅助、port_listening_in_gateway | T2 放在 test_tunnel.py，其余任务跨模块 import | 脆弱，见 R6 |
| T2→T4 | gateway Dockerfile | T2 创建，T4 追加证书生成 | 一致 |
| T2→T7 | compose 的 gateway 服务 | T2 创建，T7 加 bats 与仓库挂载 | 一致 |
| T2→T5 | test-env/engineer-keys | T2 生成，T5 使用 | 一致 |
| T2→T8 | 宿主端口约定 | T2 定义，T8 的 CI 复用 | 随 R5 调整 |
| T4→T5 | haproxy.cfg 与 engineer.conf 互不相干 | 无共享 | 无冲突 |
| T6→T2 | 依赖 ClientAlive 两行 | T2 写入，T6 断言 | 一致 |

## 预检裁决

Ruling R1: registry.py 改为 `try: import tomllib except ImportError: import tomli as tomllib`，
  gateway/tests/requirements.txt 加 `tomli; python_version < "3.11"`。
  为什么：部署目标 Debian 12 是 python3.11，标准库即可；宿主与 CI 可能更低。
  错了的代价：多一个仅开发期依赖，无部署影响。

Ruling R2: 全面弃用 sshpass，改用生成的 SSH_ASKPASS 脚本配 SSH_ASKPASS_REQUIRE=force。
  为什么：sshpass 不在 homebrew core，宿主装不干净；OpenSSH 8.4+ 原生支持该机制，
  macOS 与 ubuntu-24.04 都满足。错了的代价：若某环境 OpenSSH 过旧需退回容器内跑客户端。

Ruling R3: T4 的 TLS 中继固件用 python asyncio 写，替掉宿主 socat。
  为什么：去掉一个宿主依赖，且测试已在用 python 的 ssl 模块。
  错了的代价：约 25 行测试辅助代码需要自己维护。

Ruling R4: gateway 容器内的测试旁路 socat 监听 2223，compose 发布 127.0.0.1:2422:2223。
  为什么：sshd-tunnel 已绑 127.0.0.1:2222，再绑 0.0.0.0:2222 会 EADDRINUSE。
  错了的代价：无，纯修错。

Ruling R5: 反向转发目标写 127.0.0.1:2322（已发布的一体机端口），不写 compose 服务名。
  为什么：-R 的目标地址由运行在宿主的 ssh 客户端解析，宿主不在 compose 网络里。
  错了的代价：无，纯修错。

Ruling R6: harness/tunnel 固件与 ssh 辅助函数一律放 conftest.py，测试模块之间不互相 import。
  为什么：跨测试模块 import 固件依赖 pytest 的 sys.path 插入，脆弱且难排查。
  错了的代价：无，纯改进。

Ruling R7: T2 的 Dockerfile 中 COPY 路径相对 gateway/ 构建上下文书写。
  为什么：compose 的 context 是 ..，即 gateway/。错了的代价：无，纯修错。

Ruling R8: T2 不消费 T1 的产物，Interfaces 的 Consumes 改为「无」。
  为什么：entrypoint 直接 useradd，没读登记表。错了的代价：无，纯修正文档。

## 环境补充证据

docker compose v5.1.2，`docker compose` 子命令可用。
宿主 OpenSSH_10.3p1，远高于 SSH_ASKPASS_REQUIRE 所需的 8.4，R2 成立。
注意 SSH_ASKPASS_REQUIRE 是环境变量而非 ssh -o 选项，实现时不要写成 -o。
R2 若在 T2 仍失败，退路是把 ssh 客户端放进 compose 的 client 容器内运行。

## 进度

Preflight: complete（扫描表与 R1-R8 裁决已记录）
Plan revision: 已派子代理按 R1-R8 修订计划文档，待回报
Plan revision: complete（提交 9f90436，31 个代码块改动，核对通过）
  核对项：sshpass 仅剩一处说明性散文；无 OPENSSL:；五处 -R 目标改为
  127.0.0.1:2322；两处 -L 保留 appliance:22（服务端解析，正确）；
  端口链 2422→2223→2222 在 compose/EXPOSE/entrypoint/常量四处一致；
  常量只在 conftest 定义一次；五个测试模块均改为 from conftest import。
  子代理提出的清单矛盾（-L 仍含 appliance:22）判定为我的清单写过头，采纳其保留。

Task 1: dispatched (model=sonnet, BASE=9f90436, brief=task-1-brief.md)

Task 1: Ruling: validate 只报第一个错误，不逐条累积 — 计划 Interfaces 的措辞
  与其 Step 3 代码自相矛盾，实现者按代码写并如实标出。裁定代码为准，改措辞。
  为什么：load 遇错即抛，Task 7 的三个脚本在首个错误处也必须中止，累积错误
  只服务 validate 一个子命令，需把 load 改成先收集后抛的双路径，无测试要求，
  方案文档对此无规定，YAGNI。
  错了的代价：管理员一次改多个账号时要多跑几遍 validate，可后补且不动 CLI 契约。
Task 1: implementer DONE_WITH_CONCERNS (commit c7ef6d6, 9/9 passed, TDD RED/GREEN 已记录)
  计划措辞已按裁决修正并提交 da45795，brief 已按修正重新生成。
  Task 1 reviewer: dispatched (model=sonnet, 9f90436..c7ef6d6)
Task 2: brief 已生成（488 行），debian:12-slim 镜像已预拉，等 Task 1 过关后派实现者
Task 1: reviewer 结论 spec ✅ / quality Approved，无 Critical 无 Important。
  审查者独立复核并同意 fail-fast 裁决。
Task 1: minor (deferred): load 签名比 Interfaces 文本宽松（Path | None，CLI 无参调用需要）
Task 1: minor (deferred): 空 [[tunnel_account]] 被判为不合法而非合法空列表（plan-mandated，无测试覆盖）
Task 1: minor (deferred): 畸形 TOML 与文件缺失两条路径有实现但无测试
Task 1: complete (commits 9f90436..c7ef6d6, review clean)
Task 2: dispatched (model=opus, BASE=da45795, brief=task-2-brief.md)
  已在派发中写明五条裁决为既定事实不得回改，并交代 askpass 失败时的退路
  （把 ssh 客户端放进 compose 的 client 容器），由我裁决而非实现者自行改道。
  预期 test_engineer_reaches_appliance_through_reverse_port 本任务内仍失败，
  由 Task 5 补齐工程师入口。

Task 2: implementer DONE_WITH_CONCERNS (commit b8d6d5e, 14/14 passed)
  R2 得到验证：askpass 机制一次成功，无需退路。四条疑问全部确认为真，裁决如下。

Ruling R9: Task 2 Step 4 的预期写错了，工程师测试此时会通过而非失败。
  为什么：占位 sshd_engineer.conf 只设了 PasswordAuthentication no，默认 sshd
  仍允许公钥认证与 TCP 转发，ssh -W 不需要 shell。已改计划文本并注明它此时的绿
  不构成验证，Task 5 装真配置后必须重跑。仅文档修正，无代码改动。
  错了的代价：无。

Ruling R10: 把 test_reverse_port_is_not_bound_on_external_interface 换成查容器监听表。
  为什么：原断言「宿主连不上 22001」没有约束力，该端口本就未发布，GatewayPorts
  怎么设都连不上，近乎不断言任何东西。改为断言容器内 22001 只出现在 127.0.0.1，
  不得有 0.0.0.0 / * / [::] 通配绑定。这是方案的核心安全性质，值得一个真检查。
  错了的代价：测试改动一轮；不改则该性质实际无人把关。

Ruling R11: harness 的 compose up 改为 check=False 后手动抛出含 stdout/stderr 的错误。
  为什么：check=True 配 capture_output 会把 docker 的真实报错吞成裸
  CalledProcessError，而 Tasks 3-7 全部依赖这个固件，排查成本会反复付出。
  错了的代价：无。

Ruling R12: 工程师密钥对不入库，整个 engineer-keys/ 忽略，由 conftest 的
  ensure_engineer_keypair() 按需生成，并从版本库移除已提交的 authorized_keys
  与 eng_ed25519.pub；CI 里冗余的 keygen 步骤一并删除。
  为什么：只提交公钥会让新克隆拿到配不上私钥的公钥，工程师入口测试必然失败。
  错了的代价：CI 少一个显式步骤，改由固件保证，行为等价。

计划已按 R9-R12 修订（未提交，随实现者的修复一起提交）。
Task 2: fix round 1/5 dispatched（resume 原实现者，R10/R11/R12 三项代码改动）
Task 2: fix round 1/5 (3 addressed, 0 open; commits b8d6d5e..d189817)
  含删除密钥后重跑的再生证明；实现者另主动清掉了 Fix 1 后失效的 pytest 导入。

Ruling R13: port_listening_in_gateway 的子串判断改为逐行解析 Local Address:Port 整值比较。
  为什么：查 22 会命中 127.0.0.1:2222，查 22 或 443 时返回假 True。这是会产生
  「假通过」的测试缺陷，Tasks 3-7 共用这个辅助，比一个失败的测试危险得多。
  今日无触发（只查 22001），但潜伏在共享代码里。
  错了的代价：无，纯修正。
Task 2: fix round 2/5 dispatched（resume 原实现者，R13 一项）
Task 2: fix round 2/5 (1 addressed, 0 open; commits d189817..51d9539)
  区分性验证：旧子串形式查 22 返 True，新实现 22→False / 2222→True，
  并补了 999/9999 一对，说明旧形式在那里也是错的。
  实现者独立判定通配「缺席断言」无同向弱点（前缀碰撞只增不减命中，
  故只可能误报红不可能误报绿），并提醒 Task 4 的 443 与 Task 5 的 22
  必须用整值比较，不得照抄子串写法。此提醒需带进后续派发。

Ruling R14: 把监听表查询拆成三层——gateway_listen_table 取原文、
  parse_listen_table 纯函数解析、port_listening_in_gateway 整值比较，
  并新增 tests/test_listen_table.py 用固定 ss 样本单测解析层，不起容器。
  为什么：这个辅助已两次因前缀碰撞出错（22/2222、999/9999），被 Tasks 3-7
  共用，而 Task 4 的 443 与 Task 5 的 22 正是最易碰撞的短端口。把已知脆弱
  的共享辅助留着不测，等于默默放过结构性缺陷。纯函数单测无需 docker，
  回归可秒级捕获。实现者已正确指出这需要改签名并留给我裁决，判断得当。
  错了的代价：多一轮修复与一个小测试文件；不拆则后两个任务的端口断言无人把关。
Task 2: fix round 3/5 dispatched（resume 原实现者，R14 一项）
Task 2: fix round 3/5 (1 addressed, 0 open; commits 51d9539..d248e7d)
  25/25 通过；解析层在容器全停时单独跑 11 passed，0.110s 墙钟，证实自洽。
  实现者另重建旧子串实现喂同样样本，证明两条具名回归测试真能变红（变异验证）。
  test_tunnel.py 的通配断言已改走整值路径，非可移植的子串写法已从代码库清除。
Task 2: 正式审查 dispatched (model=opus, da45795..d248e7d, 13 files 598+/20-)
  已在派发中点名三处风险要逐一检查：sshd-tunnel 配置是整个设计的安全边界且
  Match 块之后的指令归属会变；parse_listen_table 被五个后续任务共用且已错两次；
  tunnel 固件在测试中途失败时是否会漏掉活着的 ssh 进程或已注册的反向端口。

Task 2: 正式审查结论 spec ❌ / quality Needs fixes。5 Important，无 Critical。
  审查确认安全边界配置逐条正确、Match 块无放宽、五条适配均按裁决实现、
  解析器对 ss 各种地址写法均正确、通配测试用「先断言存在」防住了空表假绿。

Ruling R15: 继续用原实现者做本轮修复，不按 rounds 4-5 的规则换人升级模型。
  为什么：cap 的目的是打破卡住的循环，而前三轮每轮都一次收口，实现者还自行
  发现了额外缺陷，并未卡住。且严格说前三轮是 DONE_WITH_CONCERNS 的疑问处置，
  本轮才是首次审查发现的修复，无论怎么计都在 resume 窗口内。换人会丢掉它对这套
  docker 环境的全部上下文，需重新摸索，收益为负。
  错了的代价：若本轮不收口，下一轮必须换人并升级模型，不再延用此裁决。

Ruling R16: Important 1 的修复做成「复合性质」断言，不为隔离 GatewayPorts 而削弱 PermitListen。
  为什么：约束原文是「不信任客户端传入的地址」。审查指出在现有 PermitListen 下
  通配请求会在更早一层被拒，那仍是同一性质的有效断言。为单独隔离 GatewayPorts
  就得把 PermitListen 放宽成裸端口，那等于去测一份我们并不发布的配置。
  错了的代价：GatewayPorts 单独失效时本测试可能仍绿，但 PermitListen 仍在兜底，
  且两者同时失效才会真正暴露端口，风险可接受。

Ruling R17: systemd unit 删掉 Requires=sshd-keygen-tunnel.service，并用 ExecStartPre
  的 install -d 创建 /run/sshd，不用 RuntimeDirectory=。
  为什么：该 unit 全计划不存在，Requires 指向不可加载的 unit 会直接让启动失败，
  发布出去的配置起不来。host key 由部署手册手工生成，本就不需要 keygen unit。
  privsep 目录若靠 ssh.service 的 RuntimeDirectory，停掉 ssh.service 会连带删除，
  之后每条隧道连接都在 chroot 里失败；两个 unit 都声明同名 RuntimeDirectory 又有
  互相清理的歧义，改用幂等的 ExecStartPre 最稳。
  错了的代价：多两行配置，无。

Ruling R18: 以下 Minor 提升进本轮修复，不推迟：
  (a) 两个 sshd 加 -e 让日志进 docker logs — 现在全部日志被丢弃，会在 Tasks 3-7
      反复付出排查成本，并且堵住了 Important 2 最强的那种修法（断言 Accepted password）。
  (b) gateway_listen_table 暴露 returncode/stderr — 否则 exec 失败退化成空表，
      在 tunnel 固件里表现为 20 秒轮询后一句误导性的「反向端口未出现」。
  (c) 给 port_listening_in_gateway 补一个脱离容器的回归测试 — R14 的本意是让这个
      辅助的回归秒级可捕获，现在只做到了解析层，而两次 bug 恰恰都在这个函数里，
      改回子串匹配 11 条解析测试全绿，等于没网住。这是对我自己裁决意图的漏项。
  (d)(e) shlex 引用 ProxyCommand 路径、entrypoint 的可执行位入库 — 各一行。
  错了的代价：本轮体量变大，但均为局部改动，审查明确说无需重新设计。

## 决策 D1（用户决定，2026-09-13）

反向端口绑 0.0.0.0，远程工程师直连 `ssh -p 22001 root@gateway.company.com`，
不经工程师账号跳转。优先可用，安全收口放到后续。

我已提出反对意见并说明代价：一体机 SSH 端口变为公网可达；失去 Gateway 侧的
访问留痕；失去按人吊销的能力；每台在线设备多一个连号的公网端口，会被扫描爆破，
且被爆破的是客户设备。我建议过绑内网接口或按来源放行两种折中。用户重申原方案，
决定生效，按全量执行。

必须同步修正的不是安全措施而是文档真实性：方案 7.1 现有结论「即使 Gateway 被
完全攻陷，攻击者能到达的也只有一体机 SSH 端口」在直连模式下不再成立，因为不需要
攻陷；7.2 的「反向端口只监听 127.0.0.1」「工程师在 Gateway 无 shell」两条作废。
留着假承诺比暴露本身更糟，这部分现在就改。

### D1 的连带影响

Gateway 侧：GatewayPorts no → yes；PermitListen 改为裸端口；sshd-engineer 实例、
eng 账号、engineers 组、工程师密钥全部删除；compose 不再发布 2022。
客户端侧：几乎不动，仍请求 -R <地址>:22001:一体机:22，绑哪里由服务端决定。
界面侧：复制按钮生成的命令简化为单条 ssh。
计划侧：Global Constraints 的 loopback 约束反转；Task 2 的配置与 entrypoint、
conftest 的工程师辅助、Task 3 的通配拒绝测试、Task 5 整体、Task 7 生成的 Match
块形式、Task 8 的手册与 CI 均需改。Task 4 的 haproxy TLS 不受影响（属客户端腿）。

已发修正指令让 Task 2 第四轮跳过 change 1（加强通配拒绝测试），保留 2-8，
并要求其计划同步只如实反映当前代码，不碰绑定相关内容，以便我从真实基线修订。
D1 的文档与计划修订待第四轮落地后进行，避免编辑冲突。
Task 2: fix round 4/5 (7 addressed, 1 withdrawn by D1; commits d248e7d..b281f39)
  32 passed（18 hermetic）。change 1 已完整回滚，sshd_tunnel_config 未被触碰。
  回滚前的观测留作 D1 修订依据：通配请求是在 PermitListen 层被拒的，服务端日志
  「to remote forward to host port 22001, but the request was denied」。
  因此 D1 必须把 PermitListen 改成裸端口形式，否则绑 0.0.0.0 会在更早一层被拒。
  change 8 反转演练：改回子串形式使 3 条 hermetic 测试在 0.02s 变红（上一轮为 0 条）。
Task 2: 定向复审 dispatched (model=sonnet, d248e7d..b281f39)，findings 1 标记为已撤销

## 决策 D2（用户批准，界面）

未开启页与认证失败页的公司 Gateway 组加一行只读「远程接入 gateway.company.com:22001」，
已连接页把反向端口行改成远程接入并加「复制」按钮，复制内容为单条 ssh 命令加一体机
host key 指纹。界面上不出现 0.0.0.0，绑定地址属实现细节。
理由（新增，非重复旧论）：直连使工程师的 known_hosts 记在 Gateway 地址与端口上，
而同一端口会先后服务不同一体机，host key 变更告警将成为常态并被习惯性忽略；
指纹是唯一能确认连对设备的东西，所以复制内容必须带它。
我明确答复不加端口输入框：PermitListen 仍逐账号钉死一个端口，填别的值照样被拒，
且会先经历两分钟误导性的端口占用重试。此结论仅在运维改为按账号分配端口段时翻转。

D1/D2 修订 dispatched：文档 agent 改方案文档与计划 Tasks 3/5/7/8 及全局约束
（Tasks 1/2/4/6 不动），画板 agent 改 design/ 下八个片段与 canvas.json。
两者文件不重叠，与只读的复审并行。
Task 2: 定向复审结论 — 8 项全部 ADDRESSED，撤销项回滚确认干净（配置文件未被触碰、
  无遗留测试、通配测试逐字节未变）。复审另独立重跑了 hermetic 子集（18 passed 0.01s、
  9 passed 0.27s）并把计划 Step 1 的两段代码与真实文件逐字节比对，一致。
  新引入 1 项 Important：收尾现在经 port_listening_in_gateway 轮询 docker，而
  compose() 无超时；15 秒期限只在两次调用之间检查，单次 exec 卡住则无限阻塞，
  且 venv 里没有 pytest-timeout 兜底。这正是我在派发中点名要盯的风险。

Ruling R19: 第 5 轮仍用原实现者，不触发 R15 设定的换人条件。
  为什么：R15 的条件是「本轮不收口则换人」。第 4 轮八项全部收口，新问题是修复
  finding 5 的衍生后果，不是在同一 finding 上反复失败，循环仍在收敛。改动约十行，
  在它最熟的文件里，换人需重新摸索整套环境，收益为负。
  错了的代价：若第 5 轮仍出新问题，触发 breaker，我逐条裁决而非继续派发。

Ruling R20: 超时加在 compose() 的可选参数上，由 gateway_listen_table 传入有界值，
  不给 compose() 设统一超时。
  为什么：compose("up","--build") 合理地要跑几分钟，统一超时会误杀构建。
  从监听表这一层设界，能同时保护收尾轮询、tunnel 固件的启动等待，以及 Tasks 3-6
  所有查端口的地方。
  错了的代价：docker 极慢时监听表查询提前失败，但会给出明确错误而非静默挂死。

Ruling R21: 计划 Task 2 Step 3 的 systemd 代码块由本轮一并同步（复审的 out-of-scope 提醒）。
  为什么：真实文件已修正而计划列表仍是不能启动的旧版，属于文档落后于代码。
  我给文档 agent 的指令是不许碰 Task 2，所以交给最熟这个文件的实现者。
  错了的代价：无。
Task 2: fix round 5/5 dispatched（resume 原实现者，R20 + R21 两项）

## 决策 D3（用户告知事实，2026-09-13）

一体机默认 SSH 端口是 61001，不是 22。按默认值处理，字段仍可编辑——界面早已把
一体机地址与端口拆成两个输入框，所以这次只改数值不动结构。

Gateway 的反向端口 22001 与 443 不受影响。注意盲替换风险：22001 含 22。

附带裁决：测试环境的一体机容器也改为监听 61001（compose 发布映射变
127.0.0.1:2322:61001，宿主侧端口与 APPLIANCE_SSHD 常量不变）。
为什么：若测试用的一体机答在 22，任何硬编码 22 的代码都能通过全部测试、
到客户现场才失败。把容器改到 61001 让这类 bug 在最便宜的地方暴露。
错了的代价：无，纯提高保真度。

执行方式：三个 agent 正在改的文件都涉及这个值，故并入在途工作而非另起一轮——
文档 agent 负责方案文档全部 :22 引用与计划 Task 5 的容器端口，画板 agent 负责
八个片段的默认值与输入框宽度（54px 是按两三位数设计的，五位数要加宽）。
第 5 轮修复不加载此改动：它是 breaker 前最后一轮，不扩范围。
Task 2: fix round 5/5 (1 addressed, 0 open; commits b281f39..fe9f5b9)
  compose() 加可选 timeout（默认无界，构建不受影响），gateway_listen_table 设 20s
  并把 TimeoutExpired 转为具名 RuntimeError；15s 轮询期限保留，两道守卫分工写进文档。
  _stop_tunnel 从 finally 抛错：实现者考虑后保留，理由是端口不清会通过
  ExitOnForwardFailure 以看似不相关的方式污染后续测试，pytest 不会掩盖它，
  降级为警告是把一个响亮的真问题换成一行可忽略的提示。我认可。
  诚实缺口：实现者明确报告无法证明「真正挂死的 docker 调用会在 20s 被打断」，
  只证明了转换路径（缩小界限到低于真实耗时）。我接受这是缺口而非造假，
  并要求复审改用读源码的方式闭合这个问题。

## 并发编辑事故（已纠正，记录以备后续避免）

第五轮实现者首次提交用了 git add -A，把另两个 agent 在途的文件扫进暂存区。
它自行发现、回退，只暂存自己那一块，并比对备份确认未破坏他人文件。
我已独立验证：fe9f5b9 仅含 conftest.py 与计划里 5 行 systemd 同步，
两个 agent 的 8 个文件仍未提交，且 systemd 修复在工作树与已提交版本中都在，没有丢。
教训：同一工作树内并发派发多个会写文件的 agent 时，必须在派发指令里要求
按显式路径提交，不得使用 git add -A。本次仅靠实现者自查才没出事。
Task 2: 第 5 轮定向复审 dispatched (model=sonnet, b281f39..fe9f5b9)
Task 2: 第 5 轮复审结论 — 全部 ADDRESSED，无新增 Critical/Important。
  诚实缺口已由源码分析闭合：subprocess.run 的 timeout 经 Popen.communicate 实现，
  超时后 kill 子进程再抛出，故挂死的 docker exec 是真被终止；从 _stop_tunnel 轮询
  到 subprocess.run 是一条直线，无绕过超时的分支、无吞错的 except。
  timeout 为 keyword-only，不影响任何既有调用；构建与环境拆除仍按设计保持无界。

Task 2: complete (commits da45795..fe9f5b9, review clean)
  代价记录：1 次完整审查 + 2 次定向复审 + 5 轮修复。每轮的发现都是真问题，
  其中两条是「测试能在其所声称的性质被破坏后依然通过」这一类，最值得付这个成本。
  产出：32 个测试（18 个脱离容器），安全边界配置逐条核对，回归网经变异验证。

Task 2: minor (deferred): test_reverse_port_appears_on_gateway_loopback 与固件等待重复，实为固件冒烟
Task 2: minor (deferred): useradd/groupadd 在 set -e 下非幂等，docker compose start/restart 会杀容器
Task 2: minor (deferred): askpass 缓存目录复用，在共享 /tmp 上是预埋向量（仅测试代码，口令为固定值）
Task 2: minor (deferred): HAPROXY 常量与 run_sftp_password 无committed测试使用
Task 2: minor (deferred): socat 与两个 sshd 在 PID 1 之后无人监管，死掉容器仍显示健康
Task 2: minor (deferred): up 失败的 RuntimeError 在 try/finally 之前抛出，半启动的 compose 留在运行
Task 2: minor (deferred): entrypoint.sh 以 100644 入库，靠 Dockerfile 的 chmod +x 救
Task 2: minor (deferred): Dockerfile 装了本任务未用的 openssl 与 python3
Task 2: minor (deferred): run_ssh_password 与 run_sftp_password 四行同构，可合为一个私有函数
Task 2: minor (deferred): harness finally 里的 compose("down","-v") 仍无界，可同样挂住外层拆除
Task 2: minor (deferred): 超时被 kill 的 docker exec 会话是否在长跑中累积未验证

## 待办（两个在途 agent 落地后，由我执行）

1. 核对文档 agent 与画板 agent 的产出
2. 按显式路径分两笔提交（禁用 git add -A，见并发编辑事故）
3. 重新打包并发布画布到原链接
4. 用修订后的计划重新生成 Task 3 的 brief 再派实现者

## D1/D2/D3 修订的四条裁决

Ruling R22: 认证失败页删掉新增的远程接入行与其说明行，未开启页与已连接页保留。
  为什么：该页溢出 720px 约 12.5px，画板 agent 按指令上报而未自行压缩，做得对。
  取舍上，认证失败时什么都没连上，没有已注册端口也没有可交给别人的地址，
  这行是惰性信息，与该页唯一要传达的「口令错了、其余检查都过了」争夺注意力。
  我原来「与未开启页一致」的理由站不住，溢出把它暴露了。删掉回收约 45px，
  也给错误文案换行到第三行留出余量。
  错了的代价：两个凭据输入页略有差异，但它们本来就因状态不同而不同。

Ruling R23: 恢复 confirm-connected 被覆盖的两行，新内容作为第三行追加。
  为什么：agent 正确指出没有哪条便签写着我描述的过时内容——我那条指令基于过时记忆。
  被覆盖的两行（地址端口分开输入且连接后锁定、出网是检测值；407 时 SSPI 协商）
  在 D1 之后仍然成立，丢掉是真损失。便签在 y=-230，第三行不影响与画板的间距。
  错了的代价：无。

Ruling R24: 不改 port_listening_in_gateway 的 loopback 默认值，另加具名的
  reverse_port_registered(port)，由它知道反向端口绑在哪。
  为什么：改默认值会波及已实现并已审查的 test_listen_table.py 六处断言；
  在调用点各自传通配地址会把这个魔法值散布到 Tasks 4/6。具名辅助把绑定地址
  收在一处，将来 7.3 的加固把端口挪回内网接口时只改一个函数。
  Task 5 须同时把 tunnel 固件启动轮询、_stop_tunnel 收尾轮询、
  test_reverse_port_appears_on_gateway_loopback 三处改指向新辅助并重命名该测试。
  错了的代价：多一个函数名；不做则 GatewayPorts yes 一落地这三处全部失效。

Ruling R25: 界面草图的两处标注列对齐，宽度不够时缩短标注而非让列漂移。
  为什么：我那份 UI 规格是散文不是像素级布局，agent 把等宽草图错位当缺陷而非
  当忠实复现，判断正确。
  错了的代价：无。

D1/D2/D3 修订落地：
  画板 6ce375f（按显式路径提交，未误纳 docs），画布已发布第 5 版。
  文档 c8eb2ab（方案文档 17 节 + 计划 Global Constraints 与 Tasks 3/5/7/8）。
  我独立核对：一体机 :22 归零；GatewayPorts 仅余 3 处 no，全部在 Task 2 冻结的
  代码列表与 Task 5 的 RED 说明里，合理；PermitListen 127.0.0.1 仅余 1 处，
  在 Task 2 冻结列表里；工程师入口 13 处引用全部在 Task 2 冻结列表或 Task 5
  描述「要删掉什么」的正文中。设计文档零残留。

Ruling R26: 自行修掉 Task 6 的六处旧 helper 调用，而非只改 Interfaces 一行。
  为什么：文档 agent 按「不许碰 Task 6」把它留下，只在 Task 5 正文加了提醒。
  但 brief 是按任务抽取的，Task 6 的实现者读不到 Task 5 的正文，拿到的会是一份
  在 GatewayPorts yes 下必然失败的代码。brief 必须自足，这是真缺陷不是文档瑕疵。
  错了的代价：无。

Task 3: dispatched (model=sonnet, BASE=c8eb2ab)

## 决策 D4（用户批准，命名与分组）

界面标签「公司 Gateway」改为「运维服务器」。仅改标签，不改组件正式名称。
为什么：我最初建议保持 Gateway 并反对「运维跳板机」，理由是跳板描述的机制正是
D1 删掉的那个。用户提出「运维服务器」后我改变意见——它说的是这台机器干什么用，
不说怎么工作，因此 D1 与 7.3 的后续加固都不会推翻它；且中文界面里不需要翻译。
边界：gateway/ 目录、sshd_tunnel_config、三个脚本、CI 路径、gateway.company.com
一律不动。执行中改目录名会波及计划、CI 与运维手册，功能收益为零。
方案 3.10 开头加一句等价说明，否则将来有人会去改错的那一侧。
待观察：「运维服务器」与「维护目标」相邻且共用「维」字，评审时若觉得易混，
改「公司运维服务器」或把公司名放进副标题。

Ruling R27: 远程接入只在未开启页独立成组「交给远程工程师」，已连接页保持在链路卡内。
  为什么：用户原本质疑的是「出网」该不该独立。我判断出网应留在该组——PAC 是拿
  Gateway 的 URL 求值的，它属于这条腿。真正错位的是远程接入：该组讲我的笔记本
  往外走，远程接入讲别人往里进，方向与受众相反。但已连接页不同，那里它是已注册
  端口即链路状态，挪走会让链路卡只显示三跳中的两跳。两个状态下这一行的含义不同，
  所以位置不同是刻意的，已要求在报告中写明以防后人「修正」这个不一致。
  错了的代价：两页位置不一致需要一行注释解释。

Ruling R28: 高度不足时的回退顺序由 agent 按规则自行判定并上报，不来回请示。
  未开启页仅剩 33px 余量，新增组标题约耗 17px。顺序：①按规范分组；
  ②溢出则去掉「由运维分配」标注再测；③仍溢出则放弃分组只改名。
  禁止发明第四种方案，禁止压缩 padding、字号或改 _shell_head.txt。
  为什么：三个选项的优劣顺序我已能判断，把判定交给能实测的一方比我盲猜高度更准。
  错了的代价：可能落到选项③，界面收益减半但改名仍达成。

D4 落地（文档侧）：d7e8ef0。核对：公司 Gateway 归零，运维服务器 7 处，
  Maintenance Gateway 保留 1 处（正式名称），计划文档零命中（未被打开）。
  采纳文档 agent 的判断：已连接页链路行的「✓ Gateway」也一并改名，
  否则同一台机器在两个状态下有两个名字。

Task 3: implementer DONE_WITH_CONCERNS (commit c5433d3, 8/8 新测试, 全套 40/40)
  sshd_tunnel_config 未需改动，说明 Task 2 的配置本身是对的。

Ruling R29: 接受 agent 转发测试改为断言 sshd -T 的有效配置，不要求改回连接层面。
  为什么：我原本准备指出它漏了 -C（不带 -C 则 Match 块不参与解析，断言会变空），
  查证后发现它已经带了 user/host/addr 三项，Match 已解析。协议层面确实无信号：
  auth-agent-req 是 fire-and-forget，且 ForceCommand+nologin 让远端无 shell 可查。
  它另发现 brief 原写法根本不成立——-N 不开 session 通道，而该请求依附其上，
  所以请求连发都发不出去，ssh 只会空等超时。配置断言已用删除指令的变异验证。
  错了的代价：该条测试守的是配置而非行为，但这是协议决定的上限，非实现选择。

Ruling R30: 接受 pubkey 测试用「与允许 pubkey 的实例对照」作为验证，不要求就地变异。
  为什么：对照展示了断言在真实配置差异下的区分力，比临时改配置的变异更强。
  已要求在报告中注明 engineer 实例将在 Task 5 删除，届时该参照点消失，
  但测试本身不依赖它，只有验证过程依赖。
  错了的代价：无。

Ruling R31: 补一个参数化的配置层断言，逐条钉住纵深防御里的每一层指令。
  为什么：它诚实地发现 sftp 封堵与命令封堵各由两条指令兜底，删掉任一单层
  测试仍绿。这正是本文件要防的静默退化：有人以为 ForceCommand 覆盖了
  Subsystem sftp 就删掉后者，全绿通过而边界变薄。行为测试证明边界整体成立，
  配置断言证明每一层仍在，两者分工不同，都要。写成一个参数化测试而非 N 个，
  使那份清单可与配置文件逐条对照。
  错了的代价：多一个测试；不补则纵深防御的单层缺失无人把关。
Task 3: fix round 1/5 dispatched（resume 原实现者，R31 一项）

D4 落地（画板侧）：db2dbe8，画布已发布第 6 版。
  画板实测落在选项 3（只改名，放弃分组），余量 32.8px。
  它推翻了我设的第二档回退：去掉「由运维分配」标注省不出高度，因为行高由
  13px 的标签与地址决定，与 12px 的标注无关。选项 1 溢出 5.6px。
  我据此把方案 3.10 的草图改回不分组版并记下：若将来该页内容削减可重新分组，
  届时组名会让说明行成为冗余、可一并去掉——这是差的那 5.6px 的出处。
  另更正了「两个状态位置不同是有意的」那句，现在两边都在组内，改为讲含义不同。

Ruling R32: 不为了 5.6px 再开一轮去掉说明行以实现分组。
  为什么：分组是我提的改进，非用户诉求；当前写法不会造成误解，只是归类不够理想。
  我自己定的规则是「停在第一个放得下的选项」，为自己发明第四选项属于双标。
  收益小于再一轮改动加发布的成本，且路径已记录，将来内容变动时可低成本重做。
  错了的代价：归类略不理想，一行注释可解释。

Task 3: fix round 1/5 (1 addressed, 0 open; commits c5433d3..a7af166)
  44/44 通过。新增参数化 test_layered_directive_is_still_individually_in_effect
  覆盖 4 条指令（ForceCommand、Subsystem sftp、AllowTcpForwarding、PermitOpen），
  每条都用删除后观察 sshd -T 回落默认值的方式实测过，非凭信任列上。
  两条跟进说明也已补：-N 不开 session 通道的根因，以及 pubkey 测试的参照实例
  将在 Task 5 被删除、验证不可复现。
Task 3: 正式审查 dispatched (model=opus, 路径限定于 test_tunnel_restrictions.py)
  已授权它额外读 sshd_tunnel_config 与 conftest.py 两个文件，并点名三处风险：
  每条测试在其所指指令被删后是否真会变红；是否有测试因更早的失败而通过；
  是否重复了 conftest 已有的辅助。三条裁决也交代了可以反驳。

## Task 4 brief 预检（派发前，无阻塞项）

仿 Task 2 的预检做法逐项查过：
- R3 裁决已落实：TLS 中继为纯标准库 asyncio 实现，宿主不需要 socat。
- 中继线程 daemon=True，join 超时也不会让 pytest 退出时挂住。
- 三处跨线程等待（start_server、_close、join）全部带 timeout。
- _pump 吞掉 OSError 与 ssl.SSLError 并在 finally 关 writer，
  故 asyncio.gather 不会把连接重置抛成「Task exception was never retrieved」
  噪声——这类噪声会被审查判为测试输出不洁净。
- 端口用 0 让内核分配，再从 sockets[0].getsockname() 回报实际端口，正确。
- 定义 3 个测试函数，Step 4 预期 3 passed，一致（不是 Task 3 加测试后的过时数字）。
- 引用 port_listening_in_gateway 的 loopback 默认值：在 Task 4 运行时配置仍为
  GatewayPorts no，正确；Task 5 Step 6 再改指向 reverse_port_registered，
  且 Task 5 的 Files 已列入该文件并注明原因，跨任务交接未断（已独立核对）。

结论：无阻塞项，不需要像 Task 2 那样先修订计划。Task 4 可在 Task 3 审查收口后直接派。

## 并发策略（记录理由）

不与 Task 3 的审查并行派 Task 4 的实现者。docker 环境是本工作树唯一的共享可变
资源，harness 固件会 down -v 再 up；实现者要反复起停它，而审查者可能跑一次定向
验证。两边同时动会产生看起来像真缺陷的偶发失败，排查成本高于并行省下的时间。
审查与文档类 agent 之间可以并行（只读或不碰 docker），实现者之间不行。

Task 3: 正式审查结论 spec ❌ / quality Needs fixes。3 Important，5 Minor，无 Critical。

Ruling R30 撤销（我错了，审查以机制证据推翻）。
  原裁决：接受 pubkey 测试用「与允许 pubkey 的实例对照」作为验证，不要求就地变异。
  错在哪：sshd_tunnel_config:10 有 AuthenticationMethods password，单元素列表
  使 sshd 只通告 password，与 PubkeyAuthentication 无关；客户端
  "Permission denied (password)." 括号里回显的正是服务端通告的方法列表，
  故删掉 PubkeyAuthentication no 后该断言仍然通过。测试名指 PubkeyAuthentication，
  实际钉住的是 AuthenticationMethods。
  为什么我的验证方法在结构上必然漏掉它：参照的 engineer 实例走公钥认证，
  因此必然也没有 AuthenticationMethods password。对照同时变了两条指令，
  却把全部差异归因于其中一条。这正是 R31 要关闭的双层遮蔽，在 sftp 与本地转发
  上关掉了，唯独这里漏了——审查把我自己的裁决接到了我判错的那个case上。
  教训：以「对照另一份配置」代替「就地变异」时，必须先确认两份配置只差被测的
  那一条指令，否则对照的是两条指令之差。

Ruling R33: 撤销 R30，改为把 pubkeyauthentication no 与 authenticationmethods
  password 一并加入参数化指令清单，连接测试保留但更正其 docstring
  （现文案声称删掉 PubkeyAuthentication 会变回 (publickey)，与事实相反）。
  为什么保留连接测试：它仍然端到端证明 pubkey 不可用，只是不该以它的名义
  声称钉住了那条指令。
  错了的代价：无。

Ruling R34: 审查的 5 条 Minor 全部提升进本轮修复。
  为什么：除 #8 外均为一行改动，而本文件的全部价值就在于「断言确实会变红」。
  #4 子串匹配可被 "forcecommand /bin/false; curl evil" 绕过，这是安全测试里
  最不能留的那种弱断言；#7 失败路径丢弃 ssh 日志，与我在 Task 2 修掉的
  harness 吞错误属同一类；#8 五条指令无人断言，而参数化清单已就位，四条各一行。
  错了的代价：本轮体量变大，但均为局部改动。

已独立核实审查标为无法核实的一项：entrypoint.sh:11 确为 --shell /usr/sbin/nologin，
其关于 nologin 横幅是本文件各处真实可观测量的分析成立。
Task 3: fix round 2/5 dispatched（resume 原实现者，9 项）
Task 3: fix round 2/5 (9 addressed, 0 open; commits a7af166..f751608)
  50/50 通过，本文件 18 个（8 行为 + 10 参数化配置钉桩）。九项全做，无一反驳。
  新增与更正的 6 条 sshd -T 断言均用删除验证，唯 X11Forwarding 例外并已声明：
  OpenSSH 9.2 的默认值本就等于配置值，删掉检测不出来。这是固有局限而非缺陷——
  值等于默认值的指令无法通过删除来验证，但若有人改成 yes 它仍会变红。
Task 3: 第 2 轮定向复审 dispatched (model=sonnet, a7af166..f751608, 路径限定)
  点名三个实质问题：新断言是否真能失败（原缺陷是 docstring 与事实相反，
  换一句听起来合理的不算修好）；改成按行匹配后是否还能被空白、大小写或
  指令重复绕过；X11Forwarding 的局限是诚实声明还是断言本身无价值，
  以及该声明是写在代码里还是只写在报告里。
Task 3: 第 2 轮复审结论 — 9 项全部 ADDRESSED，无新增破坏。
  按行匹配的紧致性已逐项排除：.lower() 消掉大小写；sshd -T 以扁平
  「keyword value」重新序列化，即使来自 Match 块也无缩进；-C 归并出唯一配置，
  故每条指令最多出现一次。
  X11Forwarding 的局限判定为固有且诚实声明，且声明写在代码里（param 上方内联
  注释加表格上方块注释），不是只写在报告里——读者在抵达断言前就会看到。
  复审还验证了 finding 7 改写后的控制流不会用 pytest.fail 掩盖原始失败。

Task 3: complete (commits c5433d3..f751608, review clean)
  代价：1 次完整审查 + 2 次定向复审 + 2 轮修复。产出 18 个测试
  （8 行为 + 10 配置钉桩），sshd_tunnel_config 未需任何改动。
  本任务最大收获是推翻了我的 R30：用「对照另一份配置」代替「就地变异」时，
  必须先确认两份配置只差被测那一条指令。

Task 3: minor (deferred): 配置断言读的是磁盘上的 sshd_tunnel_config，
  未绑定到实际监听 2422 的那个 daemon；若运行实例由别的文件启动，断言仍会通过。
  文件内其他测试走的是实时实例，整体上有覆盖。

Task 4: dispatched (model=sonnet, BASE=f751608, brief 已预检无阻塞项)

Task 4: implementer BLOCKED（报得对，是我的计划 bug）
  brief 里 test_tls_handshake_succeeds_and_presents_gateway_test_cert 设
  verify_mode=CERT_NONE 后读 getpeercert()["subject"]，而 CPython 只为「验证过的」
  证书填充该字典，CERT_NONE 下恒为空 → KeyError 必然发生，与 haproxy 配置无关。
  实现者独立确认真实端点确实提供 CN=gateway.test 的证书（解 DER 仅作诊断），
  并按我的指令选择上报而非自行改写。判断得当。

Ruling R35: 不打补丁绕过，改成用测试环境自身的证书做信任锚做真实校验。
  做法：conftest 加固件经已有 compose() 从容器取出 PEM；测试改为
  load_verify_locations(cadata=pem) + check_hostname=True + CERT_REQUIRED，
  以 server_hostname="gateway.test" 连接，此时 getpeercert() 有内容，主题断言成立。
  为什么比原方案强：从「连上了一个会说 TLS 的东西」变成「完成了针对这张证书、
  这个名字的受验握手」，正是我在派发里要求的「能区分握手成功与连上非 TLS 服务」
  的最强形式；同时免掉了 ssl._test_decode_cert 这类私有 API 的诱惑。
  自签证书可作自身信任锚；固件在运行时从容器取 PEM，镜像重建后自动对齐，不脆。
  错了的代价：多一个固件与一次容器内 openssl 调用。

Ruling R36: 顺带收紧版本断言。原文 tls.version().startswith("TLSv1.") 也能匹配
  TLSv1.0/1.1，而 haproxy 配置写的是 ssl-min-ver TLSv1.2，断言比配置弱。
  改为要求协商结果落在 {TLSv1.2, TLSv1.3}，这样它才真正钉住 min-ver 那一行。
  错了的代价：无。这是我原稿的疏漏，与本次 BLOCKED 同源——断言弱于它声称的性质。

Ruling R37: tls_wrap 中继保持 CERT_NONE 不变。它的职责是传输而非校验，
  等价于原先 socat 的 verify=0，不要连它一起「修」。
Task 4: fix dispatched（resume 原实现者，R35+R36+计划同步）

Task 4: implementer DONE (commit 093c9a9, 3/3 本文件, 全套 53/53)
  R35 与 R36 均按裁决实现。区分力验证方式正确：固定证书只改 server_hostname，
  得到 SSLCertVerificationError: Hostname mismatch——严格遵守了 Task 3 教训里
  「对照时只变一个变量」那一条。
  实现者另报一个 asyncio 警告：test_reverse_tunnel_works_over_tls 收尾时
  稳定打印「Task was destroyed but it is pending!」。它按我「别动中继」的指令未处理。

Ruling R38: 该警告必须修，我的「别动中继」指的是不要给中继加证书校验，不是忽略噪声。
  这同时推翻我自己的 brief 预检结论——我当时判断 _pump 吞掉 OSError/SSLError
  就不会产生未回收任务噪声，错了：噪声源不是 pump 抛异常，而是 stop() 在仍有
  在途 _handle 任务时直接 loop.stop()，任务于 GC 时报「destroyed but pending」。
  修法：_close() 里关完 server 后，先 cancel 掉除自身外的全部任务并以
  gather(..., return_exceptions=True) 等它们收干净，再停循环。
  为什么现在修而不留给审查：测试输出洁净是审查的明文判据，必然被打回；
  且中继会被 Task 5 继续使用，噪声会一直带下去。
  错了的代价：无。
Task 4: fix round 1/5 dispatched（resume 原实现者，R38 一项）
Task 4: fix round 1/5 (1 addressed, 0 open; commits 093c9a9..71c72d7)
  在 _close() 里关完 server 后 cancel 在途任务并以 gather(return_exceptions=True)
  收干净再停循环；未加宽 _pump 的 except（加宽会让中继停不下来）。
  警告消失，两次隔离重跑确认；全套 53/53 且 grep 无任何 warning/traceback 文本。
  实现者确认全套无其它噪声基线。
Task 4: 正式审查 dispatched (model=opus, f751608..71c72d7)
  点名三处风险：受验握手是否真的绑定端点身份（信任锚是否来自实时容器、
  check_hostname 是否被悄悄绕过、换错证书是否也会失败而非只有换错名字才失败）；
  中继的线程收尾是否有界（取消会不会挂住、drain 的异常能否越过 join 逃逸）；
  haproxy 的超时与客户端 keepalive 的关系（会不会在客户端自身活性判定之前
  就掐断一条健康的空闲隧道）。两条裁决也交代了可以反驳。

Task 4: 正式审查结论 spec ❌ / quality Needs fixes。3 Important（全为 plan-mandated），
  6 Minor，无 Critical。审查确认两条裁决均实现正确，并给出关键证据：
  ssl.SSLContext(PROTOCOL_TLS_CLIENT) 的信任库初始为空（只有 create_default_context
  才加载系统 CA），所以从容器取来的 PEM 是唯一锚点——换任何其它签发者都会失败，
  不只是换错名字才失败。这正是我要它确认的那件事。
  它还确认 haproxy 的 1h 是不活动计时器，而 keepalive 每 10 秒产生双向流量，
  健康空闲隧道不会被掐断；timeout tunnel 属 HTTP upgrade 概念，正确地未出现。

Ruling R39: Important 1 必须修——test_reverse_tunnel_works_over_tls 失败时会挂死而非报错。
  它用 proc.stderr.read() 读 PIPE，而 popen_ssh_password 的 docstring 明文禁止这一用法：
  没人读的管道写满会卡死 ssh，且进程活着时读不出已有内容。失败模式下 ssh 仍活着，
  没有 EOF，pytest.fail 永远到不了，venv 里也没有 pytest-timeout 兜底 → 红色运行
  会楔住整个套件。tunnel 固件早已用临时文件加 output() 解决，照它改，并补上
  循环内的 proc.poll() 提前退出检查（现在 ssh 立即死掉也要白等满 20 秒）。
  这是本项目第三次遇到「失败路径本身有缺陷」，前两次是断言在什么都没发生时通过，
  这次是失败时根本报不出来——同一类问题的镜像版本。

Ruling R40: Important 2 必须修——收尾不等反向端口消失就返回。
  _stop_tunnel 正是为此存在且写明了理由。本文件与 tunnel 固件共用 22001，
  而按字母序 test_tls_frontend 紧排在 test_tunnel 之前，后者用
  ExitOnForwardFailure=yes 连同一端口 → 释放慢一点就让下一个文件失败。
  一次跑绿不能证明没问题，这是潜伏的偶发失败，且本代码库已被同类问题咬过。

Ruling R41: Important 3 必须修——haproxy 只加固了从不被协商的那一半 TLS。
  ssl-default-bind-ciphersuites 只管 TLS 1.3；管 ≤1.2 的 ssl-default-bind-ciphers
  未设，于是 TLS 1.2 连接从 OpenSSL 默认集里选，含 CBC-SHA1 与非 PFS 的静态 RSA。
  而本机 venv 是 LibreSSL 2.8.3、最高只到 TLS 1.2，所以套件里没有一条连接会走到
  1.3——那唯一一行密码套件配置对所有实际连接都是空转。配置写着 AEAD-only 的意图，
  在真正生效的版本上完全没实现，而这份文件生产环境只改证书路径就复用。
  加 ssl-default-bind-ciphers ECDHE+AESGCM:ECDHE+CHACHA20。

Ruling R42: 6 条 Minor 全部提升。理由各异但都值得现在做：
  #4 版本断言仍不钉住 ssl-min-ver（客户端最高只到 1.2，删掉该指令断言仍绿），
     补一个负向探测：把客户端 maximum_version 压到 1.1 应握手失败。
  #5 stop() 缺 try/finally——wait_closed() 抛错会跳过 loop.stop/join/close，
     daemon 线程整场跑 run_forever；join 超时又会让 loop.close() 抛
     RuntimeError 掩盖真实超时。Task 5 还要复用这个固件。
  #6 第三次复制 compose 抓取的错误处理，抽 _compose_capture；conftest 是五个任务
     共用的文件，第三次重复就是该抽的时候。
  #7 计划里 1h 超时的理由写错了机制（把 30 秒回收预算说成不活动超时的下限），
     这是我的原文，一并改。
  #8 openssl req 的 2>/dev/null 掩盖诊断信息。
  #9 补 test_reverse_tunnel_works_over_tls 的 docstring，同文件另两个都有。
Task 4: fix round 2/5 dispatched（resume 原实现者，9 项）
Task 4: fix round 2/5 (9 项：8 项按裁决实现，1 项以实验推翻我的前提；commits 71c72d7..45d6265)
  53/53 通过，无告警回溯；三处要求的演示均给出真实前后输出。

Ruling R43: 接受 item 4 的实测结论，不再追求钉住 ssl-min-ver TLSv1.2。
  实现者带/不带该指令各重建并核对配置后实测：haproxy 2.6.12 自身默认即拒绝
  TLS 1.0/1.1，负向探测两种情况表现一致，故它验证的是真实性质但钉不住那一行。
  它保留探测并把 docstring 改为如实陈述，而非写上已被证伪的说法——正确做法。
  这与 Task 3 的 X11Forwarding 同类：值等于默认值的指令无法通过删除检测。
  按 R31 的同一逻辑处理：接受为固有局限，要求声明写在代码里；断言仍能在有人
  把配置放宽到 1.0/1.1 时变红，且指令本身作为显式意图与跨 haproxy 版本的保险仍应保留。
  错了的代价：若换用默认更宽松的 haproxy 构建，该指令失效不会被测试发现；
  但配置文件里它仍在，且属于部署时可核对的项。
Task 4: 第 2 轮定向复审 dispatched (model=sonnet, 71c72d7..45d6265)
Task 4: 第 2 轮复审结论 — 9 项全部 ADDRESSED，无新增 Critical/Important。
  复审逐项验证了共用机制改动未回归：_compose_capture 抽取后两个调用点的错误
  字符串与旧文逐字节一致、边界与抛出行为不变；try/finally 重构后 cancel-drain
  仍在停循环之前执行；失败路径改写后 log 在每条路径关闭、提前退出检查与
  tunnel 固件逐行一致。
  Minor 4 的说明判定为真实且位置恰当：读完该 docstring 的人不会误以为
  ssl-min-ver TLSv1.2 被断言覆盖。

Task 4: complete (commits f751608..45d6265, review clean)
  代价：1 次 BLOCKED（我的计划 bug）+ 1 次完整审查 + 2 次定向复审 + 2 轮修复。
  产出 3 个测试与 TLS 终止配置；套件 53/53。
  两处收获：受验握手因 PROTOCOL_TLS_CLIENT 初始信任库为空而成为真正的身份绑定；
  配置只加固了从不被协商的那半边 TLS，是「意图写了但在生效版本上没实现」的典型。

Task 4: minor (deferred): popen_ssh_password 在 proc 赋值前抛出时 log 不会关闭；
  与 tunnel 固件同源（Important 1 要求照抄该形状），概率极低。
Task 4: minor (deferred): haproxy.cfg 的 ssl-min-ver 行旁没有指回测试覆盖为间接的注释；
  从配置侧入手审计的人找不到那段说明。纯装饰性。

Task 5: dispatched (model=opus, BASE=45d6265)

Task 5: implementer DONE_WITH_CONCERNS (commit c2eb8e7, 53 passed，两处预期红态均按预测复现)
  四个疑问全部为正确判断，其中两个拦下了真实退化：

Ruling R44: 采纳其拒绝照抄 Step 6 代码片段的决定。
  那些片段是 Task 4 评审「之前」的旧版：import 少了 _stop_tunnel（NameError），
  失败路径退回 proc.stderr.read()——正是 Task 4 Important 1 刚修掉的挂死 bug，
  且该进程 stderr=None。照抄会静默撤销一个已修复的缺陷，是最坏的一类结果。
  它只改了 helper 调用与 import 名。计划需同步以免下次再挖同一个坑。

Ruling R45: 采纳其对 PermitListen 理由的实测更正，并据此改写方案 4.2。
  我原写「带地址时通配绑定会在 GatewayPorts 之前先一层被拒」，实测不成立。
  真实机制其一：现场命令 ssh -R 22001:... 的监听主机是 localhost，与
  127.0.0.1:22001 非字面相等而被拒。其二（我原本没有、且更强）：GatewayPorts yes
  下绑定地址完全由服务端决定，恒为通配，故在 PermitListen 里限地址一分安全不买，
  只挡合法客户端。它选择重写配置注释而非在生产配置里留一句假解释，判断正确。
  方案 4.2 已同步更正。

Ruling R46: 接受其越界修改 test_tunnel_restrictions.py。
  一体机迁到 61001 使该文件 -L 测试的转发目标变成死端口，而那个端口选择正是
  Task 3 评审 Minor 6 的产物，用来给「零字节」断言提供区分力。不动它等于让一条
  被评审专门加强过的测试静默退化。它只改目标端口与三处失真 docstring，断言未动。
  要求把该文件补进 Task 5 的 Files 列表并注明理由，使这次越界记录为有意为之。

Ruling R47: Step 5 的核验命令改用 /proc/net/tcp——appliance 镜像无 iproute2。
Task 5: 文档同步 dispatched（resume 原实现者，仅改计划三处，不动代码）
Task 5: 文档同步完成（commit 7a34811，仅计划，未动代码）。
  实现者另主动报出两处「照做而非绕开」的地方，以免审查意外：
  (a) tunnel 固件仍请求 -R 127.0.0.1:22001，而现场命令不带地址（发 localhost）；
      brief 要求别动，它验证了两种形状在当前配置下都能注册。
  (b) test_listen_table.py 三处注释仍写「Task 5 的 22」，现已失真；brief 明令不许碰。
  我那处方案 4.2 的更正单独提交为 9160e6f。

Ruling R48: (a) 提为审查的具名风险而非直接放过。
  理由：若有人把 PermitListen 改回带地址形式，固件用的显式地址请求仍会被接受、
  套件保持全绿，而真实现场命令会失败——这正是本项目反复在抓的那类「测试通过
  而生产坏掉」。已要求审查判断这是否是真覆盖缺口、以及套件里是否有别的东西兜住。
  我没有直接下令修，因为 brief 明确要求别动该固件，需先确认缺口真实存在。

Ruling R49: (b) 记为延后 minor，交最终全分支复审分流，本轮不开。
  理由：三处注释失真，不影响任何断言；而该文件被刻意冻结以保护 18 条已评审断言。
  已在审查派发中声明为「已知且刻意延后」，免得它消耗一个 finding 名额。
Task 5: 正式审查 dispatched (model=opus, 45d6265..7a34811, 12 files)

Task 5: 正式审查结论 spec ✅ / quality Approved。2 Important（均为附加一行），3 Minor。
  审查逐项确认：删除彻底（配置、entrypoint、compose、镜像、固件、systemd 六处无残留，
  且核查了删掉 sshd_engineer.conf 是否会连带移除生产 sshd 的 PasswordAuthentication no
  ——其唯一消费者就是本次删掉的那行 COPY，计划里它本就是占位）；三处实时调用点
  全部改指向新 helper，test_listen_table.py 的 18 条断言真正未动且仍然有效。

Ruling R50: Important 1 用「新增一条具名测试」而非「改共用固件」来封堵。
  审查给了两个选项：把 tunnel 固件改成发现场形状（-R 22001:…），或新增一条测试
  单独开一条裸端口形式的隧道并断言注册成功。选后者。
  为什么：审查自己在 Minor 4 里指出，固件层面的失败会表现为 fixture ERROR 而不是
  某条具名测试变红。把不变量押在固件上，回归时得到的是一片错误而非一句「裸端口
  形式的 PermitListen 被改坏了」。且 Task 6 即将消费这个固件，此时改动共享行为
  会让四个任务的测试同时位移。新增测试只增不改，信号还更准。
  错了的代价：固件仍不走现场形状，但现场形状已由新测试独立覆盖。

Ruling R51: Important 2 必须修——全局补 PermitListen none。
  这是本任务引入的真实回归，不在客户接受的范围内：GatewayPorts yes 之前，一个漏配
  Match 块的 tunnel-* 账号能绑任意端口但只在 loopback；之后变成任意端口绑 0.0.0.0、
  公网可达。客户接受的是「一账号一端口、公网可达」，不是「任意端口」。
  而生成 Match 块的 enroll-account.sh 要到 Task 7 才存在，当前没有任何东西保证
  每个账号都有块。加一行全局 PermitListen none，由各 Match 块逐账号覆盖，
  把「漏配即公网任意端口」变成「漏配即完全不能转发」。

Ruling R52: Minor 3 与 5 提升（均为「文档已失真」类，非打磨）。
  #3 注释声称全套只有一处知道反向端口绑在哪，而 test_tunnel.py 有一处硬编码同样的
  地址元组——该测试硬编码是对的（从被测常量推导断言会变成循环论证），所以要改的是注释。
  #5 pubkey 测试的 docstring 仍引用本任务刚删掉的 engineer 实例做对照实验，
  读者已无法复现它所引用的证据。
Ruling R53: Minor 4 延后——那条测试被其下方测试完全覆盖，但属 brief 原有形状，
  记为 7.3 落地时应删除而非更新的对象。
Task 5: fix round 1/5 dispatched（resume 原实现者，4 项）
Task 5: fix round 1/5 (4 addressed, 0 open; commits 7a34811..0720d1f)
  54 passed（-W error，无告警）。两项 Important 均以实测对照验证：
  配置改回带地址形式 → 1 失败 53 通过，失败的正是新测试，12 秒内经提前退出路径
  报出 remote port forwarding failed；已登记账号解析得 permitlisten *:22001，
  未登记账号得 none，sshd -t rc=0。
  实现者另报我文档漂移（方案 4.2 清单缺全局默认拒绝），已补并提交 604e1b3。

Task 5: 第 1 轮复审结论 — 4 项全部 ADDRESSED，无新增破坏。
  复审独立确认：新测试读的是容器自身监听表，不存在经宿主可达性或残留注册
  通过的路径（每个用 22001 的用例都经 _stop_tunnel 阻塞到端口消失）；失败路径
  用临时文件而非管道、轮询前先查 proc.poll()，故不可能挂死。
  PermitListen none 位于全局段且在 Match 块之上，语义正确；Task 3 的两条边界
  测试以 tunnel-zhang 身份请求 22002，仍受逐账号覆盖管辖，不受新行影响。
  conftest 中除 REVERSE_BIND_ADDRS 的注释块外，其余函数与固件逐字节未变。

Task 5: complete (commits 45d6265..0720d1f, review clean)
  代价：1 次完整审查 + 1 次定向复审 + 1 轮修复 + 1 轮文档同步。
  这是改动面最大的任务：翻转核心指令、删除整个 sshd 实例、迁移容器端口、
  改动四任务共用的固件。实现者四次上报 brief 缺陷，每次都对。
  最大收获：审查发现本任务引入了一处超出客户接受范围的回归（漏登记账号
  从「任意端口仅 loopback」变为「任意端口公网可达」），由一行全局默认拒绝封堵。

Task 6: dispatched (model=sonnet, BASE=604e1b3)

Task 6: 实现者在未完成状态下停机——声称在等自己的后台验证与 Monitor，
  但已无存活子任务，无人会回报。我自查实际状态：
  test_zombie_port.py 已写但未跟踪，零提交；compose 环境已停；
  且存在一个泄漏的冻结 ssh 进程（PID 13008，状态 T，仍持有反向端口注册，
  在容器拆除之后仍然存活）。我已 SIGCONT 再 SIGTERM 清除，环境现已干净。

Ruling R54: 该泄漏记为实现缺陷而非停机意外，要求在提交前修复并验证。
  机制：被 SIGSTOP 冻住的进程无法被 SIGTERM 终止，故任何只调 terminate()
  的收尾都会让它永久存活。收尾必须在所有路径（含测试失败与出错）上先无条件
  SIGCONT，再终止并回收。要求以「故意让测试失败」来验证，而非声称。
  为什么必须现在修：一个占着 22001 的冻结进程会让此后每个用例都失败，
  且失败现场与真实原因相距甚远，排查成本极高。

Ruling R55: 禁止该任务使用后台任务或 Monitor，一律前台执行。
  这个任务的测试本就慢（要等满约 45 秒的回收预算），前台跑几分钟是正常的；
  把它丢到后台再等回报，正是这次停机的直接成因。

Task 6: BLOCKED（报得对，停下来而不是悄悄调大预算让测试变绿）
  实测回收耗时约 80-81 秒（测两次：80.1s、81.2s），稳定可复现，非机器抖动；
  而方案第 303 行承诺「ClientAlive 保证异常断线后 30 秒内回收」。
  实现者另发现 brief 里 start_tunnel() 的第五处缺陷：用了 PIPE 默认值，
  在 -W error 下 ResourceWarning 变异常，会掩盖真实失败原因。已按 tunnel
  固件的临时文件写法修正。收尾已加固为全路径 SIGCONT + _stop_tunnel，
  并以「故意让两个测试失败」验证过无残留。

Ruling R56: 先做一次诊断把两件事分开，再决定改预算还是改文档。
  关键假设：测试测的是「22001 从监听表消失」，而 ClientAlive 管的是「会话结束」，
  这是两个事件。若会话在约 30 秒结束而监听套接字又滞留约 50 秒，那问题不在
  ClientAlive，方案那句话的修法也完全不同。
  诊断方法：临时把隧道 sshd 的 LogLevel 调到 DEBUG（Task 2 已加 -e，日志进
  docker logs），记录冻结时刻，同时观察两个时间点——sshd 记录断开的时刻，
  与 22001 从表中消失的时刻。一次运行即可劈开假设空间。做完还原 LogLevel。
  为什么不直接改预算：80 秒这个数字要写进方案与运维手册，而客户端 120 秒的
  端口占用预算的安全余量会从「以为的 90 秒」变成「实际 40 秒」。
  在不知道机制的情况下改数字，等于把一个未理解的行为固化成规格。

Task 6 诊断结论：我的假设被证伪。会话断开 +80.108s，端口消失 +80.513s，
  相差 0.4 秒——同一个事件，不存在滞留的监听套接字。确系 ClientAlive 在
  约 80 秒才放弃，约为 interval×countMax 名义值的 2.7 倍。
  debug1 下探针收发不记录（需 debug2/3），实现者按指令未擅自提高级别，
  且拒绝使用早先一次不同范围会话里未带时间戳的片段作为证据——证据纪律正确。
  它另自查出首次尝试的方法论错误（exec -d 的输出不进容器日志流）并修正重跑。

Ruling R57: 再做两个各只变一个变量的实验，然后才决定数字与文案。
  实验一，变 ClientAliveInterval（5 与 10 各测一次）：若 80 秒随之减半，
  说明是倍率关系，可据此反推出能得到约 30 秒的取值；若基本不变，说明是固定
  开销，调 interval 无用。这直接回答「要不要改配置」。
  实验二，变路径（2422 的 socat 旁路 与 8443 的 haproxy+TLS）：后者才是生产
  实际路径，测它得到的才是要写进文档的数字；两者若有差异则说明中继参与其中。
  为什么值得再花两轮：这个数字要进方案、进运维手册，并决定客户端端口占用
  重试预算的安全余量——原以为 120 秒对 30 秒是绰绰有余，实际是对 80 秒只剩
  40 秒。写错的代价是现场工程师干等 80 秒而文档说 30 秒，支持成本很高。

Task 6 实验结论（四次测量，各只变一个变量，均已还原且确认无残留）：
  A1 interval=5 → 40.074s；A2 interval=10 → 80.106s；比值 1.999 对 2.000。
  B1 旁路 interval=10 → 79.512s；B2 生产路径 TLS→haproxy → 79.517s，相差 5ms。
  结论一：放弃时间 = 8.01 × ClientAliveInterval（CountMax=3 下），倍率关系成立。
  结论二：路径无影响，中继未参与，haproxy 的 1h 超时与此尺度无关。
  未验证的假设（明确标注为假设）：8 ≈ 2×(CountMax+1)，即每一次计数耗时两个
  interval（等一个间隔后发探针，再等一个间隔收回复）。CountMax 未变动，故不下结论。

Ruling R58: 保持 ClientAliveInterval 10 / CountMax 3 不变，不为缩短回收而调小。
  为什么：调到 4 可得约 32 秒回收，但代价是 Gateway 在 32 秒静默后就判定客户端
  已死并拆掉隧道——而拆掉隧道会同时打断远程工程师正在进行的维护会话。
  客户现场网络抖动、漫游、VPN 重连造成三十秒级停顿是可能的。
  用「误杀一条活着的维护会话」换「睡眠唤醒后少等 48 秒」，方向是错的。
  错了的代价：现场重连要等约 80 秒而非 30 秒；但这是等待，不是中断。

Ruling R59: RECLAIM_BUDGET 设为 110 秒，不用 brief 的 45。
  为什么：实测 79.5-80.1 秒，45 秒根本不可能通过。110 对 80 有约 37% 余量，
  同时低于客户端端口占用重试的 120 秒上限——即测试会在「产品真正会坏」之前失败，
  这正是这条测试该守的位置。不设成 120 是为了让测试先于产品报警。
  错了的代价：失败时要等 110 秒；通过时约 80 秒。慢，但这个测试本就是计时测试。

Ruling R60: 方案与运维手册按实测改写，并标出机制。
  4.2 的「30 秒内回收」改为实测约 80 秒，并写明机制：OpenSSH 9.2p1 上
  放弃时间约为 8 × ClientAliveInterval，不是 interval × CountMax。
  「异常恢复时间在 30 到 60 秒」改为约 80 到 90 秒。
  并点明客户端 120 秒的端口占用预算对此只剩约 40 秒余量——这是要盯的数字。

Ruling R61: 标出对客户端的连带影响，留给 rmc-core。
  方案 3.4 写客户端「每 10 秒 keepalive，3 次无应答判定断线」，隐含 30 秒，
  与 Gateway 侧被证伪的是同一套算术。rmc-core 用 russh 而非 OpenSSH，实现可能
  不同，所以必须实测而不是沿用假设。在方案里写明这一点，让建 rmc-core 的人看到。
  为什么不直接改 rmc-core 计划：那是另一份计划，且 russh 的行为未测，
  此处只应留下「必须测量」的指示，不应替它假定数字。
Task 6: 实施轮 dispatched（resume 原实现者，R58-R61 四项）

## 用户确认（2026-09-13）

R58「保持 ClientAliveInterval 10，接受约 80 秒恢复」经用户确认，升级为产品决定。
我已向用户说明取舍：调到 4 可得约 32 秒，但代价是 Gateway 在 32 秒静默后判定
客户端已死并拆隧道，会切断远程工程师正在进行的维护会话；且改一行配置在上线前
几乎无成本、上线后要重新验证。用户答复可接受。
要求写进方案：注明曾考虑调快并经权衡后决定不调，否则将来有人会把 80 秒当疏漏「修掉」。

Task 6: 正式审查结论 spec ✅ / quality Needs fixes。3 Important + 1 范围问题，无 Critical。
  审查确认四条裁决均正确落地，并逐项核过：预算 110 的 120 秒上界引用属实；
  余量算术取最坏对齐，方向保守；未验证假设的标注到位；3.4 的注记只指示实测、
  未断言任何客户端数字。它还独立验证了「收尾复用旧验证」的推理成立——
  RECLAIM_BUDGET 只在两处断言里读取，从不进入 finally，SIGCONT 是 finally 的
  无条件首句，故预算 45 的真实失败运行确实覆盖了出厂失败路径。

Ruling R63: Important 1-3 全修，均为几行。
  最关键是 1：send_signal 对已退出的子进程是静默空操作，而 start_tunnel 不查
  proc.poll()。若 ssh 客户端在注册与冻结之间死掉，端口因客户端死亡而消失，
  测试一秒变绿，ClientAlive 根本没被触发——正是本项目反复在抓的假绿形状。
  2 与 3 是同一类:失败时报不出真实原因。2 里 kill 不 wait 导致 ResourceWarning
  在 -W error 下变成异常，会盖掉真正的 pytest.fail；3 里捕获的 ssh 日志被丢弃，
  本文件最有价值的那次失败（端口无法重新注册）只会报一句「反向端口未建立」。

Ruling R64: 计划文档里残留的六处「30 秒」现在就改，不推给全分支复审。
  其中 :2568 是要写进客户运维手册的排障表行「等 30 秒，客户端会自动重试」。
  本分支已有先例（7a34811「去掉三处会被照抄的陷阱」）：在发现问题的任务内修掉。
  留着等于让后来的实现者从计划里重新推导出那个已被证伪的数字。

Ruling R65: 补做 RED 演示。审查指出 ClientAliveInterval 0 的红态只在预算 45 下
  跑过，出厂常量 110 背后没有红。约四分钟。计时测试的全部价值就在于它会失败，
  出厂的那个数字必须有红态背书。

Ruling R66: 四条「文档精确性」Minor 提升，不算打磨。
  比值写作 8.01/8.02 而实际算术为 8.015/8.011；测量带写 79.5-80.1 与 37% 余量，
  而最终运行实测 81.03/81.54、实现者自己改口 27%；「调小到 4 能压到约 32 秒」
  被当作事实陈述，而 4 从未测过（只测了 5 和 10）。这份文档在别处一直严格区分
  实测与推算，这三处破了自己的规矩。第四条是两个测试里 SIGSTOP 一个在 try 内
  一个在 try 外，不对称会诱使后人在中间插入可抛异常的语句而泄漏隧道。
Task 6: fix round 1/5 dispatched（resume 原实现者）
Task 6: fix round 1/5 (9 addressed + 拍板注记, 0 open; commits ec878e2..72530ac)
  56 passed（-W error, 171s）。两处演示均给真实输出：
  RED 在出厂预算 110 下重跑，两个测试失败于 234.63s 并带诊断信息（非挂死非误过）；
  假绿防护演示：故意在冻结前杀掉客户端，13.55s 失败并报出「注册之后、冻结之前
  就已退出（退出码 -9）」，而非通过。
  复审自行重算：40.074/5=8.015、80.106/10=8.011，与文档一致；余量
  110-81.6=28.4s≈26%，与文档一致。并确认存活检查与循环退出条件同刻求值，
  故等待过程中死亡也会被抓到，不只是循环前。

Task 6: complete (commits 604e1b3..72530ac, review clean)
  代价：1 次 BLOCKED + 1 次诊断 + 1 次对照实验 + 2 轮修复 + 1 次审查 + 1 次复审。
  这是全计划最长的一个任务，但产出不止两个测试：它推翻了一个写进方案与客户
  运维手册的错误数字（30 秒实为 80 秒），并把「哪些是实测、哪些是推算」分清楚了。
  用户已确认 80 秒可接受，该取舍升级为产品决定并记入配置与方案。

Task 6: minor (deferred): _log_output 与 conftest 里 tunnel 固件的 output 闭包近乎重复
Task 6: minor (deferred): _stop_tunnel 已被三个模块导入，下划线前缀已无意义
Task 6: minor (deferred): 第一个测试被第二个完全覆盖，若套件耗时成问题可删前者
Task 6: minor (deferred): 回收超时信息里的 gateway_listen_table() 可能抛 RuntimeError
  取代预期措辞（docker 层故障时），属项目既定的「大声失败」约定，非静默掩盖

Task 7: dispatched (model=sonnet, BASE=72530ac)

Task 7: implementer DONE_WITH_CONCERNS (commit d049441, bats 12/12, pytest 56/56 -W error)
  它在我的计划代码里用 TDD 找出并修掉三个 bug：revoke 调用不带过滤的重写函数
  故删不掉被吊销账号的块；重写函数的循环变量未声明 local，经 source 覆盖调用方
  同名变量使收尾提示静默变空；die() 用 $* 而非 $1，把退出码泄进错误文本。
  并补了 brief 漏掉的「全局默认拒绝在重生成后仍全局生效」测试。

Task 7: 正式审查结论 spec ❌ / quality Needs fixes。1 Critical、6 Important。
  审查独立复核了实现者「那是唯一能抓静默移除的测试」的说法——逐条走完其余 11 条
  断言，确认全部会在默认拒绝被移除时保持绿色，claim 属实。

Ruling R67: Critical 1 必修——revoke 只判「账号是否存在」，不判 tunnel-* 前缀。
  后果：revoke-account.sh root 会 passwd -l root 再 pkill -u root，杀光 Gateway
  上全部 root 进程（sshd、haproxy、运维自己的会话）；revoke haproxy 杀掉 TLS 前端。
  enroll 因 registry_get 而免疫，revoke 没有等价关卡。加前缀白名单并补测试。

Ruling R68: Important 2 必修——rewrite_match_block 永远作为 if 条件被调用，
  这会关掉其内部的 errexit；且 lib.sh:61 从进程替换读取，退出状态不可观测。
  后果：登记表损坏时，吊销任一账号会生成只剩标记的空区域，通过 sshd -t、写入、
  重载，并打印「已移除端口放行并 reload」后正常退出——全部账号的端口放行同时消失。
  修法：先把清单捕获进变量并显式判错，awk 的状态显式检查，「无变化」用独立返回码
  表达，使调用方不必用 if 吞掉错误。

Ruling R69: Important 3 改约束而不是改脚本——tunnel-status.sh 不要求 root。
  为什么：它只读登记表并 pgrep，不修改任何东西。对只读命令强制 root 没有安全收益，
  反而训练运维习惯性 sudo，那是更坏的习惯。全局约束改为「会修改系统状态的脚本
  必须在非 root 时立即退出」，并在 Task 8 的手册里写明 status 无需权限。
  错了的代价：无。

Ruling R70: Important 4 必修——吊销会被下一次无关的 enroll 撤销。
  revoke 刻意不动 registry.toml（我的设计），于是 enroll 任何其它账号都会把被吊销
  账号的块重新生成，只剩锁定的口令挡在它和一条可用隧道之间。
  采用审查建议的方向：enroll 在发现「登记表中列着、本机存在、口令已锁定」的账号时
  拒绝或大声告警，而不是让 revoke 去改登记表——保持登记表是人工维护的唯一事实来源。
  同时补测试：revoke 必须保留其它账号的块（现无任何测试覆盖这半个性质）。

Ruling R71: Important 5 必修——没有任何测试拿真实配置跑过生成器。
  夹具的全局段 2 行，真实文件 55 行，故那条默认拒绝测试守的是夹具不是真配置。
  它还掩盖了一处真实不一致：生成器会在区域内插入一行注释，而入库的配置文件没有，
  于是生产环境第一次 enroll 会走一条从未被测过的重写加重载路径。
  补一条 bats 用例：把真实配置复制进夹具路径，跑 enroll，再断言默认拒绝的
  条数与位置，以及 sshd -t 通过。

Ruling R72: Important 6 必修——status 的 online 分支零覆盖。
  pgrep 若永不匹配，所有账号永远报 offline 而十二条测试全绿。而 OpenSSH 9.8+
  把每会话进程改名为 sshd-session，一次基础镜像升级就会让这个脚本变成常量。
  在已能建真实隧道的 Python e2e 里断言 online 分支。

Ruling R73: 三条 Minor 提升：写入改临时文件加 mv（cat > 原地截断，中断会留下
  半个已被 sshd -t 祝福过的配置）；registry_get 不要把 registry.py 的退出码 4
  「登记表不合法」压成 3「账号不在册」（Task 8 手册要写这些码）；lib.sh 去掉
  可执行位并改 0644（无 shebang 且注明不可直接执行）。

Task 8 输入（审查在范围外发现，记下以免遗漏）：计划的 Task 8 CI 在 pytest 之后才
  跑 bats，而 conftest 在 session 结束时拆掉容器（除非 RMC_KEEP_ENV=1），
  那一步会打在已停止的容器上——这十二条 bats 测试将永远不会自动运行。
Task 7: fix round 1/5 dispatched（resume 原实现者）
Task 7: fix round 1/5 完成 —— commit 2f4e724，7 files / +330 / -35；
  实现者自报 bats 19/19（容器内重建）、pytest 57/57（-W error）。
  已生成 review-d049441..2f4e724.diff（38025 bytes），scoped re-review 已派发，
  额外要求裁决实现者自曝的两条取舍：tunnel- 前缀在 lib.sh 与 registry.py 双份、
  以及 warn_locked_registry_accounts 字面匹配 passwd -S 的 " L "（是可接受的
  尽力而为，还是同一类静默降级）。

—— Task 8 预裁决（等 re-review 落地后随派发一起生效）——

Ruling R74: 计划里 CI 的步骤次序有 bug，按下面改。bats 步骤排在 pytest 之后，
  而 conftest 的 harness 固件在 session 结束时 `compose down -v`（除非
  RMC_KEEP_ENV=1），于是 `docker compose exec -T gateway bats` 会打在已经不存在
  的容器上——那 19 条 bats 测试永远不会自动跑。同一个 bug 还悄悄废掉了
  `if: failure()` 的日志导出步骤：容器早被拆了，`docker compose logs` 什么也导不出。
  改法：在 job 级别设 `env: RMC_KEEP_ENV: "1"`，容器跨 pytest 存活，bats 步骤与
  失败日志导出都有东西可打；末尾加一条 `if: always()` 的 `docker compose down -v`。
  另一个方向（把 bats 提到 pytest 之前并自己 up）会多一次 up、且修不好日志步骤，
  不采用。错了的代价：CI 上多留一组容器到 job 结束，runner 用完即毁。

Ruling R75: 计划 Task 8 Step 4 的 `git push -u origin HEAD` + `gh run watch` 不执行。
  推共享分支是本技能明令要停下来问的四类副作用之一，且分支上还带着设计文档与
  UI 画板，推与否是分支收尾时由人决定的事。实现者改为本地静态校验工作流
  （宿主没有 actionlint/yamllint，用 python -c 解析 YAML 并逐条核对步骤次序），
  并在报告里写明 CI 从未在 GitHub 上真跑过。

Ruling R76: timeout-minutes 直接写 30，不写 20。计划自己就留了"若 zombie 测试
  超时就调到 30"的后路，而 Task 6 实测回收约 80 秒、zombie 用例预算 110 秒，
  再叠上 docker build，20 分钟没有余量。

Ruling R77: gateway/README.md 必须写实现后的真实行为，不是计划草稿里的行为：
  (a) `tunnel-status.sh` 不加 sudo（R69：只读脚本刻意不要求 root）；
  (b) 吊销流程要写 enroll 的锁定口令告警（R70 落地的那条），而不是只说
      "删掉记录再跑一次 enroll"；
  (c) 退出码要成表：1 非 root、2 用法、3 账号不存在/不在登记表、4 登记表读取
      失败、5 生成的配置未过 sshd -t、6 用户名不是 tunnel- 前缀（R73 要求把
      3 与 4 分开，就是为了在这里能写清楚）；
  (d) 要写清 `# BEGIN/END RMC MANAGED` 受管区段由脚本依 registry.toml 整体
      重新生成、不可手工编辑。

Ruling R78: 方案 §4.2 的配置块与入库的 gateway/sshd_tunnel_config 有三处不一致，
  一并回填：缺 HostKey/PidFile/Subsystem（计划已列）、缺 PermitRootLogin no、
  缺 `# BEGIN/END RMC MANAGED` 标记与"该区段由 enroll-account.sh 生成"这一性质。

Ruling R79: R74 的次序修复要有测试守着，否则它和被它修掉的 bug 一样不可见。
  新增 gateway/tests/test_ci_workflow.py（纯解析、不依赖 docker，与
  test_listen_table.py 同一类），断言：bats 步骤在 pytest 步骤之后且容器仍在
  （job 级 RMC_KEEP_ENV=1 或该步骤自带）、失败日志导出步骤存在且带 if: failure()、
  timeout-minutes >= 30、末尾有 if: always() 的清理步骤。为此在
  gateway/tests/requirements.txt 加 pyyaml（宿主 venv 与 CI 都没有 YAML 解析器，
  标准库也不带）。多一个测试依赖换掉一个"CI 静默不跑测试"的整类故障，值。

Task 7: complete —— 提交范围 d049441..2f4e724（fix round 1/5 后 scoped re-review 通过）。
  七条发现全部 ADDRESSED，无新增 Critical/Important。
  re-review 确认的关键点：
  - 前缀守卫确实排在一切破坏性动作之前（require_root → 参数数 → require_tunnel_username
    → getent → passwd -l → rewrite → pkill），退出码 6，测试删掉守卫即变红。
  - Finding 2 真正被修好的原因不是「if 改成 case」：`f || rc=$?` 同样会挂起函数体内的
    errexit。起作用的是函数内每一步可失败操作都显式检查并 die()，而 die 里的 exit
    不受那条挂起规则约束，无论调用上下文都会立刻终止整个脚本。
  - 注释不一致选择改生成器（删掉块内那行冗余注释），而不是改入库配置——同一句话
    已在受管区段外的说明里。现实文件的受管区段与生成器输出逐字节一致，生产环境
    第一次 enroll 是真正的 no-op。

  新增延后小项（并入最终整支审查的分类）：
  m18 lib.sh:140 只 chmod --reference 没有 chown --reference。当前 root:root 部署下
      是空操作；若将来 sshd-tunnel 换成专用服务账号，重写会静默把属主改回 root。
  m19 require_tunnel_username 的 bats 用例只证明守卫以正确的码触发，不独立证明它
      排在 passwd -l 之前——次序结论来自代码阅读。且一旦守卫被删，这条用例自己
      会变成破坏性的（pkill -u root 打在测试容器里），是「失败时不能干净报错」那一类。
  m20 warn_locked_registry_accounts 字面匹配 passwd -S 的 " L "，格式若变则静默失灵。
      裁定为可接受：真正的防护是口令本身被锁，警告只是提醒操作员；但它与本计划
      反复发现的静默降级同类，记在此处等整支审查一并权衡。
  m21 registry.py 的 USERNAME_PREFIX 没有反向指回 lib.sh 的 TUNNEL_PREFIX（单向引用）。
  m22 rewrite_match_block 无 trap，硬杀时会留下临时文件（永远污染不到真配置）。

Task 8 追加输入（来自本次 re-review 的范围外观察，直接影响 R77(c) 的退出码表）：
  退出码 3 在两个脚本里含义不同——enroll 经 registry_get 抛 3 是「不在登记表」，
  revoke 自己抛 3 是「系统里没有这个用户」。手册的退出码表必须按脚本分栏，
  不能写成一张全局对照表。
Task 8: dispatched（BASE = 2f4e724）。派发带上 R74-R79 全部裁决与 re-review 的
  退出码 3 双义观察；明令不 push、不跑 gh。
Task 8: 实现者报 DONE —— commit ac8640a，5 files / +343 / -1。
  自报 test_ci_workflow.py 6 passed + test_registry.py 9 passed（纯解析，不起 docker），
  collect-only 63 条（57+6）。按 R75 未 push、未跑 gh。
  实现者纠正了我 R77(c) 的一处不准：enroll-account.sh 根本不会退 6——
  只有 revoke 调 require_tunnel_username，enroll 的非隧道用户名走 registry_get 退 3。
  已生成 review-2f4e724..ac8640a.diff（24754 bytes），task reviewer 已派发。
Task 8: task review 结果——不通过。1 Critical + 1 Minor + 2 范围外观察。
  Critical 正中本计划反复出现的那一类，而且就长在专门用来防它的那个测试里：
  _find_step_index(steps, "pytest tests") 命中的是「单元测试」而不是「集成测试」，
  因为前者的 run 文本 `pytest tests/test_registry.py` 也含子串 "pytest tests" 且排在前面。
  审查者实测两种改法都不会让测试变红：把「集成测试」挪到 bats 之后（正是 R74 那个
  回归的另一条路径）、以及给「集成测试」加步骤级 env RMC_KEEP_ENV=0（正好废掉 R74
  要求的修复）。六条断言里最核心的两条是瞎的，而测试自己的 docstring 与实现者报告
  都声称它们是回归网。

Ruling R80: Critical 必修，且修法有硬要求——不许只把关键词换得更长。
  步骤要按 name 精确匹配（"集成测试"/"单元测试"/"脚本测试"），匹配不到就报错而不是
  返回 -1 或 0；并且每条断言必须用变异验证过：把「集成测试」挪到 bats 之后要红，
  给它加步骤级 RMC_KEEP_ENV=0 要红，报告里逐条写明看到红的是哪一条、报什么。
  这条测试的存在意义就是这个，不能再交一次「名字声称的事没被验证」。

Ruling R81: Minor 必修——方案 §4.2 的那条要点只写了 enroll-account.sh 生成受管区段，
  漏了 revoke-account.sh（两者调的是同一个 rewrite_match_block）。同一次提交里的
  README 写对了两个，文档内部自相矛盾。

Ruling R82: 把审查的第一条范围外观察一并修掉，不开后续 ticket。
  revoke-account.sh 结尾那行 printf 仍在说「从 registry.toml 删除记录、再跑一次 enroll
  对齐配置」，而 README 已按 R77(b) 改成了正确的说法。脚本在屏幕上说的和手册上写的
  不一致，凌晨排障时看两处的正是同一个人。改一行 printf 的成本远低于一张没人会做的
  ticket。它落在 Task 7 的代码里但属于同一件事，就在这一轮改。

Ruling R83: 第二条范围外观察一并修——README「部署」小节的 install/systemctl 命令
  没有 sudo，而同一篇文档其余部分已经对权限逐条明确。既然这篇手册现在立了这个标准，
  它自己不该破例。

Task 8: fix round 1/5 dispatched（resume 原实现者）
Task 8: fix round 1/5 完成 —— commit bff52b8，5 files / +62 / -36。
  实现者自报六条断言全部经变异验证变红；但 R82 改到的那条 bats 断言只用
  bash -n 与人工比对过，没真跑。
  我自己跑了 bats（容器内，19/19 全过，含第 14 条「revoke 的收尾提示报出的是
  被吊销的用户名」），实现者留下的那个不确定就此关掉——不是静态结论。
  同时已生成 review-ac8640a..bff52b8.diff（20227 bytes），scoped re-review 已派发；
  并行开跑整套 pytest（-W error，含两条 110 秒预算的僵尸端口用例），
  这是整支分支唯一一次端到端验证，结果记在下面。
  整套 pytest 结果：63 passed in 182.83s，-W error 下零警告。容器已拆。
  附带一个对 R76 的实测确认：整套跑完 3 分 2 秒，加上 docker build 也远在
  timeout-minutes: 30 之内——那 30 分钟不是拍脑袋，是有余量的。

Task 8: complete —— 提交范围 2f4e724..bff52b8（ac8640a 实现 + bff52b8 修复轮）。
  四条发现全部 ADDRESSED，无新增破坏。re-review 没有采信实现者的变异日志，
  自己在仓库外的副本上把六条变异全跑了一遍，逐条对上了断言打印的具体数值；
  _index_by_name 的三个边界（无 name 的步骤、重名、改名）也都读过：要么正确忽略，
  要么响亮失败，不会静默解析到错的步骤。
  我另跑的 bats 19/19 与整套 pytest 63 passed 已把 re-review 只能静态下结论的
  那一条（revoke 收尾文案与 bats 断言是否逐字对得上）实测确认。

===== Gateway 计划 8/8 完成 =====
接下来：整支分支审查（最强模型），并在那里一并分类 m1-m22 延后小项。
整支分支审查已派发（Opus，最强模型）：base 263623f，head bff52b8，30 commits /
  37 files / +4127 / -413，diff 包 333671 bytes。派发带上设计文档、计划、本账本
  （R1-R83）与 deferred-minors.md，并明确交代四条客户已拍板、不得重新争论的决定
  （0.0.0.0 公网可达、ClientAlive 两值与约 80 秒回收、V1 不做的四项加固、
  tunnel-status.sh 不要求 root），只查「代码/测试/手册/文档是否对同一件事说法一致」。
  重点要它去找第九个假绿，并分类 m1-m26。

===== 整支分支审查结果 =====
结论：可以交回，无 Critical。3 Important + 若干 Minor + 分类里 1 条 FIX NOW。
审查者实跑了 bats 19/19、一条 harness 用例、collect-only 63、容器内 sshd -T
（tunnel-zhang 与未登记的 tunnel-ghost）、ss -ltn、坏登记表下的 tunnel-status.sh、
以及 README 的本地测试配方逐字执行。

第九个假绿：没找到，且给出了我认可的结构性理由——前八个关掉的是「测试撒谎」
整一族，残余风险迁移到了「没人测的指令」。最接近第九个的就是 Important 2：
_LAYERED_DIRECTIVES 那张表存在的唯一理由就是钉住行为测试钉不住的配置行，
而它偏偏停在 ClientAliveInterval 前面——那是本分支上唯一一个客户亲自拍板的值。

Ruling R84: 按技能规定，最终审查只给一次修复派发。纳入本轮的（全部为小改动）：
  I1 tunnel-status.sh 坏登记表退 0（README:113 还写反了）——照 lib.sh:105-108 的
     三行改法，并补 bats 用例；循环内 `get | cut -f3` 的管道同样吞码，一并修。
  I2 _LAYERED_DIRECTIVES 补六行：clientaliveinterval/clientalivecountmax/
     listenaddress/allowusers/permitrootlogin/permitlisten。每一行必须用删除验证
     变红，逐条在报告里写明。这是本轮最重要的一项。
  I3 方案 §4.2:325 删掉「与每 IP 连接限速」（haproxy.cfg 里没有，§7.3:425 明列推后）；
     顺带把该处 haproxy 片段补上 R41 已落地的 TLS 加固行。
  F1（分类里的 FIX NOW）test_scripts.bats 的 setup() 加
     `[ -f /.dockerenv ] || skip`。守卫若被删，这条用例自己会在开发机上
     passwd -l root + pkill -u root。代价无上界，故优先级高于其余全部小项。
  m 系列一并修：README:34 install -D；README:135-147 本地配方加 RMC_KEEP_ENV=1；
  README:88,100 退出码 1 的补充说明；enroll 在 reload 失败后重跑会报「无变化」
  且不 reload（rc=2 分支改为无条件 reload）；lib.sh:121-123 与 bats:94 里
  pre-R45 的已被实测证伪的说法；test_ci_workflow.py 三条断言不看 run 内容、
  且缺 cleanup_idx > bats_idx；CI 没跑 -W error（加 pytest.ini）；
  haproxy 以 root 运行（补 user/group，chroot 若破容器则去掉）；
  registry.py 补回指 lib.sh 的注释；registry.py 缺文件路径无测试；
  entrypoint 的 useradd 在 set -e 下非幂等；方案 §384/§4.4 吊销小结漏了删登记表记录。

Ruling R85: 不纳入本轮，留给后续计划：四份重复的隧道启动 helper 合并成
  conftest 里一个 start_reverse_tunnel（审查者自己也说「和下一个计划一起做」，
  收尾时动四个测试文件的共享代码风险大于收益）；以及把 TLS 腿与工程师腿
  合成一条生产形态的端到端用例（两条腿已实测独立，差 5ms，风险低）。
  两项均记入下一份计划的输入。

最终修复轮完成 —— 三个提交 d2b63b4 / 59341c7 / 669cc55，13 files / +330 / -33。
  自报 pytest 72/72（-W error，169.81s，从 63 增到 72）、容器内 bats 21/21（从 19 增到 21）。
  实现者主动披露一条例外，值得记下来：ClientAliveCountMax 钉不住「被删除」，
  因为 OpenSSH 的出厂默认就是 3，删掉那一行 sshd -T 照样打印 clientalivecountmax 3；
  这条 param 只能抓住「被改成错的值」。它把这条归到与既有 X11Forwarding 同一类例外。
  另外它把可选的第七条（sshd -T -C user=<未登记账号> 钉住 permitlisten none）也加了，
  并保留了 chroot /var/lib/haproxy（用 haproxy -c、ps 与三条 TLS 端到端用例验证过）。
  未做：没加断言 haproxy worker uid 的自动化测试，只用 ps 人工确认。

  最后一次 scoped re-review 已派发（Opus）。重点交代它：ClientAliveCountMax 那条例外
  是本次审查的关键——技术说法对不对，以及「摆在那里像保护、实则不保护」是否
  又踩进本分支已经抓到九次的那一类；并要求它不采信实现者的删除验证表，
  自己至少重推 clientaliveinterval 与 listenaddress 两条最高后果项。

最后一次 scoped re-review：**分支可以交回**。七项发现全部 ADDRESSED。
  审查者没有采信实现者的删除验证表，自己在容器 /tmp 里把七条钉点全部重推了一遍
  （逐条给出删除后 sshd -T 的实际输出），每一行都对得上，包括那条例外的方向。
  它也独立验证了 ClientAliveCountMax 的技术说法，并判定这条披露是诚实的：
  该指令的出厂默认就是 3，所以删除后行为不变，断言钉的是「生效值」，
  凡是会改变行为的改动都会被抓到；而客户亲自拍板的那个值是 ClientAliveInterval，
  出厂默认 0，钉得死死的。整支分支被命名的「第九个假绿」风险就此关闭。
  另确认 pytest.ini 的 filterwarnings=error 真的生效（rootdir 对 CI 的两条调用
  都解析到 gateway/，全仓没有竞争的 ini/pyproject，也没有 @filterwarnings 豁免）。

Ruling R86: 五条 New Breakage 与两条范围外观察由我自己收尾（全是一行改动，
  再派一轮子代理的成本高于收益），并按下面处置：
  - enroll-account.sh:4 文件头仍写「配置无变化时不 reload」，而同一个提交把
    rc=2 分支改成了无条件 reload——正是本分支一直在关的那一类陈旧声称。已改。
  - **revoke-account.sh:33-35 有与 enroll 完全相同的 rc=2 缺陷**（审查者列为范围外）。
    刚在 enroll 修好同一个 bug 还把孪生兄弟留着，说不过去。已同样改为无条件 reload。
  - test_scripts.bats 的 teardown() 没有容器护栏。bats-core 在 setup() skip 之后
    照样跑 teardown，于是在宿主上以 root 跑本文件时 21 条全 skip、userdel 却执行
    21 次；而最可能同时装着 checkout 和真实 tunnel-* 账号的机器正是 Gateway 本身。
    F1 的规格本身不完整，已补同一行护栏。
  - README 的「haproxy 起不来」只给了 `haproxy -c`，而本轮引入的 chroot 失败模式
    下 `haproxy -c` 返回 0 并报「Configuration file is valid」（审查者实测）。
    已补一行，指向 systemctl status / journalctl。
  - 三处计数漂移（test_ci_workflow.py 的 19 vs 21、test_tunnel_restrictions.py 的 63、
    conftest.py 的「12 条（后来 19 条）」）一律改成不带数字的表述，从根上不再漂。
  - 范围外观察 3：haproxy 降权三行是分支上唯一一组安全相关却零钉点的指令，
    三条 TLS 端到端用例在三行全删之后照样绿。已按审查者建议加纯文本钉点
    （test_tls_frontend.py，不依赖 harness），并逐行做了删除验证：
    删 user/group/chroot 各让且仅让一条 param 变红，haproxy.cfg 事后 sha256 一致。
残留收尾已提交：18f22b1，8 files / +44 / -5。
  验证：pytest 75 passed（183.29s，pytest.ini 的 -W error 生效，零警告）；
  容器内 bats 21/21（含新增的「登记表损坏时 status 响亮失败」）；容器已拆。

===== Gateway 分支完成，待人决定收尾方式 =====
分支 feat/gateway 共 34 个提交，从未 push。分支上不只有 gateway 代码，
还带着设计文档与 UI 画板源文件。推送 / 合并 / 开 PR 属于要由人拍板的动作，
不自行执行。
