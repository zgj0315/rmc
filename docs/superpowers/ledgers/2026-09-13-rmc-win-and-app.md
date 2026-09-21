# SDD ledger — plan: docs/superpowers/plans/2026-09-13-rmc-win-and-app.md

分支：feat/rmc-win，从 main 的 1bda177 开出。
  **不建 worktree**，直接在主工程目录工作。理由：上一轮 worktree 拆掉之后，
  会话的隔离围栏没有跟着解除，卡了一会儿（最后靠 ExitWorktree 解开）。
  现在没有并行工作，worktree 的隔离价值抵不上那个风险。

前置状态：Gateway 8/8 与 rmc-core 12/12 已全部完成、评审通过、合入 main
  （88 个提交）。rmc-core 现有 239 passed / 17 ignored，CI 已建但从未在
  GitHub 上真跑过。两份执行账本（R1-R99）留在 docs/superpowers/ledgers/。

计划规模：两个文件共 4054 行、12 个任务。
  Task 1-5 是 rmc-win（Windows 集成）：骨架与单实例（命名互斥量）、
  代理字符串解析、系统代理解析器（WinHTTP/PAC）、SSPI 代理认证、
  DPAPI 记住密码、电源与网络事件。
  Task 6-12 是 rmc-app（iced 界面）：骨架与主题、视图模型、维护页、
  诊断页与诊断包导出、日志页与接线、托盘与通知、打包签名与 CI。

已知的头号障碍（预检正在核实）：**本机是 macOS aarch64，只装了这一个 target，
  而 Task 1-5 全是 Windows API**。要查清三件事：windows crate 在非 Windows
  target 上是编译出空壳还是直接编不过；cargo check --target
  x86_64-pc-windows-msvc 在这台机器上装不装得起来（check 不链接，要求可能
  低于 build）；以及如果两条路都不通，那 Task 1-5 只能靠 CI 的 Windows runner
  验——而计划里建 Windows CI 是 **Task 12**，最后一个。那意味着 Task 1-11
  整个执行期这些代码都处于「写了但从没编译过」的状态。

从 rmc-core 账本带过来的硬约束（README 点名的六条里最要紧的两条）：
  - SSPI 的 trait 形状：ProxyAuthenticator::next_token 收 &self 不是 &mut self，
    足以跨多段协商承载 SSPI 上下文，但实现必须把 CredHandle/CtxtHandle 包进
    std::sync::Mutex（trait 要求 Sync，不能用 RefCell），而且**每次连接尝试
    都要新建一个实例**（Negotiate/NTLM 是连接绑定的）。「新一轮协商开始」的
    唯一信号是首次调用时 challenge == None。
  - start_paused 旁边不要放真实 I/O：虚拟时钟自动前进量取自时间轮层级槽边界
    （64^level 毫秒），一次真实 I/O 的 await 会让虚拟钟一步跳掉 262 秒。
    Task 5 要测电源/网络事件，大概率会撞上。

整支审查留下的、本计划要接的账：
  **rmc-core 没有生产装配点**。把一份 Config 变成 Transport + KnownHosts +
  SshTunnelFactory + TransportPreflight + Deps 这件事，rmc-core 既没做也没测过
  （Deps 的唯一构造点在 #[cfg(test)] 里）。计划的 Task 10（日志页与接线）
  如果没覆盖它，那就是整条链路第一次被真正接起来的地方。

用户侧已知状态：git push 首次失败——PAT 缺 workflow scope（两个工作流文件
  都是新增的）。已给出两条路（加 scope 或换 SSH），建议换 SSH，因为 Task 12
  与 rmc-win 的 Task 12 还会多次改 workflow 文件。

===== 预检扫描结果：24 条 + 一组琐碎。按原文执行走不通，逐条裁决后继续 =====

执行可行性（最重要的一条，用户提示 zigbuild 之后重做的）：
  **能 build，不能 run。** 预检复现了我的四条实测并推进一步：
  - cargo check --target ...-msvc 对纯 windows crate（无 C 依赖）**可行**
    ——Task 1-5 的 Win32 代码这样就能查，连 zig 都不需要；
  - cargo zigbuild --target ...-gnu 对整个技术栈可行：rmc-core 15 秒、
    rmc-win 五个 Win32 模块能产出 .exe 与测试 .exe、
    iced 0.13 + winit + tray-icon + zip 能链接出 171MB 测试 .exe；
  - **唯一失败**：带 wgpu 时 `unable to find dynamic system library 'd3dcompiler'`
    （zig 的 mingw 不带 MSVC-only 导入库）。方向是「gnu 红、msvc 绿」，
    是假警报不是漏网。
  - 关键佐证：probe-win 里的 13 个编译错误，**msvc check 与 gnu zigbuild 报的是
    同一批**，修完两边同时变绿。因为 windows 0.58+ 对两个 ABI 生成同一份代码，
    靠 windows_targets::link! 展开成 raw-dylib，不分 ABI。
  - Task 1-5 的 42 条测试**全部平台无关**，macOS 原生能真跑（Task1 14、Task2 7、
    Task3 6、Task4 10、Task5 5）；反过来 SingleInstance / WinHttpSource /
    NegotiateContext / DpapiSealer / spawn_win32_listeners 约 360 行
    **自动化覆盖率为零**，只能靠人工验收清单。

Ruling W1（采纳预检的建议，不提前建 CI）：每个任务的 Step 4 加一行
  `cargo zigbuild -p rmc-win --tests --target x86_64-pc-windows-gnu`。
  这一行把「写了但从没编译过」从 11 个任务压到 0 个。
  rmc-app（Task 6 起）因 wgpu 会在**最后的链接步**失败，但所有 rustc 编译错误
  在链接前已报完——当 type-check 用即可。
  Windows CI 留在 Task 12，职责收窄成两件本地做不到的事：msvc 链接 +
  asInvoker 清单断言。理由：运行期行为（互斥量真挡住第二实例、DPAPI 真解得开、
  电源事件真到达）**CI 的 windows runner 也验不了**——没有第二个桌面会话、
  没有域、没有代理、合不了盖。那是人工验收清单的活。

Ruling W2（★最严重★，Task 3 必改，且计划把错误行为写进了断言）：
  SSPI 上下文只建一次。计划 part1:864 是
  `if guard.is_none() { *guard = Some((self.factory)(scheme)); }`，
  而账本 README 白纸黑字：**每次连接尝试都要新建实例**（Negotiate/NTLM 是
  连接绑定的），「新一轮协商开始」的唯一信号是首次调用时 challenge == None。
  而 rmc-core 的装配把 authenticator 钉成单例：Transport::new 只调一次，
  Arc<dyn ProxyAuthenticator> 被 Transport 持有到进程结束。
  **后果：企业代理现场，第一次连接协商完（无论成败）*slot = None，
  此后每次重连都在 slot.as_mut()? 返回 None，直接 ProxyAuthFailed。
  客户端在第一次断线后永久废掉**——而那恰恰是 Supervisor 存在的场景。
  更糟的是计划自己的测试 context_is_reused_across_rounds_of_one_connection
  （part1:762）把这个错误行为写进了断言（第三轮必须返回 None），
  而「challenge == None 应当开新上下文」一条都没有，所以测试会全绿。
  改：next_token 里 challenge.is_none() 时无条件重建；删掉那条反向断言，
  换成「同一连接内多轮复用 + 新连接开新上下文」两条。

Ruling W3（Task 3，接口形状要改）：SPN 用的是认证 scheme 不是代理主机名。
  part2:2427 `NegotiateContext::new(&format!("HTTP/{scheme}"))`，
  而 scheme 是 "Negotiate"/"NTLM"，于是 SPN 成了 HTTP/Negotiate。
  根本问题：ProxyAuthenticator::next_token(&self, scheme, challenge)
  **根本不传代理主机**，工厂闭包 Fn(&str) 收的也是 scheme——这条设计路径上
  拿不到正确 SPN 所需的信息。要在 SspiProxyAuthenticator::new 时注入
  （收一个 ProxyResolver，或直接把 SPN 构造时传进来）。

Ruling W4（Task 10，2 处编译错误，账本都点名过）：wiring.rs 与实际交付对不上。
  - SshTunnelFactory::new 交付的是**两参**（ssh/mod.rs:39），计划给三参；
  - Deps 交付的有**五个**字段（supervisor.rs:343），计划只给四个，
    缺 preflight: Arc<dyn Preflight>。
  preflight.rs 模块文档第 52 行起逐条写了「Task 10 该怎么接」，计划一条没照做。
  另两个编译器抓不到的接线风险：Supervisor::spawn 内部是 tokio::spawn，
  若在 iced run() 之前调会 panic on "no reactor running"，计划没说在哪调；
  Task 12 给 workspace 加 [profile.release] panic = "abort" 会让
  cargo test --release 不可用。

Ruling W5（Task 1/2，6 处编译错误）：HostPort 字段私有（R33），
  计划 part1:571/578/580/586 与测试 part1:65 直接访问 .host/.port。
  改用 .host() / .port()。

Ruling W6（Task 1，13 个编译错误 + 版本统一）：windows crate 从 0.58 改用 **0.62**。
  预检实测：0.62 下 13 个错误只剩 1 个（WinHttpOpen 的 is_null）。
  而且 russh 0.63 经 pageant 已经传递性拉入 windows 0.62.2——用 0.62 顺带消掉
  workspace 里两个大版本并存。
  剩下要改的（0.62 下仍需）：
  - **5 处语法错误**：`unsafe { let _ = CloseHandle(h) };` 块内 let 漏分号；
  - Cargo.toml feature 表缺 Win32_Security_Credentials（SecHandle 在这儿，
    缺它会让 AcquireCredentialsHandleW 等四个符号一起「不存在」）、
    Win32_System_SystemServices、Win32_UI_WindowsAndMessaging；
  - DEVICE_NOTIFY_CALLBACK 与 PBT_APMRESUMEAUTOMATIC 都在
    Win32::UI::WindowsAndMessaging，不在 System::Power / System::SystemServices；
  - PowerRegisterSuspendResumeNotification 第二参是 P0: Param<HANDLE>，
    第三参是 *mut *mut c_void；
  - WinHttpOpen 返回裸 *mut c_void，没有 is_invalid()，用 is_null()；
  - InitializeSecurityContextW 两个参数类型：psztargetname 要 Option<*const u16>，
    pinput 要 Option<*const SecBufferDesc>。

Ruling W7（Task 6/8，iced 三处类型推断错误）：根因一致——把控件绑到 let 上
  而不立即 .into() 成 Element，Theme 泛型无从推断。part2:1649 的 row!、
  part2:1659 的 text_input、以及 column! 里那 4 个多余的 .into()。
  好消息：除这三处外 iced 0.13.1 的全部控件用法都对得上。

Ruling W8（Task 11/12，无实现路径）：**tray-icon 0.19 根本没有通知 API。**
  预检把它的 pub fn 全列了一遍：没有任何 notification/balloon，
  Windows 实现只用了 NIF_ICON|NIF_MESSAGE|NIF_TIP，NIF_INFO 一次没出现。
  Task 11 的四条通知需求、Task 12 验收清单的三条通知项全部落空。
  要么加依赖（winrt-notification / notify-rust），要么自己走
  Shell_NotifyIconW + NIF_INFO。
  次级风险：TrayIconBuilder::build() 在 Windows 上要消息泵，托盘事件走
  tray-icon 自己的全局 channel；而 iced 0.13 不暴露 winit 的 event loop
  也不暴露自定义 window proc。Task 11 只写了「main.rs 里持有 Option<Tray>」，
  没说两套事件循环怎么合流。

Ruling W9（界面与规格/画板的矛盾，Task 7/8/9 返工）：
  **前提**：design/README.md 写明 .dc.html 是生成物，源文件是 body-*.html；
  而仓库里的 .dc.html 是**过期的**（还写着 Gateway 反向端口 127.0.0.1:22001），
  **计划的 Global Constraints 抄的正是过期那一版**。
  - W9a 界面通篇叫 Gateway，而 §3.10 开宗明义「界面上这台机器叫**运维服务器**，
    而配置文件、目录与运维手册里一律仍以 Gateway 为标识」。
    额外一层：rmc-core 交付的预检步骤名常量就是 "Gateway 域名解析"/"Gateway TLS"
    （preflight.rs:83-84），Task 9 直接透传 → 诊断页会原样显示 Gateway。
    要么 rmc-app 加映射表，要么改 rmc-core 常量。
  - W9b **「远程接入」整条线全缺**：未开启页那一行（含「由运维分配」说明）、
    已连接页的「链路」组三行、以及**复制按钮**。§3.10 专门用一整段解释了
    为什么它不单独成组（520×720 下只剩 32.8px，多一个组标题超出 5.6px）
    ——这是已经权衡过的拍板。复制写入剪贴板的是**两行**：ssh 命令 + host key
    指纹，§3.10 也用一整段解释了为什么指纹必须跟命令一起复制。
    计划：Form 没有 reverse_port 字段，没有链路组，全计划没有任何剪贴板代码。
    连带：Model/Form 要多带 reverse_port 与 TLS 版本，而 **TunnelEvent 现在
    不传 TLS 版本**（state.rs:69 五个变体里没有），链路第二行拿不到数据。
  - W9c 已连接副标题硬编码 "Gateway 反向端口 127.0.0.1:22001"（part2:1225）：
    端口写死（真实值在 cfg.reverse_port）、主机写成 127.0.0.1（已拍板绑 0.0.0.0，
    画板写的是 gateway.company.com:22001）、措辞用 Gateway。
    **告诉现场人员去连 127.0.0.1，正好是 §3.10 废弃掉的「先登录运维服务器
    再跳转」那套模型。** 而 Model::status_card() 拿不到 Config，
    这个字段要从 Task 7 的接口形状上补。
  - W9d 一体机默认端口：画板与 Config::default() 都是 61001，而 Form 用
    #[derive(Default)] 全空串，Task 8 的夹具 good() 用的还是 "22"
    ——R13 警告过「22 恰恰是掩盖这整类错误的值」。
  - W9e 诊断页少 3 行（代理 CONNECT、代理认证 SSPI、运维服务器 host key 校验
    与口令认证）、少「重新检查」按钮与页头耗时；advice_for 五个分支漏了
    「需要代理」与「口令被拒」。而 Task 3 的人工验收还要求「确认诊断页的
    『代理认证（SSPI Negotiate）』一行为通过」——**那一行没有任何任务会画**。
  - W9f 会话行少了起始时间与时长（opened_at 是现成的，state.rs:63）。

Ruling W10（Task 10，日志链路从头到尾接不上）：
  - W10a parse_line 解析的是**不存在的格式**：它 split_once('T') 后按
    `11:12:44 INFO 消息` 解，而 audit.rs:220 实际产出的是
    `2026-09-13T11:12:44+08:00 INFO 消息`（R87 专门加的显式偏移量，
    rmc-core 有 timestamp_carries_an_explicit_utc_offset 钉着）。
    于是日志页时间列会显示 `11:12:44+08:00`。
    **又一个「测试通过 ≠ 验证了名字声称的事」**：parses_time_level_and_message
    断言的是计划自己编的 SAMPLE 常量，不是 Audit 的真实输出，所以永远绿。
  - W10b 没人计算日志文件路径：file_name_for() 是 audit.rs 的**私有**函数，
    Audit::current_path() 只在 Supervisor 内部持有的实例上。要么 rmc-app 重写
    一遍日期→文件名（逐字重复且会漂移），要么 rmc-core 补一个公开出口。
  - W10c **rmc-app 自己的 tracing 输出全部丢失**：Task 6 装的是
    tracing_subscriber::fmt()（写 stdout），而同一文件第一行是
    `#![cfg_attr(windows, windows_subsystem = "windows")]`——没有控制台。
    而 rmc-win 的所有诊断走的正是 tracing 不走 Audit。
    Task 5 的人工验收要求「日志里有一条休眠恢复记录」，
    **按现在的接线它永远不会出现**。

Ruling W11（Task 12，CI 与打包）：
  - app.yml 两处用 @1.82 而 MSRV 是 1.89。两种结局都不好：目录级 override
    生效则那两行是骗人的死配置；不生效则 cargo 直接拒绝。
    core.yml 用的是 @1.89，且 tests/ci_workflow.rs 有一条专门钉它——
    新工作流不在那条测试覆盖范围内，会悄悄劈叉。paths 过滤器也漏了
    rust-toolchain.toml（core.yml 注释里明确修过的同一个坑）。
  - asInvoker 断言在 pwsh 下直接报错：`-Encoding Byte` 在 PowerShell 7 里
    已被移除；就算用 5.1，对十几 MB 的 exe 逐字节 ForEach-Object 会跑到天荒地老。
    用 Select-String -Pattern 或 mt.exe -inputresource。
  - winres 0.1 最后发布 2021 年，维护中的分叉是 winresource 0.1.31。

Ruling W12（评审规则会判为缺陷的）：
  - bundle_creates_a_zip_containing_the_report **从不打开那个 zip**，
    只断言存在、扩展名、len>0。删掉写 preflight.txt 的整段它照样绿。
    正是账本 18 个反例里「只查存在不查内容」那一类。
  - **手搓临时目录被复活了三次**（part2:65/1968/2267 逐字重复同一 helper），
    而 HEAD 往前第五个提交就是「tests/common 的 tmp_known_hosts 换成 tempfile」
    ——这个项目**已经裁决过**手搓 temp dir 是缺陷。三份副本全都不清理。
  - **纯逻辑被关进 #[cfg(windows)]**，违背计划自己的架构声明
    （「解析那一半是纯函数、跨平台可测」）：Debouncer 是纯时间逻辑、是
    「合并窗口真的管用吗」的全部实现，却在 macOS 上编译都不编译，
    而 Task 5 测的 debounce_ms() 只是个返回 800 的常量函数；dot_icon 同理。
  - 几条弱测试：bypassed_target_resolves_to_direct 名字说验证两个函数配合、
    实际只调了一个且与相邻用例逐字同构；auth_failure_lands_on_idle_with_a_retype_hint
    只断言 credentials_visible，而 Model::apply 对**任何** State::Idle 都置 true，
    分不出「认证失败」与「正常停止」；emitting_with_no_subscriber_does_not_panic
    **没有断言**。
  - Task 1 Step 3 自相矛盾：代码块给 #![forbid(unsafe_code)]，紧接着的散文说
    改为 #![deny(unsafe_op_in_unsafe_fn)]。**这个矛盾在 macOS 上完全隐形**
    （forbid 不可被子模块 allow 覆盖，而 single_instance::imp 被 cfg 切掉了），
    到 Windows 上五个 #![allow(unsafe_code)] 模块一起硬报错——
    恰好是 W1 那条 zigbuild 闸门最该接住的形状。

琐碎（随各任务派发一并交代）：parse_proxy_list 的 _target_host 从不使用而
  Interfaces 说「挑出适用于目标的第一项」；std::mem::forget(handle) 对 Copy 类型
  是 no-op，clippy -D warnings 会红（实测确认）；Task 1 的 Files 清单没列
  proxy/mod.rs 而 Step 3 要求创建；Task 8 的 Interfaces 写两参而实现三参；
  Form::validate 把 HostPort::new 的具体错误吞掉；Task 6 的 update 返回 ()
  而剪贴板与 Task 10 的命令派发都需要 Task<Message>；引入 iced 让 workspace
  多出 561 个包。

Task 1: complete —— commit 46ce814，15 passed，clippy/fmt/deny 全绿，
  zigbuild 闸门产出 92MB 测试 .exe。评审通过。
  评审把 15 条测试**全部**重做变异（不是抽样），15/15 全红、无一处与报告不符，
  还逐次 diff 确认还原、最终与 git show HEAD 逐字节相同。
  它额外核实了一条比实现者自己说的更强的结论：这次 diff 对依赖图的**边际影响
  是零**——windows 0.62.2 在 base commit 1bda177 的锁文件里就已经通过
  pageant→russh 传递性存在。

  **W1 那条闸门在第一个任务里就当场接住了它要接的东西**（评审亲自复现）：
  把 lib.rs:13 换回 #![forbid(unsafe_code)]，macOS 原生 cargo test **仍然
  15 passed**——矛盾完全隐形，因为 cfg(windows) 把 single_instance 整个切掉了；
  而同一份代码 zigbuild 硬报 5 个 E0453（1 处 allow 与 forbid 冲突 +
  4 处 usage of an unsafe block），精确指向 lib.rs:13 的 forbid 定义处。
  换回 deny(unsafe_op_in_unsafe_fn) 两条命令都干净。
  结论：这条闸门对 Task 2-5 全部保留。Task 2-5 的 Win32 代码量级远大于 Task 1
  （WinHTTP、SSPI、DPAPI、电源/网络事件），这类「仅在 windows target 上才现形」
  的错误只会更多。

Ruling W13（修正预检的一个结论，写进后面四个任务的派发）：
  **cargo check --target x86_64-pc-windows-msvc 对 rmc-win 根本不可用。**
  评审亲自复现：ring 的 build.rs 真调 C 编译器（cc-rs 生成的命令行里能看到
  --target=x86_64-pc-windows-msvc），而这台 macOS 的 clang 缺该 target 的
  assert.h。链条是 rmc-win → rmc-core → rustls/russh → ring。
  预检当初「msvc check 对纯 windows crate、无 C 依赖可行」的结论，是用一个
  **不依赖 rmc-core 的探针项目**测出来的，从未踩到 ring 这道墙。
  Task 1 是第一个真正把 rmc-win 接到 rmc-core 上的任务，这道墙从第一天就在。
  Task 2-5 只会更依赖 rmc-core（HostPort、Error 等），所以
  **zigbuild-gnu 是唯一可行的本地闸门**，后续派发里不要再指望 msvc check。

Task 1 的三条低（实现者自己披露，评审确认真实存在、不影响验收）：
  L1 SingleInstance(HANDLE) **不是 Send/Sync**（windows 0.62.2 源码未给 HANDLE
     unsafe impl Send/Sync，评审核过源码）。后续任务若要把它塞进要求 Send 的
     结构（比如跨 .await 持有的状态机、或 main.rs 里与 iced 事件循环共存的
     状态），会编译不过。**Task 6/10 接线时要注意。**
  L2 zeroize、async-trait 声明但本任务未使用，clippy -D warnings 不会报。
  L3 parse_proxy_list 与 parse_bypass_list 各写了一遍相同的分隔符字符集
     字面量。实现者给的不合并理由（两个函数下游语义不同）评审判定成立。

模块划分评审判定「撑得住，不只是写了句话」：lib.rs 的模块文档**指名点出**了
  Debouncer/dot_icon 这两个 W12 点名的未来风险点；proxy/mod.rs 已按约定起头
  （parse 纯函数在，winhttp 留白等 Task 2）；single_instance 没按两层拆，
  但理由（CreateMutexW 只有二值结果，不产生需要另外解析的原始数据）技术上成立。
  硬证据是两层结构当场跑通：15 条纯函数测试 macOS 原生过，Win32 一侧 zigbuild 过。
  唯一风险不在这个任务：约定要撑住后面四个任务，取决于 Task 2-5 的实现者
  是否真的照做（比如真把 Debouncer 拆成纯函数）。

Task 2: 评审不通过。3 高 + 5 中 + 6 低。纯逻辑那一层做得好（decide/manual_decision
  干净、12 条测试全部经得起变异、三条语义缺陷的**方向**判断经 MSDN 逐条核实都对，
  第 1 条评审还找到了实现者没找到的更强佐证：微软官方移植算法把手工配置与自动配置
  分成两条路，bypass 名单在文档里从头到尾只跟手工代理配对）。
  但 Win32 那一层是半成品，而且错在恰好要救的那条路径上。

Ruling W14（高，必修）：lpszAutoConfigUrl 违反 MSDN 明文前置条件。
  文档逐字：「If dwFlags does not include WINHTTP_AUTOPROXY_CONFIG_URL,
  then lpszAutoConfigUrl must be NULL.」
  而 winhttp.rs:94-98 在 pac_url 为空串时不开 CONFIG_URL 标志，
  winhttp.rs:102 却**无条件**写 PCWSTR(pac_wide.as_ptr())——此时 pac_wide 是
  [0u16]，是一个非 NULL 的指向空宽字符串的指针。
  **这正是缺陷 #2 修复唯一想救的那种网络（只勾自动检测、不填地址）**。
  评审在净副本上验过，条件 NULL 是五行、zigbuild 通过。

Ruling W15（高，必修）：auto_detect 在 Win32 侧仍然从未被读。
  winhttp.rs:94 无条件 `let mut flags = WINHTTP_AUTOPROXY_AUTO_DETECT;`，
  而 ProxySource::eval_pac 的签名根本没把这个 bool 传下去——缺陷 #2 从
  「声明了没读」变成了「跨层根本传不过来」。
  后果：一台「自动检测未勾、只填了 PAC 地址」的机器，每次解析仍要先跑完
  DHCP INFORM + DNS wpad 全套发现才轮到那个明写的地址。与 MSDN 官方算法
  （fAutoDetect → AUTO_DETECT，lpszAutoConfigUrl → CONFIG_URL，两者独立）相反。
  改法：eval_pac 签名加宽成 (auto_detect: bool, pac_url: Option<&str>, target_url)，
  消掉「空串当跨层信号」这个魔法值；**并把标志计算上移成 mod.rs 里的纯函数**
  fn autoproxy_flags(auto_detect, pac_url) -> (u32, u32)，在 macOS 上表驱动测
  四种组合。这段纯映射本可以接住 W14 与本条——正是两层约定要防的失效模式，
  第一次检验就被咬中。

Ruling W16（高，必修；并推翻「留给 Task 10」那个决定）：
  **每次 eval_pac 自建自毁 WinHTTP 会话，把 PAC 与自动发现缓存全部扔掉。**
  MSDN 逐字：缓存挂在**会话句柄**上，「discarded when the application closes
  the session handle」，官方建议复用同一句柄。而 winhttp.rs:68-80 每次都
  WinHttpOpen、:119-121 返回前 WinHttpCloseHandle。
  叠加 winhttp.rs:103 的 fAutoLogonIfChallenged: true——文档说该标志为 TRUE 时
  进程外服务也不缓存，官方写法是先 FALSE、遇 ERROR_WINHTTP_LOGIN_FAILURE 再 TRUE。
  **结果：实现者用来给「阻塞问题留给 Task 10」背书的唯一缓解因素不存在。**
  MSDN 对耗时的说法同样逐字：自动检测「possibly as long as several seconds」，
  且这两个函数是「blocking, synchronous」；PAC 脚本执行本身允许跑到 60 秒。
  评审查明的真实伤害：preflight.rs:363 那次 effective_proxy **完全没包在
  bounded() 里**，而且一次预检要跑两遍 resolve()（:363 一次 + transport.connect
  内部一次），无缓存时就是两轮完整 WPAD 发现；更要命的是 **PROBE_TIMEOUT 对这条路
  本来就不可执行**——tokio::time::timeout 只能在 await 点取消，一个同步阻塞几十秒
  的 WinHTTP 调用不产生 await 点，8 秒预算会被直接穿过去。
  裁定本轮一并修：会话句柄复用（纯 Win32 层改动）+ fAutoLogonIfChallenged 两步法
  + Arc<S> 与 spawn_blocking。
  评审同时给出了那个「无法断言」说法的反例：用一个在 current() 里
  std::thread::sleep(2s) 的 ProxySource，在 #[tokio::test] 里断言
  tokio::time::timeout(100ms, resolve()) 会超时——今天这条会因为 timer 得不到
  调度而失败，改成 spawn_blocking 后会通过。**执行位置是可以写成断言的。**

Ruling W17（中，必修）：ProxyDecision 7 个变体里 **3 个没有变体身份测试**。
  评审实测：PacDirect → NotConfigured、PacDirect → Bypassed、
  StaticProxy 与 PacEvalFailedFellBackToStatic 整体互换，三次都是 27 passed 全绿。
  而 §3.10 诊断页最需要的两组区分恰好都在这三个里：
  「本就不需要代理」vs「PAC 说直连」、「正常静态代理」vs「PAC 挂了退回静态代理」。
  按「一个只在某几个变体上成立的区分等于没区分」，这个设计目前是 4/7 成立。
  另：那条折叠测试的 assert_eq!(into_target(), None) 一半**结构上不可证伪**
  （两个变体都无载荷，into_target 作用域里没有 HostPort 可返回）——
  「一条测试同时证明两件事」实际只证明了一件。
  实现者在变异表里对 pac_returning_direct 那一格做了诚实披露，
  却没把这个披露推成结论、也没补测试。

Ruling W18（中，必修；Task 1 的缺陷，但本 diff 是第一个真实调用点）：
  **parse_proxy_list 不识别 SOCKS / SOCKS5 / HTTPS 这三个标准 PAC 关键字**，
  会把关键字当主机名解析出一个假代理。评审实测 decide() 的真实返回：
    "SOCKS5 p.company.com:1080" → PacProxy(host: "SOCKS5", port: 80)
    "HTTPS p.company.com:8443"  → PacProxy(host: "HTTPS",  port: 80)
    "garbage"                    → PacProxy(host: "garbage", port: 80)
    "PROXY ;DIRECT"              → PacProxy(host: "DIRECT", port: 80)
  而 ProxyDecision 会把它报告成一个**自信的 PacProxy**——正是这个类型被引入来
  消除的那种混淆。现场表现：客户端去 TCP 拨一台叫 SOCKS5 的主机，
  失败被归因成「Gateway TLS 失败」。
  Task 1 的评审与 target_host_does_not_affect_selection 都只覆盖了
  PROXY/DIRECT 两个关键字。

Ruling W19（闸门加强，写进 Task 3-5 的派发）：
  **cargo-zigbuild clippy -p rmc-win --all-targets --target x86_64-pc-windows-gnu
  -- -D warnings 是可用的**（评审在净副本实测 15.8s、当前代码干净）。
  今天的 W1 闸门只做 build，而 clippy 跑在 macOS 上——**至今没有看过 winhttp.rs
  一行**。Task 3 是 SSPI，unsafe 面比这次更大。
  另一个说明证据力的实测：把 winhttp.rs 三处 GlobalFree 整个删掉，
  cargo test 27 passed，zigbuild 只报一条 unused import warning（留个假引用
  就完全静默）。这次修的三条缺陷里，第 3 条 100% 无自动化覆盖，
  第 2 条的 Win32 那一半也无覆盖——不是实现者的过失，是 cfg(windows) 的固有代价，
  但它说明「测试全绿」在这个任务里的证据力比 Task 1 更低。

低（随本轮顺手，不单独开条）：eval_pac 失败路径不对称（lpszProxy 不释放而
  lpszProxyBypass 无条件释放，实际泄漏为零但要读者自己推理）；winhttp.rs:113-115
  的注释把 MSDN 说反了（文档不但说会回填 lpszProxyBypass，还明确要求释放它）；
  winhttp.rs:55-56 的「失败时 WinHTTP 没有分配任何东西」是无文档支撑的断言；
  解析不出来的静态代理串折成 NotConfigured、解析不出来的 PAC 结果折成 PacDirect
  ——7 变体的分类法在「配了但看不懂」这一格是空的，而那一格恰恰是诊断页最该报的；
  free_pwstr/take_pwstr 是 safe fn 却对任意裸 PWSTR 做 GlobalFree。

范围外（记入 Task 10 的输入）：decide() 到 §3.10 中间还缺一段——
  run_preflight 走的是 Arc<dyn ProxyResolver>，PreflightReport 里能出现的信息
  上限就是 Some/None（preflight.rs:371-374 的「经代理 {p}」/「直连」）。
  要让 decide() 的区分真的出现在诊断页，要么 rmc-core 的 trait 加一个诊断方法，
  要么 rmc-app 在 PreflightReport 之外单独拼那一行。

Task 2: complete —— 05632db + a3db491，复审判「全部解决，可以收口」。
  35 passed，两条 zigbuild 闸门 + macOS clippy + fmt + deny 全绿。
  上一轮评审亲手做过的三次「全绿」变异（StaticProxy↔PacEvalFailedFellBackToStatic、
  PacDirect→NotConfigured、PacDirect→Bypassed）现在全部红。

  **实现者自己挖出的 dwAccessType 那条，经三方交叉核实属实**：
  Win32 头文件数值（NO_PROXY=1、NAMED_PROXY=3）、WINHTTP_PROXY_INFO 语义、
  以及 Chromium 的 proxy_resolver_winhttp.cc（成功后第一件事就是判
  dwAccessType == NO_PROXY → UseDirect()）。本次修法与它同构。
  旧代码只要调用成功就读 lpszProxy，PAC 说 DIRECT 时该字段通常是 NULL →
  decide() 报 PacEvalFailedFellBackToStatic 或 PacEvalFailedNoFallback。
  **任何用 PAC 且对 gateway 返回 DIRECT 的企业网络，客户端都会认定 PAC 坏了**，
  并去连一个本不该走的静态代理。这恰是 Task 2 标题要消除的那对混淆。
  复审还核了三点细节：WINHTTP_ACCESS_TYPE 是 repr(transparent) 且 derive Eq，
  所以 match 里是**真常量模式**——若当初没 derive Eq 会编译报错，
  若符号是 static 而非 const，第一条 arm 会退化成不可反驳绑定、永远命中，
  那会是静默的灾难。现在两条都成立。

  几件确认得很硬的事：
  - W16 那条「执行位置可以写成断言」的测试真写了真有效：去掉 spawn_blocking
    后 1 failed 且整套从 0.51s 变慢；还经得起换成 multi_thread flavor
    （仍然红），不会因为后人改 flavor 而静默失效。
  - 会话复用的 Send/Sync 是**编译器强制**的：删掉 unsafe impl Send 后
    zigbuild 报 E0277，链条一路指到 WinHttpSource。范围也恰当——只给内层裸指针
    包装 impl Send，没有画蛇添足地 impl Sync，Sync 是 Mutex 挣来的。
  - Arc<S> 不只是省一次拷贝：它让「关到正在用的句柄」**结构上不可能**——
    Drop 需要独占，而在途的 spawn_blocking 闭包持有 clone。
  - winhttp.rs 的 const _: () = assert! 是真闸门：把 mod.rs 的常量从 1 改成 9，
    macOS 35 passed 毫无察觉，zigbuild 直接 error[E0080]。

Ruling W20（带进 Task 3 顺手做，三条都小）：
  1. **dwAccessType 映射零自动化覆盖**（winhttp.rs:270-277）。复审实测：
     把 NO_PROXY 与 NAMED_PROXY 两条 arm 对调，35 passed + zigbuild +
     zigbuild clippy **全绿**。本轮后果最大的行为修复，一个字节的保护都没有。
     而它的形状与 W15 刚要求上移的 autoproxy_flags 一模一样——
     (dwAccessType, Option<String>) -> Option<String> 是纯映射，
     唯一碰 Win32 的数值已经有 const assert 守着。
     改法：让 eval_pac 返回 enum PacOutcome { Direct, Proxies(String) }，
     顺带消掉 "DIRECT" 这个新的跨层魔法字符串（形状与 W15 刚消掉的
     「空串当跨层信号」一致）。同一次动作顺手补 eval_pac 侧的 spawn_blocking
     断言——复审实测把它换成同步调用 35 passed，而它才是真正会阻塞数秒的那个。
  2. **Drop 里 lock().unwrap()**（winhttp.rs:66）：中毒时 Drop 自己 panic，
     unwinding 中则 abort，且句柄不关；:160 的同款会把一次中毒变成**永久性**的
     「PAC 求值失败」。改成 unwrap_or_else(|e| e.into_inner())，一行。
     Task 3 是 SSPI，unsafe 面更大，同样的形状在那里代价更高。
  3. **重试前覆盖 info 的释放不对称**（winhttp.rs:233）：
     `info = WINHTTP_PROXY_INFO::default()` 直接覆盖，若第一次调用已写入
     lpszProxy/lpszProxyBypass 就泄漏。这与同文件 :240-249 自己的论证
     （「不必再靠调用是否成功去猜要不要释放」）自相矛盾——两段必须一致。

复审的范围外观察（记入 Task 10 输入）：
  - WinHttpGetIEProxyConfigForCurrentUser 失败时折成 default → NotConfigured →
    「不需要代理」。该 API 在服务/SYSTEM/无用户配置单元下会失败，
    届时诊断页会把「读不到配置」报成「本来就没配代理」。
    7 变体的分类法里「读取失败」与「配了但看不懂」两格都是空的。
  - Mutex 让所有 PAC 求值串行化，而 spawn_blocking 任务**不可取消**——
    timeout 放弃后那次调用仍在阻塞线程里跑、仍持锁，下一次 resolve() 会排在
    后面。旧实现各开各的 session、不排队。方向正确（并发度 1 正是缓存要的），
    但「超时 → 重试 → 更慢」这条曲线变了，Task 10 按新形状算预算。
  - 没有 WinHttpSetTimeouts：PAC 下载/执行可达数十秒。spawn_blocking 解决
    「不占 runtime」，不解决「任务不可取消、线程被占住」。
  - **WinHttpSource 至今没有任何构造点**，Drop 与会话复用路径在真实进程里
    一次都没跑过；人工验收清单那三条要等 Task 10 接线才有人能执行。
  - 仓库根 .gitignore 忽略了 Cargo.lock。对一个要交付二进制、且依赖
    windows/russh 这类快速演进 crate 的产品，这是可重复构建与 cargo deny
    审计的风险。不在本 diff 里，但值得单独决定。

订正（Task 3 实现者指出，我已核实属实）：上一轮复审的范围外观察里那条
  「仓库根 .gitignore 忽略了 Cargo.lock」**与实际不符**——`git check-ignore`
  无输出、`git ls-files` 确认 Cargo.lock 已入库跟踪。这条观察销掉。

Task 3: 实现完成 f2dddad，评审已派发（opus，评审包 review-a3db491..f2dddad.diff）。
  派发里点名要独立核实的七件事：实现者自曝的 use-after-free（借用检查器与
  macOS 双盲）、W2 三条生命周期测试（第三条是变异逼出来的，要查是否用了
  不同实例）、W3 的 ProxyEndpoint/SPN 形状、九态出口的钉住率、
  Zeroizing 的唯一逃逸点、147 行 Win32 零覆盖下两层划分守没守住、
  以及 29 次变异的诚实性。

约定：Task 4-12 的正文在 docs/superpowers/plans/2026-09-13-rmc-win-and-app-part2.md，
  但账本与全部产物仍统一放在本目录（2026-09-13-rmc-win-and-app/），不另开工作区。
  task-brief 脚本按计划文件名派生目录，生成后手工移过来。

=== Task 4 派发前预检（我自己读 brief 做的，编号接 W20）===
依赖面先核过：sha2 = "0.10" 已是 rmc-core 的直接依赖、Cargo.lock 里是 0.10.9，
  rmc-win 加这一条不新增依赖边（锁里另有一个 0.11.0，是别的包拉的，不受影响）。
  Win32_Security_Cryptography feature 骨架阶段已备好（W6 那次预留），
  CryptProtectData/CryptUnprotectData/CRYPT_INTEGER_BLOB 都在里面。

W21（必修，这是同一个缺陷类的**第三次**出现）：`load()` 返回 `Option`，
  把「本来就没记住密码」与「记住了但解不开」压成同一个 None。
  前两次：Task 2 的 `resolve()`（不走代理 vs 解析失败），Task 3 的
  `next_token()`（协商成功结束 vs 失败结束）。两次的解法都是另给带类型的出口。
  这一次的现实后果最直接：用户换了 Windows 账号或换了机器，DPAPI 解不开，
  密码框空着且**没有任何解释**，用户会以为「我明明勾了记住密码」。
  要求：`load` 之外给一个带类型的出口，至少分开「没有这条记录」/「有记录但
  解封失败」/「解封出来不是合法 UTF-8」，并让每一格都有身份测试。
  Task 2 的教训是 7 变体里 3 个没有身份测试，而那 3 个恰好是诊断页最需要的。

W22（必修）：`plaintext_never_hits_the_disk` 是已知的空转形状——
  断言写在 `for entry in read_dir(&dir)` 的循环体里，`save` 若一个文件都没写，
  循环体一次都不执行，测试照样绿。rmc-core 的审计日志那条踩过一模一样的坑
  （把 record() 改成 no-op，断言不是在 !contains 上失败的，是被显式的
  `assert!(!text.is_empty())` 排掉的）。这里补同样的显式前置：先断言目录里
  **恰好有一个文件且非空**，再查内容。并且要变异验证：把 save 改成 no-op 必须变红。

W23（必修）：`unseal` 解出来的明文经 `take_blob` 落进一个普通 `Vec<u8>`，
  然后 DPAPI 那块缓冲区被 `LocalFree` **原样释放、没有清零**。
  Zeroizing 只盖住了拷贝出来的那一份，原件留在已释放的堆上。
  全局约束对口令的要求（只用 Zeroizing、不进日志/Debug/错误）在这里被绕过。
  改法：LocalFree 之前把 blob.pbData 指向的字节清零（volatile 写，别让编译器
  优化掉——zeroize 的 `Zeroize` 对 `&mut [u8]` 就是干这个的）。
  这与 Task 3 自承的那个 Zeroizing 逃逸点是同一条防线，但这一次修法零成本，
  不需要动 rmc-core 的 trait。

W24（必修）：`String::from_utf8(plain.to_vec())` 多做了一次明文拷贝
  （`plain` 已经是 `Zeroizing<Vec<u8>>`，`to_vec()` 再克隆一份）。
  成功路径上两份都会被清零，但失败路径（`.ok()?`）里 `FromUtf8Error`
  持有的那份字节没有任何保护就被丢掉了。用 `String::from_utf8(std::mem::take(...))`
  之类的方式避免克隆，并保证失败分支也清零。

W25（必修）：`save` 的临时文件 `{hex}.tmp` 在 `rename` 失败时留在盘上，
  内容是密文——不是灾难，但 `clear()` 删的是 `{hex}.sealed`，
  删不掉这个残留。用户点了「不再记住密码」之后盘上还留着一份能解开的密文。
  要么失败时删 tmp，要么 clear 把两个名字都删掉，并各配一条测试。

W26（必修，与 rmc-core 的 R93 同形状）：文件按默认 umask 创建。
  Windows 上落 %LOCALAPPDATA% 靠 ACL、mode 位无意义，
  但这个 store 是跨平台的纯逻辑层，CI 与开发机上就是真实暴露。
  照 R93 的落地方式：`#[cfg(unix)]` 的 `OpenOptionsExt::mode(0o600)` +
  目录 0o700，**在创建那一刻带上权限**（不是先创建再 chmod，那留了抢占窗口），
  并在模块文档写明「Windows 侧靠 ACL 不靠 mode 位」——R88 判过，
  「权衡后认为无意义」与「压根没考虑过」是两回事，代码里要看得出是前者。

W27（提醒，不是缺陷）：brief 里 `CRYPT_INTEGER_BLOB` 的输入是在函数作用域
  建的 `let mut input`，生命周期够长，**没有** Task 3 那个
  「把缓冲区建在 match 分支块里、SecBufferDesc 指着已释放的栈内存」的问题。
  但实现者必须自己复核这一点，并在报告里明确写「复核过，形状不同」——
  那个缺陷借用检查器看不见、macOS 上完全隐形，只能靠人读。

W28（携带）：`FileSecretStore::new(dir, sealer)` 的 `dir` 从哪来，
  brief 没说，Task 10 接线时才定。rmc-core 的 config.rs:38 那条
  「log_dir 默认相对路径 logs」已经是同一个形状的未了账（R97 记过）。
  Task 10 要一次性把 %LOCALAPPDATA%\rmc\ 这个落点给审计日志、known_hosts
  与密码存储三处都接上，别分三次。

=== Task 3 评审结论：通过（9 条发现：3 中 + 1 低中 + 4 低 + 1 信息）===
复审自己重做了 30 次变异（报告的表重做 25 条，另加 5 个探针），逐条跑全套 62。
  **报告的表没有一处不实，包括它自曝的两格「绿」。** 复审的原话：
  「这是我见过的自评最诚实的一份」——它自己报出两格失败的变异并据此补了第三条测试。

独立核实成立的三件大事：
  1. **那个 use-after-free 是真的。** 复审在仓库外副本里把 brief 的写法忠实还原
     （SecBuffer 建在 match 分支块里、SecBufferDesc.pBuffers 记它的地址），
     `cargo zigbuild --tests --target x86_64-pc-windows-gnu` **绿、零告警**，
     `cargo-zigbuild clippy -- -D warnings` **绿、零告警**，macOS 上整块
     #[cfg(windows)] 被切掉、62 条一行跑不到。**三条自动化防线全部双盲。**
     借用检查器看不见的机理也核了：pBuffers 是 *mut SecBuffer，
     `&mut buf` 在字段初始化位置隐式强转，借用当场结束。
  2. **W2 的三条测试确实缺一不可**，且三条都用**同一个协商器实例**跑两条模拟连接
     （换新实例的话「新连接开新上下文」变成恒真）。假上下文之间用 next_id 发不同
     ctx_id、断言里直接写 ctx_id: 1，所以「换了新实例」是被观测到的不是推断的。
     两种破坏方式（brief 的 spent 语义 / `neg.context.is_none()`）各自只被其中
     一边抓到，复审逐格复现，与报告自曝的两格完全一致。
  3. **W3 在当前代码里拿得到正确的那台代理。** resolve() 全仓只有
     Transport::effective_proxy 一个调用者，它的调用者只有 connect 与
     preflight.rs:363（同一个 target、紧接着就 connect），
     Supervisor 的 connecting_or_connected() 挡住并发建连。串行前提成立。

--- 裁决 ---

Ruling W29（中，本轮修）：imp.rs:246-280 那 35 行「状态码分类 → SspiStep」
  仍留在零覆盖层。复审把 Continue/Done 两条 arm 的**函数体对调**
  （语义上是灾难：要继续的一段被标成结束）——zigbuild 绿、clippy 绿、零告警。
  形状与 W20.1 刚要求上移的 dwAccessType 一模一样，而这是**同一个坑的第三次**
  （Task 2 的 autoproxy_flags、dwAccessType，现在是它）。
  报告第五节「已经把能搬的判断都搬出来了」言过其实，要改口。
  提成纯函数 `step_from(kind, token) -> (SspiStep, bool /*接管 ctx*/, bool /*finished*/)`
  放进 sspi.rs 表驱动测。
  **现在修的理由**：这 35 行是全 crate 后果最大的代码，而它现在无法被任何闸门验证。

Ruling W30（中，本轮修）：AuthOutcome::diagnostic() 九个分支只有 3 个被断言碰过，
  **NotAttempted 连身份测试都没有**。复审把六个分支文案清空、并把 NotAttempted
  的判定从 None 翻成 Some(false)——**62 全绿**。后果：没有代理的机器上诊断页
  报一条硬失败，没有任何闸门会响。而 NotAttempted 正是绝大多数没有代理的现场
  唯一会看到的那一行。这是 Task 2「7 变体里 3 个没身份测试、而那 3 个恰是
  诊断页最需要的」在下一层的原样复现。
  补一条表驱动测试，对九个变体逐一断言 (Option<bool>, 文案关键词)，
  并把「第一项永不为 Some(true)」从只钉 TokenIssued 扩成钉全部九个。

Ruling W31（中，本轮修）：**AuthOutcome::Completed 在真实 Windows 上近乎不可达。**
  我自己核过 imp.rs:262-271：只有状态码 Done **且没有输出 token** 才给
  SspiStep::Done；而 NTLM 第二段与 Kerberos 单段都必然带着要发的 token 返回，
  走 SspiStep::Token 并置 finished。于是代理拒绝凭据的真实路径是
  TokenIssued（diagnostic().0 == None，**无结论**）或 Failed(「这个上下文的
  协商已经结束」，内部行话）。**「凭据格式没问题，是代理不接受当前用户」
  这句最需要的话挂在一个产不出来的状态上。**
  修法：让 SspiStep::Token 带上「是不是最后一段」，AuthOutcome 据此分开
  「中间 token 已发出」与「最后一段 token 已发出、等代理裁决」，
  把那句诊断挪到后者。**现在修不等 Task 9 的理由**：Task 9 要在这张表上
  建映射，那时再改要同时动两个任务。

Ruling W32（低中，本轮修）：UnsupportedScheme(String) 收的是代理响应头里
  未加长度约束的字节（read_response 按第一个空格切 scheme，整行上限 16KB），
  直接进诊断行与 Debug。仓库已有对应规范与测试
  （knownhosts::tests::damaged_line_error_message_is_bounded_in_length 要求 <1000 字节），
  这里没遵守。照同一条规范截断。

Ruling W33（低，本轮修，四条一起）：
  - impl Debug for SspiProxyAuthenticator（sspi.rs:474）取了 negotiation 那把
    长持有的锁。拆两把锁的全部理由就是「诊断页读结局时不该被正在进行的协商挡住」，
    last_outcome() 做到了，Debug 又把口子开回来。Debug 只读 outcome。
  - 报告遗留 #4 称 recorder 的串行假设「已写在该类型的文档里」——**不属实**，
    sspi.rs 里 grep 不到。补进 ProxyEndpointRecorder 的文档，
    并写明真正的逃逸口不是并发建连（Supervisor 已挡）而是
    effective_proxy 被文档标为「供界面显示使用」：Task 9/10 一旦轮询它，
    就会在协商途中改写 recorder，无测试会红。这句同时进 Task 9/10 的派发。
  - spn_for_proxy 的 None 分支无测试（HostPort::new(".", 8080) 合法、去尾点后为空）；
    IP 字面量代理会拼出 HTTP/10.1.2.3 这类对 Kerberos 无意义的 SPN，无测试无说明。
  - commit message 写「新增 20 条 sspi」，实际 25 条（报告正文的表是对的）。
    不改写历史（这一轮会新加提交），记在案。

Ruling W34（信息升为本轮修）：**UAF 的防复发只有注释，类型上没有任何东西
  挡住后人再把缓冲区挪回块内。** 鉴于复审实测三条防线全部双盲，
  「靠注释」在这一处是不够的。改成复审建议的闭包形状
  `fn with_input_desc<R>(bytes: &mut [u8], f: impl FnOnce(Option<*const SecBufferDesc>) -> R) -> R`，
  把自引用关进必然比调用长寿的栈帧，调用方再也写不出「建在块里」的形状。
  约 15 行，换掉本计划至今最严重缺陷的复发可能。

Ruling W35（中，本轮修，**从范围外提进来**）：connect.rs:94 的
  `auth_scheme.is_none()` 只取**第一条** Proxy-Authenticate。企业代理同时通告
  Basic / NTLM / Negotiate 是常态，顺序不由我们控制。代理若先列 Basic，
  就把 Task 3 整个能力旁路掉——现表现是 UnsupportedScheme("Basic") →
  ProxyAuthFailed，而机器明明能做 Negotiate。
  **提进本轮的理由：不修的话 Task 3 在最常见的企业配置下等于没做。**
  改成收集全部 scheme、按 Negotiate > NTLM 优先选。
  同处 connect.rs:152 的 `unwrap_or_else(|| "Basic".into())` 一并去掉——
  代理压根没给 scheme 时，诊断页现在会说「代理要求 Basic 认证」。

Ruling W36（本轮修，**趁没有下游消费者**）：
  ProxyAuthenticator::next_token 的返回改 `Option<Zeroizing<String>>`。
  复审核过逃逸路径：token 经 connect.rs:157 的 format! 进 authorization，
  再经 :117-124 拼进 req: String 写 socket；**不进日志、不进错误**
  （send_request 无日志，ProxyAuthFailed 只带 scheme），
  但两者都是普通 String、drop 时不抹零，堆上留残影直到被复用。
  内容是 NTLM Type-3（NT/LM response）或 Kerberos AP-REQ 的 base64——
  离线爆破 NTLMv2 response 是成熟手法。真正让它值得堵的是 Task 9 的
  **诊断包导出**：哪天有人往包里加进程内存快照，这两个 String 就是
  现成的凭据派生物。
  **现在付 8 处、且下游一个消费者都没有**（system_sspi_authenticator 至今
  没有调用点）。等 Task 6-12 之后改，会同时牵动 app 侧接线与那时已写好的诊断页。

Ruling W37（不修，记录）：协商成功后上下文与凭据句柄留到下一次重连
  （TokenIssued 分支不清 neg.context），DeleteSecurityContext/FreeCredentialsHandle
  在长会话里数小时不执行。不是泄漏，但人工验收第 6 条「长时间挂着看内存」
  要按这个事实看。

Ruling W38（携带进 Task 9）：诊断页「代理认证（SSPI Negotiate）」那一行
  至今没有任何任务会画。Task 9 的 brief 要补上，并带**完整九格**的
  「CONNECT 结果 × last_outcome()」映射——报告里那张表缺一格，
  缺的恰好是最常见的失败（CONNECT 失败 + TokenIssued）。

Ruling W39（携带，写进后续每一次派发）：sed -i.bak + mv 会让 mtime 退回、
  cargo 复用被改坏的产物。变异验证一律用会推进 mtime 的写法，恢复后 touch。
  复审这次全程这么做，并逐文件比对确认副本与原仓库一致、原仓库 git status
  全程干净、HEAD 未动。

Ruling W40（不修，记录）：代理拒绝凭据时 http_connect 会在 5 轮里白跑 2.5 遍
  完整协商（每遍一次 AcquireCredentialsHandleW + InitializeSecurityContextW），
  因为「407 不带 token」被**正确地**识别成「新一轮开始」。语义没错。
  W35 落地后观察真实轮数，必要时再给 MAX_ROUNDS 或协商器加
  「同一次 CONNECT 内不重开」的计数。

Task 3: 修复轮 1/5 已派发（10 条：W29-W36 + W33 的四小条）。

Task 3 修复轮 1：实现者交回 72a7b8f（十条全做）。定向复审已派发（opus，
  评审包 review-f2dddad..72a7b8f.diff）。自报数：rmc-win 62→74、
  rmc-core lib 198→210、tests/connect.rs 9→12，共 +27；20 条变异实测红、
  8 条实测不会红；六道闸门全绿。

实现者主动报的两条**负面结论**（这是它这两轮一贯的做法，价值最高的部分）：
  - **W34 换掉的是复发的代价，不是复发的可能。** 它把 SecBuffer 挪回块里
    （这次挪进 with_input_desc 内部）实测：macOS 74 ok、zigbuild 零告警、
    windows clippy 零告警——**三道防线依旧全部双盲**。闭包形状做到的是
    「调用方那 60 行里连写的地方都没有了，要犯这个错必须去改一个 15 行、
    文档从头到尾在讲这件事的 helper」。真正能检测它的只有 Windows 上的
    Application Verifier 或 ASan CI。
  - **W36 钉住的是签名，不是「没有第二份副本」。** 在 rmc-win 内部多抄一份
    普通 String 实测 74 全绿；类型改动只能被「编译不过」抓住，因为观察 drop
    之后的堆内存本身就是 UB。唯一在运行期真被钉住的是它额外补的那条：
    Zeroizing<String> **挡不住 String 扩容**——旧缓冲区原样还给分配器、
    不抹零——所以 connect_request 改成一次算够容量，用 capacity() == len()
    反查（M20 实测红）。

Ruling W41（携带进 Task 12）：UAF 这一类缺陷在本机三道闸门下**结构上不可检测**
  （macOS 切掉整块 cfg(windows)，zigbuild 与 clippy 都不做别名/生命周期分析）。
  Task 12 的 CI 要么上 Windows runner + Application Verifier，要么放弃这一类的
  自动化检测并在文档里说清楚。这是本计划唯一一处「已知无法被现有闸门覆盖」的
  缺陷类，不能靠下一个人自己发现。

Ruling W42（认可实现者的取舍，不改）：MAX_SCHEME_CHARS 的**具体数值**没被钉住
  （64 改 900 两处都全绿，因为 900 + 文案仍 < 1000）。这与仓库现有的
  knownhosts::tests::damaged_line_error_message_is_bounded_in_length 是同一个
  性质——钉的是「有界」这条性质，不是某个常量。实现者按现有规范办、
  没单方面加严，判断正确。截断标记 `…（已截断）` 删掉也全绿这一条同理。

Ruling W43（携带进 Task 9/10 的派发，必须照抄）：ProxyEndpointRecorder 的
  逃逸口现在只有文档、没有测试——那句警告的效力**完全取决于 Task 9/10 的
  派发单会不会照抄「不要轮询 effective_proxy」**。这条不是建议，是派发单的
  必填项：Task 9 与 Task 10 的 brief 里都要出现「界面显示代理信息时不得
  调用 Transport::effective_proxy，它会在协商途中改写 recorder 且无测试会红」。

=== Task 3 修复轮 1 的定向复审：十条里 8 条 ✅、2 条 ⚠️ ===
复审把六道闸门全部自己复跑，并且**在一份与 HEAD 逐字节一致的仓库外副本里
清掉 fingerprint 重跑第 3/5/6 道**以排除缓存假绿——仍然 rc=0、零告警。
  测试数 74/210/21/12 逐个核过属实，Cargo.toml/Cargo.lock 一个字没动。
  实测 12 条变异全部变红、7 条实测不红。**报告那张表没有一处不实**，
  包括实现者主动自曝的八格绿。W29/W30 两个「上一轮三道防线全盲」的变异
  现在都在 macOS 上当场变红——这一轮解决的是本计划里最要命的那类问题。

复审顺手纠正了我派发单里的一个错误前提（它是对的）：我写「token68 里本身
  可以有逗号」，而 RFC 7235 §2.1 的 token68 字符集里**没有逗号**。
  所以按逗号切不会切坏带 challenge 的行。实现者的实现是对的，我的顾虑不成立。

--- 两条 ⚠️ ---

Ruling W44（必修，本轮）：**W34 只收了输入侧，输出侧一寸没收。**
  复审做了 P2b：把 `step` 的输出描述符 `imp.rs:212-221`（`out_desc.pBuffers
  = &mut out_buf`，两个都是 step 的局部变量，而 out_desc 要活过闭包里那次
  InitializeSecurityContextW）照同样的方式挪进块里——
  macOS 74 ok、zigbuild rc=0 零告警、windows clippy rc=0 零告警。
  **同一个 use-after-free 形状、同一个函数、三道防线同样全盲、照样编得过。**
  而那块缓冲装的正是刚从 SSPI 拿到的 token。
  实现者「step 那一侧连写的地方都没有了」这句**说轻了半边**：
  对它做的那一半准确，对没做的那一半失实。照 with_input_desc 的样子收进闭包。

Ruling W45（必修，本轮，**我判得比复审重**）：
  复审写了一个走完整 http_connect 链路的端到端探针（真实 SspiProxyAuthenticator
  + tokio::io::duplex 假代理），实测两种真实的代理拒绝形状：
  - **形状 A**（拒绝的 407 带 token68）：Completed 到得了，文案正确，3 次 CONNECT。
  - **形状 B**（拒绝的 407 是裸的 `Proxy-Authenticate: Negotiate`——
    NTLM 拒绝 Type-3 之后的标准写法，Negotiate 也常见）：
    outcome 停在 `TokenIssued { round: 1 }`，`diagnostic().0 == None`，
    文字是「协商还要继续」——**而 CONNECT 已经确定失败**。
    实测 **5 次 CONNECT、4 个完整上下文**（4 次 AcquireCredentialsHandleW
    + 4 次 InitializeSecurityContextW，域机器上每次都可能去找域控）。

  机理复审查清楚了：sspi.rs:781 的 `concluded` 那一支排在 `start_new` 之后，
  而 `start_new = decoded.is_none()`；裸 407 ⇒ token68 为 None ⇒ start_new
  为真 ⇒ `*neg = Negotiation::default()` 把 concluded 一起清掉 ⇒
  **那一支永远撞不上**。

  **这不是实现者的疏忽，是 W2 留下的真实两难**：把 concluded 挪到 start_new
  之前，就会把「新 TCP 连接的第一个裸 407」误判成「被拒绝」，
  那正是 W2 当初要修掉的 bug（客户端第一次断线后永久废掉）。
  同一个信号（challenge == None）承担了两个互斥的含义，
  而 next_token 手里**没有任何连接身份**可以区分它们。

  所以复审给的「改报告 + 写进 Task 9 派发」不够——那是让 Task 9 的诊断页
  去给一个答不出这个问题的状态机打补丁。**根因要在 rmc-core 的 trait 上修**：
  给 ProxyAuthenticator 一个显式的连接边界信号（如 `begin_connection()`，
  由 http_connect 在循环前调用一次）。这样：
  - 「每次连接尝试新建上下文」这条 W2 的硬约束从**推断**变成**结构性保证**；
  - 连接内的裸 407 + concluded 可以正确判成「代理拒绝了凭据」；
  - W40 那 4 次白跑的上下文一并消失。
  **现在付的理由和 W36 一模一样：下游一个消费者都没有**
  （system_sspi_authenticator 至今没有调用点）。等 Task 6-12 之后再改，
  要同时动 app 接线与那时已写好的诊断页。

Ruling W46（本轮顺手，三小条，复审记的）：
  - sspi.rs:1970 的 variant_name 只保证「加变体会编译不过」，
    **不保证新变体进了 cases 表**——表里那条 names.len() == cases.len()
    只查重复不查遗漏。加第十一格并顺手补 variant_name 而不动表，测试照样绿。
    从一个穷尽 match 生成表，让漏掉变体编译不过。
  - the_debug_rendering_does_not_wait_for_a_negotiation_in_flight（sspi.rs:2188）
    靠 sleep(80ms) 等对方拿锁，机器负载高时方向是**假绿**不是假红。换成真同步。
  - step 开头那句 `if self.finished { Failed("这个上下文的协商已经结束") }`
    在 W31 之后实际已到不了（Done/Failed 都会把 context 置 None，
    下一次走 ChallengeWithoutNegotiation），但它仍是那句内部行话在代码里
    唯一的出处。W45 落地后重新推导这一支的可达性，要么给它像样的文案，要么删掉。

Ruling W47（认可，记录）：复审对 capacity() == len() 那条断言的成色判断
  **比实现者自己说的好**——`String::with_capacity` 若哪天改成过量分配，
  这条断言**变红**（假红）不会变绿，失效方向是安全的；而 MSRV 被
  rust-toolchain.toml 钉死在 1.89，「某个 Rust 版本上突然假红」要先经过
  一次有意的工具链升级。复审还读了 zeroize 1.9.0 的
  `impl Zeroize for Vec<Z>`（注释原文 "Cannot ensure that previous
  reallocations did not leave values on the heap"）——zeroize 本来就会抹掉
  整个 capacity，唯一的漏洞恰恰是「之前那次重分配留下的旧块」，
  with_capacity 一次算够正好把那个唯一的漏洞堵死。**这条断言瞄的位置是对的。**

Ruling W48（升级 W41）：W44 之后，UAF 这一类在本机三道闸门下不可检测
  已经被实测**两次**（输入侧 P2、输出侧 P2b）。Task 12 的 CI 必须正面回答
  这一类怎么办，不能留给下一个人。

Task 3: 修复轮 2/5 已派发（W44、W45、W46 三条）。

=== 暂停（用户指示，等其消息再开始）===
修复轮 2 的实现者刚起步就被我停掉了，**没有任何改动落地**：
  HEAD 仍是 72a7b8f，工作树干净，git status 无输出。
恢复时的入口：W44、W45、W46 三条尚未开工，派发单的内容已完整写在上面的裁决里
  （W45 的端到端探针两种形状、W44 的 out_buf/out_desc 输出侧、W46 的三小条）。
Task 4 的说明书与预检（W21-W28）已备好，在 task-4-brief.md。

=== 恢复（用户指示「继续」）===
修复轮 2/5 重新派发（W44、W45、W46 三条），BASE 仍是 72a7b8f。

Task 3 修复轮 2：实现者交回 0c32b50（三条全做，5 文件 +916/−217，
  Cargo.toml/Cargo.lock 未动）。自报 rmc-win 74→79、tests/connect.rs 12→14、
  rmc-core lib 210 不变；11 条变异实测红、5 条实测不红；六道闸门全绿。
  定向复审已派发（opus，评审包 review-72a7b8f..0c32b50.diff）。

实现者主动报的三条负面结论（第三轮延续这个做法）：
  - **P1：W44 这类修复只收代价、不收可检测性。** 把 SecBuffer 挪回块里逐字
    复现 UAF——macOS 79 ok、zigbuild rc=0 零告警、zig-clippy rc=0 零告警。
    **同一类缺陷第三次实测全盲。**
  - **P3 这一格绿，它没能修成可测的。** `neg.started = true` 从「调工厂之前」
    挪到「工厂成功之后」，79 条 + workspace 全绿——因为 http_connect 拿到 None
    就立刻退出，同一条连接里不存在「工厂失败之后的下一次调用」。
    也就是说这条约束目前靠**调用方的行为**成立，不靠这里的代码成立。P4 同理。
  - **begin_connection 保住 W2 靠的是「http_connect 记得调」，不是类型。**
    trait 方法做成无默认实现（逼实现者表态），那一次调用由 rmc-core 两条测试
    钉住，但「调用方忘了调」在类型上仍然写得出来。

实现者还指出我派发单点名的第三条变异**需要翻译**：Negotiation 里加 `spent`
  （老注释的写法）现在杀不掉 a_challengeless_call_...（M10 实测 79 全绿），
  因为 begin_connection 整个换掉 Negotiation 顺手把它清了；标记提到 Inner 上
  （M10b）就照样红。它据此改写了测试注释，免得后人照老注释做一次变异、
  看到全绿就以为测试失效。**这个翻译对不对交复审独立判**，
  关键问题是：W2 那条约束现在是被测试守着，还是被 begin_connection 的
  实现细节偶然守着。

--- 对实现者两处请示的裁决 ---

Ruling W49（认可它不做，W43 原样保留）：它指出 begin_connection 是天然的
  「把这次连接用哪个代理定下来」的时刻，本可以顺手修 ProxyEndpointRecorder
  的窗口，但**没做**，理由是修不完整（resolve() 与 begin_connection 之间还隔着
  一次 TCP 连接），而把 W43 那条派发单必填项改成「大概不用了」会更坏。
  **这个判断是对的，照准。** 半个修复让警告显得过时，比不修更危险。
  W43 保持必填项状态不变。

Ruling W50（macro_rules! 的事交复审判，我先记下判据）：它为了让「表漏一格」
  变成编译错误，把 AuthOutcome 的**声明**包进了 macro_rules!
  （稳定 Rust 里 variant_count 仍是 unstable，确实没有别的路）。
  这是本轮唯一一处为测试能力去动生产代码声明形状的地方，它主动请示了。
  判据我列给复审：一、加变体不加进表是不是**真的编译不过**；
  二、文档注释与 derive/属性有没有在宏里活下来；三、从消费方看公开 API
  形状有没有变；四、可读性与 IDE 跳转的代价，以及有没有更便宜的稳定写法。
  倾向接受——这个项目 19 个「测试通过但没验证名字声称的事」的账，
  值得用一点声明形状换一条编译期保证——但要复审先把上面四条核完。

Ruling W51（携带，不在本轮）：真正关死「调用方忘了调 begin_connection」
  要把连接身份塞进 next_token 的签名，那是又一次 trait 改动。
  实现者判断不该本轮顺手做，**我同意**：无默认实现 + 两条钉住调用点的测试
  是合理的停手处，而连接身份会带来「什么时候退休一个 id」的簿记问题，
  不该在一轮整改里顺手引入。Task 10 接线时若发现调用点不止一处，再回来重估。

=== Task 3 修复轮 2 的定向复审：三条全部 ✅，判可以收口 ===
复审把 HEAD 整个 rsync 到仓库外（逐字节核对每个 tracked 文件、无 target/ 无 .git/，
  等于零 fingerprint），在净副本里从零重跑第 3/5/6 道并加跑第 1、4 道——全绿、
  **全程没有一条 warning:**。测试条数增量逐个核实（rmc-win 74→79、
  tests/connect.rs 12→14、rmc-core lib 210 不变），
  Cargo.toml/Cargo.lock 实测为空 diff。报告那两张表没查到一处不实。

三条的实测证据：
  - **W44**：`step` 里现在能写出自引用的地方是 **0 处**（复审自己数的：全文只出现一次
    SecBufferDesc，是闭包参数类型，没有任何一处构造）。全 crate 只剩两个 12-15 行的
    helper 函数体。ISC_REQ_ALLOCATE_MEMORY 的三条语义都在，
    CompleteAuthToken 只能写在闭包里、排在归还之前，这条顺序变成结构性的了。
  - **W45 形状 B 从 5 次 CONNECT / 4 个上下文 / 「协商还要继续」变成
    3 次 / 1 个 / 与形状 A 逐字相同的正确结论。** 复审自己跑的数字。
    W40 判定**不需要**再加计数：`started` 在调工厂之前置位、只在 begin_connection
    清零，「一次连接尝试建两个上下文」写不出来（M2 实测 13 条红）。
  - **W46**：加变体不进表实测两条路都编译不过（E0308 数组长度 10 vs 11；
    E0004 non-exhaustive）。sleep(80ms) 换成 oneshot 是真同步
    （advance 第一行取锁、一路持到 ctx.step，信号发出时锁一定已被持有）。

**W2 是被测试守着，不是被实现细节偶然守着**——复审做了两步独立验证：
  先把 begin_connection 换成逐字段重置（79 全绿，是等价实现），
  再在逐字段重置之上做我派发单原文那条变异（Negotiation 加 spent、
  begin_connection 忘了重置它）——**当场变红**。
  所以 M10 之所以绿不是测试失效，是那个变异在「整体替换 Negotiation」的形状下
  已经不代表一个真实缺陷。实现者改写的测试注释准确。

Ruling W50 落定（**接受那个 macro_rules!**）：四条判据复审全核过——
  加变体不进表真的编译不过（两条路都堵死，rc=101 一条测试都跑不起来）；
  属性活下来且有语义效力（它把 #[deprecated] 加进宏里，clippy 报出 21 条
  use of deprecated，证明不是被当字符串吞掉）；公开 API 形状逐行 diff 完全一致，
  cargo doc 里枚举文档与每一格变体文档全在；代价只是 IDE 跳转落在宏调用点。
  它还替我找了最接近的替代写法（production 声明不动、穷尽 match 写进测试模块）
  并说明为什么更弱：**那个写法不强制新变体进 cases 表**，补上 arm 就绿了，
  新那一格的文案照样一个字没被看过——正是 W46 要消灭的漏洞。
  照复审建议，在宏调用点补一句「这就是一个普通的 pub enum，包在宏里只为让
  编译器数出变体个数；展开后用 cargo expand -p rmc-win sspi 看」。

Ruling W52（本轮顺手补，复审新发现第 1 条）：**报告 §五 P3 的「为什么没测出来」
  失实**——它说「要变成可测，得让 http_connect 改成『None 之后再试一轮』」，
  而复审写了一条 20 行、跟同模块其它生命周期测试同构的单元测试（工厂恒返回 None，
  begin_connection 之后连调两次 next_token，断言工厂只被调一次），不碰 http_connect：
  当前代码绿、P3 变异下当场红（left: 2, right: 1）。这是可以廉价补上的真缺口，
  别记成「必须改调用方才能测」的悬案。已向复审索要源码，我自己落地并复跑变异。

Ruling W53（记进 Task 9/10 的观察项，不动手）：begin_connection 与
  「被取消的连接尝试残留的 spawn_blocking(advance)」之间没有顺序保证。
  旧任务若在重置**之后**才抢到锁，会在新连接的干净 Negotiation 上建出上下文、
  把 round 推到 1，新连接第一次 next_token（无 challenge）随即撞上那一支，
  报「代理在协商途中不再给 challenge」，白白失败一次。
  **这是本轮新引入的性质**：修复前这种污染会被下一次 challenge == None 的重建自愈，
  现在要等下一条连接的 begin_connection 才自愈。触发需要旧任务在整个重连窗口里
  都还没开始执行，概率很低。

Ruling W54（记进 Task 9/10 的派发单，必填）：**「W2 不被破坏」现在依赖
  http_connect 记得调 begin_connection，而不是依赖类型。** 忘了调的后果
  **比修复前更重**——复审推演过：第一条连接协商完 concluded 留着，
  第二条连接的裸 407 返回 None，第三条连接 started 仍为真而 context 为 None
  → ChallengeWithoutNegotiation，**客户端永久废掉**，正是 W2 当初那个 bug；
  而修复前这一格是结构上不可能的（challenge == None 会自愈）。
  目前被三条测试钉住（两条 rmc-core + 一条 rmc-win 端到端），
  且 next_token 全仓库只有一个调用方（connect.rs:351，复审 grep 过）。
  **派发单必填项：任何第二个 next_token 调用方出现时，
  必须先回答「谁来划连接边界」。**

Ruling W55（记进 Task 9/10，本轮不动）：同一次失败里 http_connect 抛出的
  错误文案是「代理要求 Negotiate，本机无法协商」（connect.rs:359，72a7b8f 就有），
  与诊断行「凭据格式没问题，是代理不接受当前用户」**互相矛盾**。
  W45 让这个矛盾从罕见变成**最常见的形状**。Task 9/10 一起改。

Ruling W56（记录，文字精度）：with_output_desc 的文档把「归还一定发生」
  说得比实际绝对（imp.rs:222-227）——f 内 panic 展开时 take_token 不执行，
  缓冲既不抹零也不归还。f 里唯一能 panic 的只有 tracing::warn!，实际到不了。
  收口时把文案改成「不论返回的是成功还是失败状态码」。

Ruling W57（升级 W48/W41）：UAF 在本机三道防线下不可检测，现已 **四次独立实测**
  （输入侧 P2、输出侧 P2b、实现者 P1、复审本轮复现）。
  Task 12 的 CI 必须正面回答这一类怎么办——Windows runner + Application Verifier，
  或明确放弃并写进文档。不能留给下一个人。

=== Task 3: complete ===
提交链：f2dddad（实现）→ 72a7b8f（修复轮 1，十条）→ 0c32b50（修复轮 2，三条）
  → ba69eec（收口三条，我自己做的：W52 的测试、W50 的宏说明、W56 的文案）。
最终状态：rmc-win **80 passed**、rmc-core lib 210、tests/connect.rs 14，
  workspace 十个测试目标全 ok / 0 failed；
  clippy --workspace -D warnings、fmt --check、
  cargo zigbuild -p rmc-win --tests --target x86_64-pc-windows-gnu、
  cargo-zigbuild clippy 同 target -D warnings——**六道全绿、零告警**。
  Cargo.toml/Cargo.lock 全程未动，无新依赖包。

W52 我自己复跑了变异：把 `neg.started = true;` 从工厂调用之前挪到工厂成功之后，
  `left: 2, right: 1` 当场变红，**且只红这一条、无误伤**。仓库外副本里做的，
  用 os.utime 推进 mtime，清理写在 trap EXIT INT TERM 里。

这个任务两轮整改一共解决 13 条，其中三条是「现在不修以后要动两个任务」的：
  W35（只取第一条 Proxy-Authenticate，代理先列 Basic 就把整个能力旁路掉）、
  W36（next_token 改 Option<Zeroizing<String>>）、
  W45（给 ProxyAuthenticator 加连接边界信号）。

--- 带进后续任务的清单（按任务归口）---
Task 9/10 的派发单必填项：
  - W43：界面显示代理信息时不得调用 Transport::effective_proxy，
    它会在协商途中改写 ProxyEndpointRecorder 且无测试会红。
  - W54：next_token 的第二个调用方出现时，必须先回答「谁来划连接边界」。
    忘了调 begin_connection 的后果比修复前更重（客户端永久废掉）。
  - W38：诊断页「代理认证（SSPI Negotiate）」那一行至今没有任务会画，
    要带上「CONNECT 结果 × last_outcome()」的**完整十格**映射。
  - W55：http_connect 抛的「本机无法协商」与诊断行「是代理不接受当前用户」
    互相矛盾，W45 让这个矛盾从罕见变成最常见的形状。
  - W53：begin_connection 与被取消的连接尝试残留的 spawn_blocking(advance)
    之间没有顺序保证（观察项，概率很低）。
Task 12：
  - W57：UAF 在本机三道防线下不可检测，**四次独立实测**。CI 必须正面回答——
    Windows runner + Application Verifier，或明确放弃并写进文档。
Task 10：
  - W28：%LOCALAPPDATA%\rmc\ 这个落点要一次性给审计日志、known_hosts
    与密码存储三处都接上，别分三次。
  - W37：协商成功后上下文与凭据句柄留到下一次重连，长会话里
    DeleteSecurityContext/FreeCredentialsHandle 数小时不执行（不是泄漏，
    但人工验收「长时间挂着看内存」要按这个事实看）。

下一步：Task 4（DPAPI 记住密码）。说明书在 task-4-brief.md，
  派发前预检 W21-W28 已写在上面。

Task 4（DPAPI 记住密码）已派发，BASE ba69eec。

Task 4: 实现完成 4d1d368（4 文件 +1016），评审已派发（opus，
  评审包 review-ba69eec..4d1d368.diff）。自报 rmc-win 80→102 passed，
  workspace 10 个 test result 全 ok，六道闸门全绿。
  Cargo.lock 我自己核过：**只多 `+ "sha2 0.10.9"` 一行依赖边，零新包**。

实现者主动报的（第四轮延续这个做法）：
  - **C 组三条改什么都不会红**：W23（去掉 LocalFree 前的抹零）、
    W24（退回 plain.to_vec()）、W27（把 input 建进内层块做成真正的
    use-after-scope）——macOS 102 passed、zigbuild rc=0 零告警、
    zig-clippy rc=0 零告警。
  - 它还做了一件前几轮没人做过的事：**区分「真检测」与「巧合告警」**。
    M14 那条 clippy 看着像抓到了 W23，它发现抓的其实是
    `unused import: Zeroize`，于是做对照实验——让 import 仍被别处用到
    再去掉抹零，clippy rc=0 零告警。
  - **D 组证明两条 Windows 闸门确实在编译 win 模块**（塞一句
    assert!(1==2) 进去，zigbuild rc=101 error[E0080]），
    所以「盲」是真盲，不是「压根没编」。这一步补上了前五次实测缺的一环。

Ruling W58（待评审核实后落定）：实现者**偏离了 brief 写死的 trait 签名**
  并主动报备——SecretStore 多了 load_outcome，load 变成由它派生的默认实现。
  这正是 W21 要的「另开一个带类型的出口」，方向对。
  Task 10 接线时要按新签名来，写进 Task 10 的派发单。

Ruling W59（实现者发现 brief 的一个真 bug，与 rmc-core 同形状）：
  brief 的 tmpdir() 只用纳秒做目录名，macOS 上 SystemTime 粒度到不了纳秒
  + 测试并行 ⇒ 多条测试共用一个目录、都用 "k"。**实测 60 轮 34 轮失败**，
  而且它第一版变异表被这个污染过一次。已修（加进程内自增序号 + pid），
  修后 60 轮 0 失败。
  rmc-core 踩过一模一样的坑：tests/common/mod.rs 的 tmp_known_hosts 用
  纳秒时间戳，两条测试撞同一纳秒、读到别的用例写的指纹，
  报出不相关的 HostKeyMismatch（R96 第 3 条修的就是它）。
  **这类 flake 混进 CI 教出来的习惯是「重跑一次就好了」**，
  比它本身的直接危害大得多。评审要独立复跑验证。

=== Task 4 评审结论：通过（W21-W27 七条全部 ✅）===
评审做了 35 次变异，报告的 A/B/C/D 四组全部重做，**一格不实都没有**，
  另加 11 条自己的探针。六道闸门全部复跑，其中 clippy 与两条 zigbuild
  在**全新 CARGO_TARGET_DIR** 里从零编译（workspace clippy 35 个 crate、
  windows 目标 168 个 crate）以排除缓存假绿——全部 rc=0、零告警。
  Cargo.lock 复核：整份 diff 只有一个 hunk、只有 `+ "sha2 0.10.9",` 一行。

三条本机全盲、只能靠人读的，评审逐行读下来都是对的：
  - **W23**：`slice::from_raw_parts_mut(ptr,n).zeroize()` 走的是 zeroize crate
    对 &mut [u8] 的实现（volatile_write + compiler_fence，优化不掉），
    不是 ptr::write_bytes 也不是 for 循环赋 0。位置在 LocalFree 之前、
    拷贝之后。与 Task 3 take_token 逐行同形。
  - **W24**：`std::str::from_utf8(&plain)` 只借用；Err 分支的 Utf8Error
    **只携带 valid_up_to/error_len 两个下标、不持有字节**。
    brief 原写法那两个问题（多一份拷贝 + FromUtf8Error 持字节且不清零）
    都消除了。
  - **W27 四个指针逐个验过**，评审对着 windows 0.62.2 的真实签名核的：
    input.pbData 指向函数参数（借用检查保证覆盖调用点）；
    &input 是**函数作用域**的 let、逐字确认不在任何内层块里
    （这正是与 Task 3 W34 那个缺陷的分界）；
    &mut out 同理，且 `CRYPT_INTEGER_BLOB::default()` 在 0.62.2 里是
    `unsafe { mem::zeroed() }` 不是 derive，所以「初始化成 NULL」成立；
    out.pbData 释放后只写自己栈上的字段、ptr 是释放前取的本地副本、
    每条路径只调一次 take_blob。
    评审还顺手核了两件决定需求成败的事：CryptUnprotectData 第二参传 None
    所以不存在第二块要 LocalFree 的内存；**seal/unseal 两路 entropy 对称**
    （不对称会导致解不开）；`dwflags = 0` 无 CRYPTPROTECT_LOCAL_MACHINE，
    密文确实绑定当前 Windows 账号。

W58 落定（**偏离 brief 的 trait 签名是对的**）：评审判这个形状比「并列两个方法」
  更强——load 由 load_outcome 派生，**结构上不可能与它漂移**。
  实测 M17（给 FileSecretStore 单独覆写一个 load 返回 None）6 条红。
  Task 10 接线按新签名来。

W59 落定（**flake 属实**）：评审独立复跑——HEAD 上 60 轮 0 失败；
  换回 brief 原样的 tmpdir() 后 60 轮 **23 轮失败**（与自报的 34/60 同量级，
  轮次数看机器负载）。失败的测试每轮都不同，正是多条测试共用一个目录、
  又都用 "k" 这个 key 互相踩的特征签名。实现者自曝「第一版变异表被这个
  污染过一次」评审也验了属实。

评审量出了 W22 那条测试的**边界**（这段比「做到了」本身有用）：
  真正做功的是三条显式前置，子串断言在 FlipSealer 下不做功（取反后本来
  就不出现明文）。**P8 是关键的那一枪**——save 与 load 两侧同时绕过 sealer，
  round_trips_a_secret 在 P8 下是绿的，只有这条测试把它揪出来（5 红，
  红在 assert_ne! 上）。抓不到的是写到 dir **之外**（P1，102 全绿），
  这是天然边界不是缺陷。本来就证不了的是「DPAPI 真的密封了」——
  DpapiSealer 一次都没执行过，只能靠 Windows 人工验收。

**两层划分这次守住了，而且守得比前两个任务好**：win 模块只有 65 行非注释代码，
  **分类逻辑一格都没落在 Win32 侧**——Sealer 只返回 Option，
  「解不开→UnsealFailed」「不是 UTF-8→NotUtf8」「文件不在→NotRemembered」
  全在纯层的 load_outcome 里，四条都有 macOS 上真跑的测试（M7/M7b/M8/M9）。
  与 Task 2 的 autoproxy_flags/dwAccessType、Task 3 的 imp.rs 35 行状态分类块
  正好相反。

--- 裁决 ---

Ruling W60（中低，本轮修，**这是 W21 标准在另一侧的漏格**）：
  `load_agrees_with_load_outcome_in_all_five_situations`（secret.rs:881）
  **名不副实**——名字说五格，循环实际只走 NotRemembered 与 Loaded 两格
  （`["nope","k"] × [&miss, &ok]`），Unreadable 与 NotUtf8 没进去。
  评审实测 M21：把 into_secret 改成 `Unreadable(detail) => Some(Zeroizing::new(detail))`
  ——**把 io::Error 的说明文字当口令填进密码框，用户会拿这段文字去登录**
  ——**102 全绿**。
  W21 要的「每一格都有身份测试」在 diagnostic 一侧做满了，在 load 一侧没有。
  修法是纯搬运：改成跑那张已有的定长表（LoadOutcome::VARIANTS 的长度
  已被编译器钉住），每格多断一句
  `into_secret().is_some() == matches!(_, Loaded(_))`。

Ruling W61（低，本轮修）：`clear` 的「两步都走完再报第一个错」没有测试。
  `sealed.and(tmp)` 的语义评审读过是对的，但实测 P2（改成第一步 `?` 早退）
  **102 全绿**。这正是 W25 要堵的另一半——`.sealed` 删失败时 `.tmp`
  就留在盘上了，而用户点的是「不再记住密码」。

Ruling W62（低，本轮修）：`Unreadable` 携带的原因没被钉住。
  实测 M20：`Unreadable(e.to_string())` → `Unreadable(String::new())`，
  诊断行里的原因整段消失，**102 全绿**。表里用的是字面量
  `Unreadable("权限不足".into())`，只测了 format! 模板，
  没测真实的 io::Error 说明有没有接上。

Ruling W63（不修，记录边界）：W22 那条测试看不到 dir **之外**的写入
  （P1 实测 102 全绿）。不是缺陷，是这条测试的边界。
  记下来是为了将来别把它当成「明文从不落盘」的全称证明。

Ruling W64（不修，记账，等第三份出现再提）：declare_load_outcome! 是
  sspi.rs:559 那个宏的第二份拷贝，评审对读过、除少一条 struct-variant arm
  外逐行同构。共用要动 Task 3 已收口的模块、且要新开一个宏模块，
  收益是删 40 行。**等第三份出现时一次性提出去。**

Ruling W65（不修，既有惯例）：测试目录不自清理（评审这一轮约 130 次
  cargo test 攒了 3470 个 rmc-secret-* 目录，已清）。不加 Drop 守卫的理由
  （守卫提前 drop、失败时保留现场）站得住，泄漏的只是 0600/0755 下的假口令。
  rmc-core 的 R98 已经把同一条记为「不修」。

Ruling W66（携带进 Task 10）：
  - `%LOCALAPPDATA%\rmc` 的落点仍悬着——审计日志、known_hosts、密码存储
    三处各自等着 Task 10 给落点（W28 / rmc-core R97 同一条未了账）。
  - 在那里补一条裁决：**目录预先存在且权限过宽时怎么办**。
    现在 `create_dir_all_hardened` 用 recursive(true)，对已存在的目录
    直接 Ok(())、不碰权限（代码注释写明是有意的），但那条路径没有测试。
  - `save(&self, key, secret: &str)` 让口令以 &str 穿过 trait 边界
    （brief 写死的签名，调用方持 Zeroizing<String> 时 `&*z` 不产生新拷贝，
    不违反约束）。接线时别在这一步落一个临时 String。
  - FileSecretStore 无并发保护：同一 key 的两次并发 save 在 {hex}.tmp 上
    撞车，冲突方拿到 AlreadyExists 而非静默损坏，所以不是数据风险。
    single_instance 模块兜着。

Ruling W67（携带进 Task 12）：task-4-report.md 第 6 节那 5 条 Windows
  人工验收写得比 brief 那句「密码框应自动填上」强得多，
  尤其第 2 条要求诊断页显示 UnsealFailed 那句话而不是只给一个空框——
  **那正是 W21 存在的理由**。原样并进 Task 12 的验收清单。

Task 4: 修复轮 1/5 已派发（W60、W61、W62 三条，全是补测试，不动实现）。

Task 4 修复轮 1：实现者交回 8ca9d0c（只动 secret.rs，+207/−23，一行实现没动）。
  自报 rmc-win 102→104、workspace 360 通过 / 0 失败 / 17 ignored，六道闸门全绿。
  三枪裁决点名的变异（M21/P2/M20）在 4d1d368 上原本都是 102 全绿，现在各红 1 条，
  且红的就是本轮新补的那条。加第六个变体现在会让**两张**定长表同时 E0308。
  secret 连跑 30 轮 0 失败、全 crate 另跑 10 轮 0 失败。
  定向复审已派发（opus，评审包 review-4d1d368..8ca9d0c.diff）。

**它自曝了本轮最有价值的一条：差点自己制造第 20 个空转测试。**
  W61 第一版只挡 `.sealed` 一个方向，而**镜像早退**（先删 .tmp、? 早退）
  实测 24 全绿——那是同一缺陷的另一半。补成两个方向后三枪才都红。
  这正是我在派发里点名警告的那个风险（「补的正是三个假绿缺口，
  补出来的如果自己也空转，那是第 20 个」），它自己撞上了并自己抓住了。

它自己最不放心的一条（交复审重点判）：W61 那条测试依赖
  「remove_file 冲着一个**目录**调用返回的不是 NotFound」。
  Windows 那一半是它**逐行读 std 的 sys/fs/windows.rs 断出来的**——
  unlink 的只读兜底没带 FILE_FLAG_BACKUP_SEMANTICS，CreateFileW 打不开目录，
  于是原样报 ACCESS_DENIED。两条 zigbuild 只证明编译过、没证明运行时行为。
  它的方向断言是「假设若失效，会在 Windows CI 上**变红而不是静默跳过**」——
  这一点最要紧：一条会假红的测试可以修，一条会静默跳过的测试等于没有。
  它还说同一假设 a_record_that_cannot_be_read_... 与 a_failed_rename_...
  已经在用，若属实则是这个文件的既有依赖而非本轮新引入的风险。

它报的设计顾虑（待裁）：W60 那张表用 Box<dyn SecretStore> 把五种现场装进
  定长数组，将来若加一个只能由 Win32 路径产生的变体，这里会被迫写一个**假 store**。
  它给的处置是「那时拆表，别为了让它编译过而塞一个空转的格子」。

它自报「改不红也不打算堵」四条：sealed.and(tmp) → tmp.and(sealed)（报的是
  哪个错没钉住）、两句删除顺序对调、path_for 的 .take(16) → .take(4)
  （文件名哈希长度全无守护，是 Task 4 原有边界）、DPAPI 本身仍然一枪打不到
  （W63/W66 两条空白原样还在）。

=== Task 4 修复轮 1 的定向复审：三条全 ✅，判可以收口 ===
「只补测试」这条硬要求复审以**前 493 行逐字节相同**为证（测试模块起于 494 行，
  四个 diff hunk 全部落在其后）；Cargo.lock diff 0 行。
六道闸门在**仓库外净副本**（git archive 展开、与工作树逐字节一致）、
  **每道一个全新 CARGO_TARGET_DIR** 里从零跑一遍——全部 rc=0、零告警零杂音。
  flake：净副本里 secret 连跑 35 轮 0 失败、全 crate 15 轮 0 失败，
  另加 6 进程 × 6 轮 = 36 次并发 0 失败。

**W61 的 Windows 假设复审读了本机 1.89 的 std 真实源码坐实了**（装了 rust-src）：
  调用链 fs.rs:2466 → sys/fs/mod.rs:59 → sys/fs/windows.rs:1220 unlink；
  只读兜底只有 FILE_FLAG_OPEN_REPARSE_POINT、**确实没有 BACKUP_SEMANTICS**，
  CreateFileW 打不开目录 → posix_delete 没机会跑 → 原样 ACCESS_DENIED。
  复审补了一条实现者没提、但更有力的旁证：**紧挨着的 rename（:1243）
  同一套兜底是带 FILE_FLAG_BACKUP_SEMANTICS 的**——unlink 少这一位
  不是疏漏式巧合，是两处刻意不同。它还比了 1.90.0 与当前 stable 1.95.0，
  三份 std 的 unlink 兜底都一样。
  **方向断言对，而且是三重红**：假设失效只有两条路（std 加了 BACKUP_SEMANTICS
  让删除成功 → 第一句与第三句都红；或 remove_file(目录) 返回 NotFound
  → 被 remove_if_present 吞成 Ok → 第一句红）。没有任何路径通向静默跳过。
  复审还 **strings 扫了 zigbuild 出来的 windows-gnu 测试 exe**，
  确认这三条测试都在符号表里、而 #[cfg(unix)] 那条不在——真会在 Windows 上注册。

**订正实现者报告的一句**：它说「同一假设 a_record_that_cannot_be_read_...
  与 a_failed_rename_... 已经在用」——略微夸大。已有那两条依赖的是
  **别的 Win32 调用**（fs::read → CreateFileW；rename → MoveFileExW）。
  本轮这条是该文件里**第一条**依赖 remove_file/DeleteFileW + posix_delete
  兜底的。同一类假设（Windows 的文件 API 不肯把目录当文件），不是同一个假设。
  风险方向不变（都是红而非跳过），只是记账精度问题。

复审量了新表**每一句断言各自的检测力**（这一层前几轮没人做过）：
  - variant_name 身份句：M22/M23/M24 都红在它，做功。
  - `load(key).is_some() == is_loaded`：M21 与 M17 都红在它，做功。
  - `into_secret().is_some() == is_loaded`：前 10 枪一次没轮到它先炸，
    看着像冗余。复审**专门造了一枪验**——M21 + 给 FileSecretStore 补一个
    「正确的」load 覆写（只留 into_secret 坏着）→ 红，且**唯一红在它**。
    有独占检测力，不是凑数。
  - `assert_eq!(is_loaded, *want_variant == "Loaded")`：**是重言**，
    在前一句通过的前提下不可能独立失败（variant_name 由 stringify! 生成、
    与变体一一对应）。零检测力零风险，纯噪声，不值得改。

Ruling W68（复审修正了实现者的处置，我采纳复审的）：疑虑 3（将来加一个
  只能由 Win32 产生的变体时 W60 那张表会被迫写假 store）**成立一半**。
  假 store 在这张表里**并不是完全空转**——`load().is_some()` 与
  `into_secret().is_some()` 照样在真跑 into_secret 对新变体的处理，
  而那恰是这条测试名字声称的事。丢掉的只是「这一格真由生产路径产生」那半边，
  而对只能由 Win32 产生的变体，那半边在 macOS 上本来就证不了。
  **正确做法：格子照留（它守 into_secret），但别把它当分类证据，
  分类那半边写进 Windows 人工验收。** 「拆表」也行，但不是唯一解。

Ruling W69（我自己做掉了，commit 6750df9）：复审建议「path_for 哈希长度
  随 Task 10 顺手补」——只要两行，现在做掉不带走。
  `different_keys_do_not_collide` 只用两个 key，挡不住哈希被截短
  （复审实测 `.take(16)` → `.take(4)` 24 条全绿）。而截短的后果不是
  「文件名难看」：两个 key 撞同一个文件名 = **A 运维服务器的口令被填进
  B 的密码框**。造碰撞太做作，钉长度不做作。
  我自己复跑变异：`left: 8, right: 32` 当场红，只红这一条、无误伤。

Ruling W70（记账，跨平台 CI 会自己堵上）：W62 有个自封闭边界——
  把实现硬编码成字面量 `Unreadable("Is a directory (os error 21)")`，
  macOS 上 24 全绿。但同一段硬编码在 Windows CI 上**必然变红**
  （那里的说明文字不同）。不必补测试。

Ruling W71（携带进 Task 12 的验收清单旁注）：把「remove_file(目录) 在
  Windows 上返回 ACCESS_DENIED 而非 NotFound」这条依赖写明，
  免得将来 std 改了之后有人误以为是测试写坏了。

Ruling W72（方法学，写进后续每一次派发）：复审报告了一条它自己踩到的坑——
  **跨 commit 做变异时，基线副本与 HEAD 副本共用同一个 CARGO_TARGET_DIR
  会串味**（它第一次基线跑出「104 tests / 7 failed」，换独立 target 后
  基线是干净的 102 全绿）。一 commit 一个 target 目录。
  这条与 W39（sed -i.bak 让 mtime 退回）是同一族的工具链陷阱。

=== Task 4: complete ===
提交链：4d1d368（实现）→ 8ca9d0c（修复轮 1，三条补测试）→ 6750df9（收口一条，我做的）。
最终状态：rmc-win **105 passed**，workspace 十个测试目标全 ok / 0 failed / 17 ignored，
  clippy --workspace -D warnings、fmt --check、两条 zigbuild——六道全绿零告警。
  Cargo.lock 只多 `+ "sha2 0.10.9"` 一行依赖边、零新包。

下一步：Task 5（电源与网络事件）。

=== Task 5 派发前预检（我自己读 brief 做的，编号接 W72）===

**最要紧的一条先说：brief 违反的那条约定，lib.rs 的模块文档里点名的反例
字面就是它。** lib.rs:34-36 写着「不要把纯逻辑（例如**某个防抖计时器该不该
触发**、某个图标该画哪个像素）也关进 #[cfg(windows)] 里——那样它就只能靠
人工验收清单守」。而 brief 的 `Debouncer` 恰恰整个建在 `#[cfg(windows)] mod win`
里面。这是同一个坑的**第四次**（Task 2 的 autoproxy_flags、dwAccessType，
Task 3 的 imp.rs 状态分类块，现在是它）。

W73（必修）：`Debouncer` 整体上移到纯逻辑层。它有真判断
  （窗口内→false；否则更新时间戳并→true），而现在它在 macOS 上一行都不编译。

W74（必修）：`Debouncer::allow()` 内部调 `Instant::now()`，所以即使上移也测不了。
  改成把时刻当参数传进来。**注意一个已经踩过的坑**：tokio 的 start_paused
  控制的是 `tokio::time::Instant`，管不着 `std::time::Instant`——
  rmc-core 的 R92 在 SystemTime 上学过这一课，当时的解法是「对私有函数写单元
  测试、把时刻显式喂进去」，照那个办。

W75（必修，**第三次**）：`Debouncer::allow` 里的 `lock().unwrap()`。
  W20.2 已经在 winhttp.rs 与 sspi.rs 修过两处，理由是「中毒时 Drop 自己 panic，
  unwinding 中则 abort」。这里更重：**这把锁是在 `extern "system"` 的回调里取的**
  ——panic 跨过 FFI 边界是 UB（现代 Rust 会 abort），也就是说一次锁中毒
  会让整个客户端进程死掉。用 `unwrap_or_else(|e| e.into_inner())`，
  并且整个回调体要保证 panic-free（或包 catch_unwind）。

W76（必修）：`let _ = HUB.set(hub); let _ = DEBOUNCE.set(Debouncer::new());`
  ——`OnceLock::set` 在已设置时返回 Err，这里被 `let _` 吞掉。
  若 spawn_win32_listeners 被调用两次（Task 10 接线、或将来加一个「重新注册」
  的路径），第二个 hub 被**静默丢弃**，事件全发给第一个 hub，
  界面上表现为「唤醒后没反应」而日志里一个字都没有。
  而且两个独立的 OnceLock 让「HUB 设了、DEBOUNCE 没设」这种半截状态在类型上
  可表达（回调里那句 `if let (Some(hub), Some(d))` 正是在兜它）。合成一个。

W77（必修，先核实再动手）：`std::mem::forget(handle)` 配的注释是
  「句柄随进程存活，故意不注销」。**先查 windows 0.62 里 `HPOWERNOTIFY`
  到底有没有 Drop 实现**——如果没有（很可能没有，这类句柄通常是裸 newtype），
  那 mem::forget 是个空操作，注释在骗下一个读代码的人。
  要么删掉 forget 并把注释改成实话，要么说明为什么需要它。

W78（必修，先想清楚再动手）：`loop { std::thread::park(); }`。
  `PowerRegisterSuspendResumeNotification` 用 DEVICE_NOTIFY_CALLBACK 注册时
  **不需要消息循环**（回调由系统线程调用），而 hub 已经进了 static。
  所以这个线程为什么必须永远活着？如果没有理由，让它退出——
  一个永久 park 的线程是没有用途的泄漏。如果有理由（比如某些 Windows 版本
  要求注册线程存活），**把理由写进注释**，别留一句 park 让人猜。

W79（必修）：`register_network` 里那句
  `previous.map(|p| p.0 != current.0).unwrap_or(false)` 同样是纯判断
  （**首次观测不许发事件**——这条语义很重要，第一次读到连通性不等于网络变了），
  和 Debouncer 一起上移，配表驱动测试。

W80（必修，是 W73 的后果）：**防抖行为本身零覆盖。** brief 里唯一跟防抖有关的
  测试是 `assert!((300..=1000).contains(&debounce_ms()))`——钉的是一个区间、
  不是一个行为。「窗口内两次事件只发一次」这件事**没有任何测试**。
  W73/W74 落地后补上，并且要变异验证：把 allow() 改成恒返回 true 必须变红。

W81（本轮修，质量项）：`late_subscriber_does_not_see_earlier_events` 烧 200ms
  真实时间等一个 timeout。`try_recv()` 立刻返回 `Empty`，严格更好。
  （方向本来是对的——迟到订阅者若真收到历史事件，recv 会立刻返回、
  timeout 不 err、测试变红——所以这是质量项不是正确性项。）

W82（范围外，记进 Task 10）：rmc-core 的 Supervisor 在 select 里写的是
  `Ok(event) = sys.recv() => {...}`。broadcast 的 `Err(Lagged)` 与 `Err(Closed)`
  都不匹配这个模式，于是被**静默跳过、零日志**。
  后果：EventHub 若被 drop（sender 没了），系统事件从此永久停摆，
  「唤醒后立刻重连」静默退化成「等满退避」，而没有任何地方会说一句。
  不是本任务的 diff，但 Task 10 接线时要保证 hub 的生命周期覆盖 Supervisor，
  并考虑给 Closed 补一条 warn。

W83（提醒）：`register_network` 那个 2 秒轮询循环**没有任何停止方式**，
  进程在跑它就在跑。brief 用轮询换掉 COM 事件是为了压 unsafe 面积，
  这个取舍本身合理（写进注释了），但要知道代价：笔记本上一个永不停歇的
  2 秒定时唤醒。Task 10 接线时评估要不要给它一个关闭通道。

Task 5: 实现完成 47d8460（events.rs 840 行 + lib.rs 一行），状态 DONE_WITH_CONCERNS。
  自报 rmc-win 105→125（净增 20），workspace 381 通过 / 17 ignored，六道闸门全绿。
  评审已派发（opus，评审包 review-6750df9..47d8460.diff）。

**订正我自己的一个数**：我在派发里写「闸门 2 基线 360 通过」，实现者在 6750df9 上
  开独立 worktree + 独立 CARGO_TARGET_DIR 实测是 **361 / 17**，它是对的。
  360 是 8ca9d0c 的数，而 Task 5 的基线是 6750df9——我自己加的那条哈希长度
  测试（W69）让它变成 361。已在派发给评审时纠正。

**第 20 个假绿形态出现了，而且形态是新的：不是绿，是永不结束。**
  实现者自报：`emit` 变空操作时，两条 `rx.recv().await` 的测试**不是变红，
  是永久挂死**（第一次跑 M12 吊了 300 秒，手工 pkill 才停）。
  已改成 recv_soon() 包 timeout，重跑 M12 是 `2 failed, 5.00s`。
  它自己的评价是「说明我第一版的测试自己就没经受住这个项目的纪律」。
  **前 19 个都是「该红却绿」，这一个是「该红却挂」**——从变异验证的角度，
  挂死比假绿更隐蔽：跑变异的人看到进度条不动，很容易当成机器慢。
  写进后续每一次派发：**变异验证要给 cargo test 加超时。**

实现者自报的其它：
  - **brief 的 Step 3 代码按原样抄进去编译不过**，不止 W77 一处：
    DEVICE_NOTIFY_CALLBACK 与 PBT_APMRESUMEAUTOMATIC 都不在 brief 写的模块里
    （它说在 Win32::UI::WindowsAndMessaging）、`let mut handle = Default::default()`
    推不出类型（裸指针没有 Default）、mem::forget 会触发 forgetting_copy_types
    让闸门 6 直接红。**如果属实，说明 brief 的 Win32 部分从来没被编译器看过一眼。**
  - 连带发现：Cargo.toml 里 W6 预留的 `Win32_System_SystemServices` feature
    本任务**一个符号都没用上**，那条注释的落点是错的。按要求没改 Cargo.toml。
  - W73 只做到「本任务」这一层：win 子模块里仍有五件事零自动化覆盖
    （catch_unwind 是否真接得住、W76 的「第二次注册记 warn 并跳过」、
    Box::leak 的参数结构体是否真被系统读到、线程退出后回调是否照常被叫、
    NLM 轮询是否真读得到变化）。列成了人工验收清单。
    **W76 是它唯一想不出办法搬进纯逻辑层的一条**——OnceLock 是进程级 static，
    为它造抽象它判断是过度设计，但这意味着那条修复本身没被任何测试守住。
  - 三个数值没被守住：broadcast 容量 16（改成 1 全绿）、debounce_ms() 的 800、
    POLL_INTERVAL 的 2 秒（后两个只有区间测试，改成 500ms / 4s 全绿）。

=== Task 5 评审结论：不通过，需要一轮很短的修复 ===
六道闸门评审全部在仓库外净副本复跑（clippy 与两条 zigbuild 用全新 CARGO_TARGET_DIR
  从零编译）：125 / 381+17 / 全绿零告警。基线 6750df9 实测 105 与 **361/17**——
  **实现者对我那个数的订正成立**。Cargo.lock diff 0 行。30 轮连跑 0 失败。
  变异表重做 **14 条自报 + 11 条自己的探针，一格不实都没有**。

做得最好的一条（评审原话「我这几轮见过最扎实的查证」）——**W77**：
  实现者不但查出 HPOWERNOTIFY 没有 Drop（windows-0.62.2 全 crate
  `impl Drop for HPOWERNOTIFY` 零命中，它只实现 windows_core::Free，
  而 Free 只在 `impl<T: Free> Drop for Owned<T>` 里被调），
  **还查出 PowerRegisterSuspendResumeNotification 的出参根本不是 HPOWERNOTIFY**
  （是 `*mut *mut c_void`）；而且它对闸门后果的落点**精确到了哪一道**——
  mem::forget 在闸门 5 只是 warning（rc=0）、在闸门 6 才是 error（rc=101）。
  评审自己查源码逐条复核，全对。
  **评审还补了一条更狠的**：HPOWERNOTIFY::free 调的是
  UnregisterPowerSettingNotification，跟 suspend/resume 订阅根本不是一回事——
  就算有人将来想用 windows_core::Owned<HPOWERNOTIFY> 来「正确地」管这个句柄，
  那也是错的，会去注销一个不存在的 power-setting 订阅。

**第 20 个假绿形态评审两头都复现了**：现在的版本下 emit 空操作是
  `18 passed; 2 failed; 5.01s`（是红不是挂）；把 recv_soon 的 timeout 拆掉
  再叠加 emit 空操作，**75 秒硬超时被杀（exit=124）**；单独换回裸 recv()
  不改 emit 是 20 passed——**所以吊死是这两者的组合，recv_soon 就是那道分界**。
  超时值 5 秒判为合理：happy path 值已在环里、零实际耗时，
  失败路径两条并发共 5s，对 CI 负载有极大余量不会假红。

**「哪些测试钉的是 tokio」这份区分评审判为诚实且准确**，并逐条验了独占检测力：
  two_subscribers_both_receive 与 late_subscriber_... 都找不到任何一行实现改动
  能单独让它红（PSUB 会红但同时红掉三条，无独占检测力）。
  评审另找到一条实现者没提的：**PDUP（emit 里把 send 写两遍）20 passed 全绿**
  ——「emit 发且只发一条」没有任何测试。

--- 裁决 ---

Ruling W84（中高，本轮修，**这是不通过的唯一原因**）：
  **电源那一路的「闸」压根没搬。** 网络那一路拿到了 ConnectivityWatcher::observe
  （= is_change && debounce），电源那一路的同构判断
  （is_resume_event(event_type) && debounce.allow_at(now)）**整个留在
  events.rs:387-395**。评审两枪实测、六道闸门全绿：
  - **PW1**（把 `if !super::is_resume_event(event_type)` 的 `!` 去掉）：后果是
    **真唤醒（18）时提前返回什么都不发，而「即将休眠」（4）和
    PBT_POWERSETTINGCHANGE（32787）反而各发一条 ResumedFromSleep**
    ——**正好是本任务需求的反面**，而六道闸门一个字都不会说。
  - **PW2b**（把防抖门的结果丢掉改成 if true，保留字段读取以避开 dead-code lint）：
    六道全绿。（不保留读取的 PW2 会被 `field is never read` 抓到，
    但那是 Task 4 说的「巧合告警」，不是检测。）
  补法是纯搬运、六行：`PowerGate::on_event(&self, event_type: u32, now: Instant) -> bool`
  放进纯逻辑层，回调退化成 `if state.gate.on_event(event_type, Instant::now()) { emit }`。
  形状与已有的 ConnectivityWatcher::observe 一模一样——**网络那一路已经示范了
  正确形状，照抄一遍即可**。

Ruling W85（中低，本轮修，**评审驳回了实现者的取舍，我采纳评审的**）：
  实现者说 W76 那条修复「OnceLock 是进程级 static，造抽象是过度设计」，
  所以零覆盖。**这个理由不成立**——评审指出：格子可以**当参数传**，
  这正是 W74 对 Instant 用过的同一招。把 PowerCallbackState（它只装
  Arc<EventHub> + Debouncer，两个纯类型）和
  `fn install(cell: &OnceLock<PowerCallbackState>, hub: Arc<EventHub>) -> bool`
  搬到纯层，win 传 `&POWER` 进去；测试自己 new 一个本地 OnceLock、install 两次，
  断言 true/false 且格子里仍是第一个 hub（emit + recv_soon 验证）。
  不需要任何 mock，macOS 上真跑，成本是移动一个 struct 加六行。
  评审实测 PW3（`.is_err()` → `.is_ok()`，语义正好翻成「第一次注册跳过、
  第二次才注册」，休眠恢复整个不工作）**六道全绿**。

Ruling W86（中低，本轮修，**W76 的修复自己引进的新半截状态**）：
  `POWER.set(...)` 在 events.rs:425 执行，Win32 注册在 events.rs:453 才执行。
  注册失败（`.ok()?`）时格子**已经被占住**，将来任何重试都会走进
  「已经注册过，本次跳过」并**返回 Ok(())**——功能永久关闭却报成功。
  今天没有重试路径所以是潜在的，但它**正好是 W76 想堵的那个形状的镜像**。
  修法：把 set 挪到 `.ok()?` 之后，或把失败时格子的语义写清楚。

Ruling W87（低，本轮顺手）：`emit` 发且只发一条没有测试（PDUP 全绿）。

Ruling W88（低，本轮顺手，**评审驳回了实现者的推理**）：broadcast 容量 16
  改成 1 全绿。实现者说「要测得有意义就得构造慢订阅者」——评审判这个推理
  **只对「测容量的行为后果」成立，对「钉住这个数不被随手改小」不成立**。
  照 POLL_INTERVAL / debounce_ms 已有的形状，抽一个
  `pub const EVENT_CHANNEL_CAPACITY: usize = 16;` 再钉一条区间（如 >= 8），
  成本两行。

Ruling W89（低，本轮顺手）：W75 的「不归本模块管的代码」那一段
  **漏列了 tracing::info!**（events.rs:392）——它是回调里最现实的外部 panic 源，
  而这个项目在 Task 3 的 W56 刚刚认定过同一件事。结论不变
  （正因如此两道防线是对的），但理由写漏了一条。

Ruling W90（记录，**实现者报告里唯一一处硬伤**）：报告 §3 那句
  「`let mut handle = Default::default()` 推不出类型：裸指针没有 Default」
  **两半都不对**。评审两头验了：把 HEAD 的
  `let mut registration: *mut c_void = null_mut()` 换成 `Default::default()`，
  闸门 5/6 都 rc=0；独立 rustc 小程序确认 `*mut c_void` 确实实现 Default（返回 null），
  且从 `&mut handle` 的实参位置能推出类型。
  不影响任何裁决（brief 的 Win32 部分确实没被编译器看过，另外三条属实）。

Ruling W91（记录）：实现者漏了 brief 的**第四条**编译错误——
  `&params as *const _ as *const _` 与真实签名的 `recipient: HANDLE` 不符（E0308）。
  这是 brief 里除模块路径之外**唯一的真类型错误**。

**brief 的 Win32 部分确实一眼都没被编译器看过**，评审把 Step 3 原样贴进去跑
  windows-gnu 编译，拿到 E0432 × 2 + E0308。三条属实：
  DEVICE_NOTIFY_CALLBACK 全 crate 唯一定义在 WindowsAndMessaging/mod.rs:3073；
  PBT_APMRESUMEAUTOMATIC 在 WindowsAndMessaging/mod.rs:5412、
  SystemServices 里 grep PBT_ 零命中；mem::forget 的 lint 落点精确。

Ruling W92（记录，低）：poison_for_test（events.rs:188-198）动的是**进程全局的
  panic hook**。测试并行执行时有一个几微秒的窗口，期间另一条真失败的测试的
  panic 信息会被那个空 hook 吞掉（失败本身仍会报，只是没有消息）。
  全 crate 只有这一处动 hook，风险极小。

Ruling W93（携带进 Task 10，顺手做掉不带走）：Cargo.toml:35 的
  `Win32_System_SystemServices` feature 与它上面那条 W6 注释**都是错的**
  ——符号在 Win32_UI_WindowsAndMessaging，而那个 feature 本来就开着。
  全仓库 grep SystemServices 唯一命中就是那一行 feature 本身。删掉。

Ruling W94（携带进 Task 10，与 W82 同一笔账的两头）：Task 5 的 broadcast
  容量 16 与 supervisor.rs:1110 的 `Ok(event) = sys.recv()` 是一笔账的两头——
  **容量若被改小，退化正好表现为 Lagged，而 Supervisor 那边零日志**。
  两条一起在 Task 10 处理。

Task 5: 修复轮 1/5 已派发（W84-W89 六条）。

=== 用户指示：当前任务完成后暂停，等其消息再开始 ===
我对「当前任务」取的是 **Task 5 整体**（修复轮 + 定向复审 + 收口），不是只到
  修复轮落地为止。理由：一个未经复审的修复轮是最差的停手点——这条流水线的
  全部价值就在复审，而 Task 5 的修复轮里有 W84 那条「需求被整个反过来、
  六道闸门一个字不说」的补救，它尤其需要被独立验一遍。
  复审这一步无论如何都要做，现在做不浪费。
停手边界：**Task 5 收口之后、Task 6 派发之前**。
  若复审判「还需一轮」，**也停**，把结论报给用户，不自行开第二轮。

Task 5 修复轮：第一次跑被 API 连接中断（ECONNRESET）打断，死在准备变异验证那一步。
  HEAD 仍是 47d8460、**零提交**，但改动都在工作树里（events.rs +367/−32）：
  PowerGate、on_event、install、EVENT_CHANNEL_CAPACITY 与配套测试都已落地，
  报告文件未写、变异一条没跑。已把同一个 agent 叫回来接着干（改动原样保留）。

**署名行变更**：从此只加 `Co-Authored-By: Claude Opus 5 (1M context)`，
  不再加 `Claude-Session:` 行。

=== Task 5 修复轮 1 已完成（W84–W89 六条）===
只动 crates/rmc-win/src/events.rs（+555/-85）与两份报告。六道闸门全绿：
  125 → **136**（rmc-win）、381/17 → **392 通过 / 17 ignored**（workspace）。
  Cargo.lock diff 0 行，Cargo.toml 未动。完整报告：task-5-fix-1-report.md。

W84：`PowerGate::on_event(event_type, now)` 进纯层，形状同
  `ConnectivityWatcher::observe`（含两个门的串联顺序）。回调体里一条判断
  都不剩。PW1 实测 7 红、PW2b 2 红、自补的 PW2c（顺序调换）3 红。
W85：`PowerCallbackState` + `install(cell, hub)` 进纯层，格子当参数传。
  PW3 实测 5 红。
W86：**做得比裁决要求的多一层**——只挪 `set` 的位置的话，那个顺序仍然整个
  在 `#[cfg(windows)]` 里、一行测不到，等于用 W84 犯过的错去修 W86。所以把
  顺序本身也搬进纯层：`register_once(cell, hub, register)`，`register` 当
  参数收。自补的 W86ORD（还原上一轮顺序）1 红、W86SKIP 1 红。
  明知的代价写进了文档：注册生效到占格子之间几微秒的窗口会丢一次唤醒，
  退避兜底；比「此后永远不重连」轻。
W87：PDUP 2 红。W89：`tracing::info!` 已补进 W75 那段（用户装的 subscriber
  才是回调里最现实的外部 panic 源，同 Task 3 的 W56）。

W88 **没按裁决给的形状写，理由是实测发现那个形状是假的**：
  `#[test] assert!(EVENT_CHANNEL_CAPACITY >= 8)` 被 clippy 的
  `assertions_on_constants` 判为「会被编译器优化掉」，闸门 3 rc=101。
  改成 `const _: () = assert!(..)`（同 win 子模块已有形状），语义更强——
  数被改小连编译都过不去（CAPCONST 实测 E0080）。另加一条真行为测试钉
  「EventHub 确实用了这个常量」（CAP1 把 channel 换回 1，1 红）。

检测力没让出去：M1 5→**7 红**、M5 1 红（panic）、M6 5 红、
  M12 2→**7 红且 5.01 秒 rc=101，不是挂死**。

自报的两件事：
  1. **两条 windows 闸门这一轮真的挡住了我一次**：把 Win32 调用塞进闭包后
     错误类型推不出来（E0282/E0283，`windows::core::Error` 两头一堆 `From`），
     macOS 的闸门 1/3 全绿。修法 `Ok::<(), windows::core::Error>(())`。
  2. **上一轮「debounce_ms 没守住」这句说重了，本轮改口**：二分实测 800 实际
     被钉在 **451..=1000**（下界来自 flap 测试、上界来自 debounce_is_under_one_second）。
     `POLL_INTERVAL` 与容量那两项上一轮说得对，仍然只钉区间。

改什么都不会红的地方（诚实清单）：**`mod win` 里的任何语义改动，按构造就
  检测不到**——闸门 5 是 build、6 是 clippy，都不跑测试。实测两枪
  （N3 去掉 catch_unwind、N4 去掉重复注册的 warn）六道全绿。这一轮把判断
  搬空之后，`mod win` 剩下的是两个 spawn、Box::leak、那一次注册调用、
  COM 初始化与轮询循环、catch_unwind、三条 tracing，全部零自动化覆盖。
  缩小它要么上 Windows CI、要么把 Win32 调用也抽成 trait 注入——后者会把
  一堆 unsafe 包在一个只为测试存在的间接层后面，本轮判断不划算。

报告改口两处（W90/W91）已落进 task-5-report.md：删掉「裸指针没有 Default」
  那句（两半都不对），补上 brief 的第四条编译错误（`recipient: HANDLE`，E0308）。

Task 5 修复轮 1：实现者交回 773322a（只动 events.rs，+555/−85，Cargo.toml/lock 零改动）。
  自报 rmc-win 125→136、workspace 381/17→392/17，六道闸门全绿。
  定向复审已派发（opus，评审包 review-47d8460..773322a.diff）。

**它有两处偏离我的裁决，都主动报备了，都值得记：**

一、**W86 它做得比裁决多，理由很锋利**：我给的两个选项（挪 set / 写清语义）
  它都没选，因为**那两个选项都会让那个顺序仍然整个待在 #[cfg(windows)] 里、
  一行测不到——等于用 W84 犯过的错去修 W86**。所以它把顺序本身抽成
  `register_once(cell, hub, register)`，把 register 当参数收。
  它同时自承引进了一个**明知的新代价**：注册生效到占格子之间有几微秒的窗口，
  此刻真有唤醒会丢一条（退避兜底）。它判断这比「此后永远不重连」轻，
  但明说「这是我的判断不是裁决的」。交复审独立判，并问有没有第三种
  既可测又没这个窗口的写法。

二、**W88 我给的形状本身是个假测试，它指出来了。** 我裁的是
  「`#[test] assert!(EVENT_CHANNEL_CAPACITY >= 8)`」——被 clippy 的
  `assertions_on_constants` 判掉（闸门 3 rc=101），**而 clippy 是对的：
  那条断言会被优化掉**。它换成 `const _: () = assert!(..)`，
  与这个项目 Task 3 SSPI 状态码常量用过的形状一致。
  **这是我这一路裁决里第一次被实现者指出「你给的形状本身不成立」，它是对的。**

它的一处改口：上一轮说「debounce_ms 的 800 没守住」**说重了**，
  二分实测 800 实际被钉在 **451..=1000**（下界来自 flap 测试的
  250ms/550ms 两次询问）。POLL_INTERVAL 与容量那两项上一轮说得对。
  交复审二分复验——这决定我判「区间就够」那条裁决是不是建立在错误前提上。

**它自报的最大一块缺口，形状比 W57 更清楚**：
  **闸门 5 是 build、6 是 clippy，都不跑测试**，所以 mod win 里任何
  还能编译的语义改动**按构造就检测不到**（N3 去掉 catch_unwind、
  N4 去掉重复注册的 warn，六道全绿）。搬空之后剩下的是：两个 spawn、
  Box::leak、那一次注册调用、COM 初始化与轮询循环、catch_unwind、三条 tracing。
  它的结论：要缩小只有上 Windows CI，或把 Win32 调用抽成 trait 注入
  （会把一堆 unsafe 包进一个只为测试存在的间接层，它判断不划算，
  但明说「这是取舍不是事实」）。**这条要进 Task 12 的 CI 决策，
  所以我要复审给一个可靠的事实基础。**

**一条正面的、这个项目第一次**：它说两条 windows 闸门这一轮**真的挡住了它一次**
  ——闭包化之后错误类型推不出来（E0282/E0283），而 macOS 的闸门 1/3 全绿。
  若属实，这是本项目第一次记录到 Windows 闸门抓到真东西
  （此前六次实测都是「盲」）。交复审核实。

=== Task 5 修复轮 1 的定向复审：六条全 ✅，判可以收口 ===
复审**先在基线 47d8460 的独立副本上重做了 PW1/PW2b 两枪**确认六绿
  （即上一轮「不通过」的依据属实），再在 HEAD 上确认 PW1 **7 红**、PW2b 2 红、
  另加 PW2c（两门顺序调换）3 红。W85 的 PW3 5 红、W86ORD 1 红、W86SKIP 1 红、
  W87 的 PDUP 2 红、W88 的 CAP1 1 红 + CAPCONST **编译失败 E0080**。
  六道闸门在仓库外净副本、独立全新 CARGO_TARGET_DIR、从零冷编译：全绿零告警。
  15 轮连跑闸门 1 失败 0 次。三份 Cargo.toml/lock diff 全空。

--- 实现者顶回来的两处，复审两头实测，**它都对，而且对得有证据** ---

**W88：我给的形状确实是假测试。** 复审自己两头验了同一段代码：
  `#[test] assert!(EVENT_CHANNEL_CAPACITY >= 8)` 在闸门 1 下是**绿的、
  而且计入 137 条**——一条被编译器折叠掉的断言混进测试计数，
  这正好是这条流水线最该防的东西；闸门 3 的 clippy::assertions_on_constants
  把它判死（rc=101）。换成的 `const _: () = assert!(..)` 挡「16 改成 1」
  是**连编译都过不去**（E0080），比测试变红更早一步。
  形状核对：全仓库 14 处这种写法，前 13 处都在 #[cfg(windows)] 里、
  macOS 上编译不到；events.rs:101 这一条**在顶层，macOS 闸门 1 就会撞上**
  ——形状一致，覆盖更宽。

**W86：我给的两个选项都会重犯 W84，理由成立。** 复审独立验了基线的
  register_power 从 POWER.set 到 .ok()? 整段都在 #[cfg(windows)] 里，
  而 mod win 在这台机器上**只被 build/clippy 看过、从不被执行**。
  所以选项 (a) 落地后那个顺序检测力仍是零，选项 (b) 是纯文档、检测力同样为零。
  新窗口的取舍**判为对**：要丢一条唤醒，机器得恰好在注册线程执行那几微秒里
  从休眠返回，代价一个退避周期；旧半截状态的代价是「此后永远不重连，
  而且调用方拿到 Ok(())」。量级差得太远。

**复审找到了第三种写法，既可测又没有那个窗口**（实现者与我都没想到）：
  `DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS` 有一个 `Context: *mut c_void` 字段，
  系统会原样回传给回调的第一个参数——**而现在那个参数叫 `_context`，
  被直接扔掉**。把状态 Box::leak 成 'static 塞进 Context，状态在注册**之前**
  就已存在，系统只可能在注册成功**之后**用那个指针调回调：
  没有格子、没有顺序、也就没有窗口，纯逻辑层一个字不用改。
  代价是丢掉 OnceLock 兼职的「重复注册探测」，得另配一个 AtomicBool。
  复审判「比现在严格好一点，但不值得现在返工」——我采纳，已把这条路
  写进 register_once 的文档（commit 694391a），Task 10 接线时定。

**debounce_ms 那处改口改对了**：复审自己二分十三个点，
  实际被钉死在 **451..=1000**（下界来自 flap 测试在 250ms/550ms 两次询问，
  上界来自 debounce_is_under_one_second）。我上一轮判「区间就够」
  建立在正确前提上。

--- 这一轮最有价值的产出：Task 12 的事实底稿 ---

Ruling W95（**进 Task 12 的 CI 决策，这是事实不是估计**）：
  复审自己数了 mod win 现在 235 行、**实际代码 94 行**（基线是 105 行，
  这一轮搬走 11 行），并**逐项枚举**了剩下的东西（它的清单比实现者的更全：
  实现者漏了格子本身、漏了「读失败这一轮跳过、previous 不动」这条判断、
  tracing 是五条不是三条）。

  然后它**打了八枪**，每枪过闸门 1/5/6：
  - **全绿**：去掉 catch_unwind；去掉重复注册的 warn；poll_network 发错变体；
    删掉 sleep(POLL_INTERVAL)（变成烧满一个核的忙等）；
    **Box::leak 换成栈上临时量（悬垂指针）**——最后这条正是代码里
    专门写了一段注释论证过的那个危险。
  - **红**：COM 线程模型 STA→MTA、只启一个监听线程、回调忽略 event_type——
    三条全是**巧合告警**（unused import / function never used / unused variable），
    不是检测。

  **结论：唯一会让 mod win 的改动露馅的，是那次改动碰巧让某个符号变成孤儿。**
  真正的行为缺陷六道闸门一个字都不说。**根因是闸门 5 是 build、6 是 clippy，
  都不跑测试**——这不是「测试不够」，是结构性的。

  复审同意「要缩小只有上 Windows CI」，但对「trait 注入不划算」打了个折，
  并给了**第三条路**：把 mod win 里最后那条判断（`if let Ok(current) =
  GetConnectivity()` 的「读失败跳过」）也搬进 ConnectivityWatcher
  （如 `observe_result(Result<i32,_>, now)`），成本三行。
  搬完之后 mod win 就只剩纯搬运，「只能靠 Windows CI 或真机手测」
  这个结论才是干净的。**这条带进 Task 10。**

Ruling W96（**这个项目第一次：Windows 闸门抓到真东西，属实**）：
  复审三头验了——把 `Ok::<(), windows::core::Error>(())` 退回成 `Ok(())`：
  macOS 闸门 1 **136 passed 全绿**、闸门 3 **全绿**，
  而闸门 5 **rc=101，E0282 × 1 + E0283 × 2**。
  此前六次实测都是「盲」，这是第一次记录到它们挡下一个 macOS 侧完全看不见的
  真问题。而且它是**本轮 W86 闭包化的直接产物**——把 Win32 调用塞进
  `impl FnOnce() -> Result<(), E>` 才让 E 无从推断。
  **教训：闸门 5/6 的价值不只在「守住 Win32 API 用法」，
  抽象化改造本身就会制造只在 windows target 上暴露的类型问题。**

Ruling W97（记录，低，带进 Task 10）：register_once 并发双调用时
  可能「真注册了 Win32 却返回 Ok(false)」，于是那条 warn 会说
  「已经注册过，本次跳过」而其实这次注册了。今天单调用点单线程，纯理论。

=== Task 5: complete ===
提交链：47d8460（实现）→ 773322a（修复轮 1，六条）→ 694391a（收口两条，我做的：
  install 降 pub(crate)、把 Context 那条路写进 register_once 的文档）。
最终状态：rmc-win **136 passed**，workspace 十个测试目标全 ok / 392 通过 / 17 ignored，
  clippy --workspace -D warnings、fmt --check、两条 zigbuild——六道全绿零告警。
  Cargo.toml / Cargo.lock 全程零改动。

=== 按用户指示，停在这里，等其消息再开始 Task 6 ===

=== Task 6 派发前预检（我自己读 brief 做的，编号接 W97）===
先核过的事实：SingleInstance::acquire 返回 Option<Self>，brief 写对了；
  workspace members 现在只有 rmc-core 与 rmc-win，要加 rmc-app；
  cargo-deny 已装；deny.toml 的 allow 列表 8 项
  （MIT / Apache-2.0 / ISC / BSD-2 / BSD-3 / Unicode-3.0 / Zlib / CDLA-Permissive-2.0）。

W98（必修，**很可能是第 21 个假绿**）：`tint_is_lighter_than_its_base_and_keeps_
  the_hue_direction` 这条测试**对常量不可能失败**。
  实现是 `1.0 - (1.0 - base) * K`，K=0.08，展开就是 `0.92 + 0.08*base`。
  于是对任何 base ∈ [0,1]：
  - `t >= base` **恒真**（0.92+0.08b ≥ b ⇔ 0.92 ≥ 0.92b，b≤1 时恒成立）；
  - `t.r > 0.9` **恒真**（最小值 0.92）。
  K 从 0.08 改成 0.02 或 0.15，这条测试照样绿。
  而且**名字里的 "keeps the hue direction" 一个字都没测**——
  色相方向根本没进任何断言。那个 `t.b > 0.88` 的 0.88（另两个是 0.9）
  是没有含义的余量，看得出是目测凑的。
  要求：钉住 K 的实际效果（比如对某个具体底色断言 tint 的确切十六进制值），
  并且要么真测色相方向、要么把名字改成它真做的事。
  变异验证：K 改成 0.02 必须变红。

W99（必修，**同一个坑的第五次**）：`chrome.rs` 零测试。
  `tabs()` 里那段「is_active → 文字色 + 边框色」是纯判断，
  却埋在一个 iced 视图函数里，在这台机器上没有任何东西看得见它。
  前四次：Task 2 的 autoproxy_flags 与 dwAccessType、Task 3 的 imp.rs 状态分类块、
  Task 5 的电源侧闸门（PW1 那一枪把需求整个反过来而六道闸门全绿）。
  rmc-win 的 lib.rs 模块文档把这条写成了 crate 级约定，
  **rmc-app 是新 crate，要在它自己的 lib/main 文档里把同一条约定立下来**。
  改法：抽 `fn tab_style(is_active: bool) -> (Color /*文字*/, Color /*边框*/)`，
  表驱动测试两格。

W100（必修，**这是本任务最大的未知**）：`cargo deny check licenses`
  **从来没见过 iced 这棵树**。iced 0.13 会拉进 wgpu / winit / naga /
  cosmic-text / ttf-parser 等一大片，而 allow 列表只有 8 项。
  要求：四项 deny 检查（advisories / bans / licenses / sources）全跑、
  把实际输出贴进报告。**如果 licenses 变红，不要自己往 allow 列表里加**——
  报上来我裁。先例：webpki-roots 的 CDLA-Permissive-2.0 是
  「一次刻意拍板，不是被 CI 逼红之后顺手加的」，deny.toml 里那段注释写着这句话。

W101（必修，依赖声明要跟工作区对齐）：brief 的 Cargo.toml 写
  `tracing = "0.1"`、`zeroize = { version = "1", features = ["std"] }`，
  而这两项**已经在 `[workspace.dependencies]` 里**，应该写 `.workspace = true`。
  另外 brief **漏了 `publish.workspace = true`**——其余两个 crate 都有，
  而且 deny.toml 的 `[licenses.private] ignore = true` 正是靠
  `publish = false` 才跳过对我们自己 UNLICENSED 源码的检查。漏了会让
  licenses 因为我们**自己**的包变红，跟第三方依赖无关。

W102（必修，先核实再决定）：`#![cfg_attr(windows, windows_subsystem = "windows")]`
  加在 bin 上，Windows 上意味着没有控制台。**而单元测试就住在这个 bin target 里**
  ——要确认 `cargo test` 在 Windows 上还看不看得见测试输出。
  如果会吞掉输出，改成只在 release 生效（`cfg_attr(all(windows, not(test)), ...)`
  之类），并在注释里写明为什么。

W103（必修，现在就定，别拖到 Task 7）：brief 建的是**纯 bin crate**，
  `chrome.rs` 用 `use crate::Message`。Task 7 要做视图模型、Task 8-11 要做三个页面
  加托盘——全部塞进 bin 里测试仍然能跑，但这是个现在几乎零成本、
  以后要改五个文件的决定。判断要不要拆成 lib + 一个薄 bin，并把理由写进报告。

W104（必修，**Task 5 的教训**）：brief 那句「若 iced 0.13 的 `application` 签名不同，
  以 cargo doc 为准调整」说明**作者自己也没编译过这段**。
  Task 5 已经证实过一次同样的事：brief 的 Win32 代码按原样抄进去
  编译不过（两个常量在错的模块里、一处真类型错误），从来没被编译器看过一眼。
  所以：feature 名（`wgpu` / `tiny-skia` / `tokio` / `advanced`）、
  `iced::application` 的签名、`button::Style` 的字段、`text().color()` 的存在性，
  **逐个以 0.13 的真实 API 为准**，凡是 brief 与实际不符的**逐条记进报告**。

W105（记录）：`PROGRESS` 与 `ACCENT` 是同一个色值 `#0067c0`，
  两条测试各自钉一遍。不是问题，但读代码的人会以为是笔误，值一句注释。

W106（记录，人工验收）：固定 520×720 + `resizable: false`，
  在高 DPI 笔记本上可能过小或过大。这台机器验不了，进人工验收清单。

Task 6: 实现完成 19bfda2（DONE_WITH_CONCERNS）。workspace 403 passed / 18 ignored
  （基线 392/17，rmc-app 新增 11 条 + 1 条 ignored doc-test）。

实现者报的三件事，两件把方向指到了同一处：
  - **W100 cargo deny 由绿变红**，它按要求没动 deny.toml。
    它先在 HEAD 副本上确认基线四项全 ok，加 iced 后
    advisories FAILED（4 条 unmaintained：instant / paste / rustybuzz / ttf-parser，
    **没有一条是 vulnerability**，四条都写着 "No safe upgrade is available"）、
    licenses FAILED（clipboard-win / error-code 的 BSL-1.0 经 winit；
    hexf-parse 的 CC0-1.0 经 naga/wgpu）。
  - **闸门 8 rmc-app 过不了 windows-gnu 的 zigbuild**，它没硬扛：
    失败点是**纯链接**——wgpu-hal 的 DX12 后端要 -ld3dcompiler，
    而 windows_x86_64_gnu-0.52.6 的导入库里没有 libd3dcompiler.a。
    **代码本身在 windows 目标下被 rustc 与 clippy 完整检查并通过**
    （`clippy -p rmc-app --all-targets --target ...` 与 `zigbuild -p rmc-app --lib`
    都是 exit 0），只有编 bin/tests 时链接失败。rmc-win 的闸门一个字没退。
  - **六条「改什么都不会红」的缺口，比变红的十条更值得看**：
    把 title_bar() 文案改成 "Gateway"（**需求明令禁止的词**）、
    让 tabs() 完全不调 tab_style 而全部硬编码成未选中样式、
    去掉 .on_press 让页签点了没反应、resizable: false → true、
    窗口尺寸绕开 WINDOW_SIZE 写死 800×600、单实例互斥体改名——**六条全绿**。
    它的诊断很准：W99 的抽取解决了「判断不可见」，**解决不了「视图有没有真的用它」**
    ——iced 0.13 没有任何 headless 控件树断言，**iced_test 是 0.14 才有的**。
    并指出 Task 7-11 每加一个 view/ 文件这个缺口就大一分。

W104 的结论（值得记）：**brief 的 iced API 部分全对**——application 签名、
  四个 feature 名、button::Style 字段、text().color() 它都核实过真实源码。
  问题全在 Cargo.toml（W101）、测试（W98）和 crate 形状（W102/W103）上。
  这与 Task 5 的 brief 不同（那份的 Win32 代码从没被编译器看过）。

--- 我自己实测的三种组合（用本仓库的 deny.toml 跑的）---
  iced 0.13 + wgpu（现状）：advisories 4 条、licenses 3 条
  iced 0.14 + wgpu：        306 包、advisories **2** 条（instant/rustybuzz 消失）、licenses 3 条
  iced 0.14 只 tiny-skia：  243 包、advisories **1** 条（只剩 ttf-parser）、licenses **1** 条（只剩 BSL-1.0）
  另核实：**iced_test 0.14 能正常解析**，headless 控件树断言可用。

=== 用户拍板（两问两答）===

Ruling W107（**用户选定：只用软件渲染 tiny-skia，iced 升 0.14**）：
  理由链：0.14 带 iced_test，是补上那六条盲区的**唯一**办法，而界面还有
  Task 7-11 五个任务要写，每个都会把盲区放大；砍掉 wgpu 之后
  243 包 / 1 条 advisory / 1 条许可证，而且 **windows-gnu 的链接问题一并消失**
  （d3dcompiler 是 wgpu 的 DX12 后端要的）。
  代价是纯软件绘制——对这个 520×720、只有文字和几个按钮的工具窗口判为看不出差别；
  而且 brief 原本要 wgpu+tiny-skia 并存的理由正是「RDP 与虚拟机里能起来」，
  只留 tiny-skia 之后**根本没有 GPU 初始化这条会失败的路**，那个目标反而更稳。

Ruling W108（**用户选定：deny 的剩余问题写进 ignore 并附理由**）：
  照 deny.toml 现有惯例——每条写明是哪个包、为什么绕不开、什么条件下该重新评估。
  这个仓库已有先例：webpki-roots 的 CDLA-Permissive-2.0 是
  「一次刻意拍板，不是被 CI 逼红之后顺手加的」，注释里写着理由。
  落地两处：allow 加 BSL-1.0（Boost 软件许可证）；
  advisories.ignore 加 ttf-parser 那条 unmaintained（无漏洞、无升级路径、
  iced 0.14 钉死 cosmic-text 0.15）。**unmaintained ≠ 有漏洞，但要留下决定的痕迹。**
  明确不采纳的选项：把 advisories 降成警告——这个项目的 rustls-pemfile
  正是靠 advisories 变红才被发现并迁移掉的。

Task 6: 返工轮已派发（W107 + W108 + 用 iced_test 堵那六条盲区）。

=== 暂停（用户指示，等其消息再开始）===
Task 6 返工轮刚派发就被停掉，**没有任何改动落地**：
  HEAD 仍是 19bfda2（Task 6 的首版实现），工作树干净。

恢复点（返工轮的完整内容已写在上面 W107/W108 两条裁决里，照发即可）：
  1. iced 0.13 → 0.14，features 改成 ["tiny-skia", "tokio", "advanced"]，
     0.13→0.14 的 API 变动逐条记进报告（对 Task 7-11 直接有用）。
  2. **主戏**：用 iced_test 堵实现者自己列的那六条盲区，尤其第 1 条
     「title_bar() 文案改成 Gateway（需求明令禁止的词）六道闸门全绿」——
     顺手做一条「整棵控件树里不许出现 Gateway/网关」的断言，
     那对 Task 7-11 五个页面都是现成的防线。
     后三条（resizable、窗口尺寸、互斥体名）在 main() 里可能够不着，
     要求「够不着就如实说并说明要怎样才够得着，别硬造形状也别默默跳过」。
  3. deny.toml 两处：allow 加 BSL-1.0、advisories.ignore 加 ttf-parser，
     照 webpki-roots 那段注释的调子写明理由。**不把 advisories 降成警告。**
  4. 保住上一轮 W98/W99/W101/W102/W103 的落地，重做两枪确认仍红
     （tint 的 K 0.08→0.02；tab_style 两格对调）。
  5. 九道闸门，含 **rmc-app 的两条 windows-gnu 闸门现在应该能过了**
     （d3dcompiler 是 wgpu 的 DX12 后端要的，砍掉 wgpu 就没这个依赖），
     以及 cargo deny 四项必须全 ok。

当前整体进度：12 个任务完成 5 个（Task 1-5），Task 6 首版已提交待返工。
  feat/rmc-win 领先 main 14 个提交，从未 push；origin/main 在 1bda177。

=== 恢复（用户指示「继续」）===
Task 6 返工轮重新派发，内容与 W107/W108 一致，BASE 仍是 19bfda2。
**署名行又变了**：从此提交结尾两行都要——
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
  与 `Claude-Session: https://claude.ai/code/session_015PtVMVkfRBibyzDDPhwBGw`。

Task 6 返工轮：实现者交回 d5d52e3（接在 19bfda2 之后，未改写历史）。
  workspace **413 passed / 0 failed / 18 ignored**（上一轮 403/18；
  rmc-app 从 11 条长到 21 条 = lib 15 + tests/ui.rs 6）。
  **九道闸门全绿，含上一轮报红的两条**：
  `cargo deny check advisories bans licenses sources` → 四项全 ok；
  `cargo zigbuild -p rmc-app --tests --target x86_64-pc-windows-gnu` → exit 0。
  **W107 的预判成立**：d3dcompiler 链接失败随 wgpu 一起消失，
  实现者主动撤回了它上一轮「把 rmc-app 从这条闸门降级」的建议。

六条盲区逐条变红（B1 Gateway 文案、**B1b 中文「网关」**、B2 tabs 不调 tab_style、
  B3 去掉 on_press、B4 resizable、B5 窗口尺寸、B6 互斥体名）。
  K1（TINT_ALPHA 0.08→0.02）、K2（tab_style 两格对调）重做仍红，
  W98/W99/W101/W102/W103 未退化。
  **W102 这次在真产物上复核**：rmc.exe 的 PE Subsystem=2(GUI)、
  bin 的测试程序=3(CONSOLE)——不是读代码推的，是读产物量的。

--- 裁决 ---

Ruling W109（**接受实现者那处范围外的修改**）：它升版本时核到一个真回归——
  0.13 我们关掉 `auto-detect-theme` 后 `Theme::default()` 恒为 Light；
  **0.14 把那个 feature 删了**，深浅色探测挪进 iced_winit
  （`event_loop.system_theme()` → `window/state.rs:60`），
  **Windows/macOS 上没有 feature 开关**。于是不显式指定主题的话，
  用户开着 Windows 深色模式启动就会得到**深色底 + 我们固定浅色画板的
  TEXT(#1c1c1c)**＝深底黑字，读不了。
  它加了 `APP_THEME = Theme::Light` + `.theme(APP_THEME)` + 一条对比度测试
  （变异 Light→Dark 实测红）。
  **接受**：这是本轮强制的升版本**自己带进来的**回归，不是洁癖；
  锁 Light 与已定版浅色画板一致；而且它明说反向只需改一行常量。
  **带进 Task 7 的问题**：要不要跟随系统深色模式、并补一套深色画板。
  这是产品决定不是技术决定，Task 7 派发时提给用户。

Ruling W110（**认可它「不建议继续追」的取舍**）：残余五条「改什么都不会红」
  全在 main() 的 17 行里，而且**性质与第一轮不同**——不再是「一整块逻辑没测」，
  而是「值有测试了，但没人验证 main() 真的用了它」
  （R1 绕开 window_settings() 就地写死、R3 绕开 SINGLE_INSTANCE_NAME 就地写死）。
  它的判断：要让它们变红只能写真启动窗口的端到端测试（这台机器与 CI 都起不了），
  或去断言 iced::Application 的私有字段（做不到，硬做就变成「再抄一遍常量」的假绿）。
  **同意。** 但它挑出的那条例外要认真对待——见 W111。

Ruling W111（**进人工验收清单，且要进 Task 7-11 每一次派发**）：
  五条里**只有 R2 有实际需求风险**：`.title()` 设的是**操作系统窗口标题栏**，
  不在 iced 控件树里，`iced_test` 够不着。
  真改成 "Gateway" 会出现在**任务栏与 Alt+Tab 上**，
  而那条禁用词扫描**看不见**。
  也就是说 B1/B1b 那条防线有一个明确的、已知的缺口，位置就在窗口标题。

Ruling W112（记录，N2 快照测试的边界——**这段比「做到了」本身有用**）：
  实现者说清楚了 N2 差分快照只能证明「选中不同页签画出来不一样」，
  **不能**证明「画得对」——有人把选中态下划线从 ACCENT 换成别的颜色，
  两帧仍然不同，这条照样绿；那一层靠 tab_style 的表驱动单测守。
  **两条缺一不可，删任何一条 N2 都会重新变成盲区。**
  它还**刻意没把快照基线提进仓库**，理由是 `matches_hash` 在基线文件缺失时
  会自动写一份并返回 true——**标准的假绿形状**；且 CJK 走系统字体回退
  跨平台必然对不上。基线写进 tempdir 跑完即扔，tempfile 是 rmc-core
  已有的 dev-dep、不新增包。

Ruling W113（记录，两条升版本的副作用）：
  - `default-features = false` 之后 **iced 在 Linux 上没有 x11/wayland**
    （0.14 把它们放进了 default）。对 Windows 客户端无影响，
    但将来有人在 Linux 上 `cargo run -p rmc-app` 窗口大概率起不来。
    已进验收清单，没改 features。
  - **MSRV 被顶到 1.88**（iced 0.14 与 iced_test 都声明 1.88，
    iced_test 还是 edition 2024）。workspace 的 1.89 够用，
    但**以后不能再往下降**。

Task 6: 评审已派发（opus，评审包 review-694391a..d5d52e3.diff，两个提交）。

=== Task 6 评审结论：通过（6 条发现：2 中高 + 1 中 + 2 低 + 1 记录）===
九道闸门评审在**全新 CARGO_TARGET_DIR** 冷启动逐条复跑、每条带硬超时，
  数字全部对上：21 passed (lib 15 + ui 6)、workspace 413/18、deny 四项 ok、
  闸门 8 rc=0。`cargo metadata --locked` 通过，Cargo.lock 无漂移。
  **它按 Task 4 的标准证明了闸门 8 真在编译 cfg(windows) 那一层**
  （塞 `const _: () = assert!(1==2)` 进 main.rs 的 windows 分支 → E0080），
  不是「编过了」而是「编到了那一行」。

七条盲区评审逐条重做全红，**并且自己加了三枪，其中一枪是关键**：
  - **G2**：在 tabs() 控件树**最后**再挂一个 `text("Gateway")` → 扫描器变红。
    这证明它**真的遍历全树**，不是只看到第一个文本控件。
    B1/B1b 的禁用词都在树的第一个位置，单靠它们证不了这件事，
    而 **Task 7-11 每加一个页面都是往树的后面加**——这条性质才是
    那道防线值不值钱的关键。**它值钱。**
  - G3：把 Tab::Logs 标签改成「网关日志」（禁用词埋在按钮文字深处）→ 红 4 条。
  - G1：title_bar 整个不画文字 → 反向自证那段被打红，不是摆设。

评审回到真实源码/产物/advisory 库核了四件事，**没有一处说法是夸大的**：
  - **W109 是真回归**，四处源码链条完整：0.13 的 `auto-detect-theme` feature
    在 0.14 里**三个 Cargo.toml 与全部源码零命中**（整个删了）；
    iced_winit-0.14.1/src/lib.rs:179-186 把 system_theme 送进主循环，
    :554-556 那个 cfg 分支**只把 Linux 排除在外，Windows/macOS 走的正是没有
    开关的那条路**；Program::theme 默认返回 None，State::theme() 在 None 时
    回落 default_theme，而且 state.rs:179/:236 在系统主题变化时**运行时重算**
    ——不显式指定的话用户切深色模式它当场跟着变。
  - **matches_hash 的假绿陷阱属实**（iced_test-0.14.0/src/simulator.rs:307-330
    逐字确认：基线不存在 → 写一份 → `Ok(true)`；matches_image 同形状）。
    **而且评审指出这个陷阱在现在的写法里极性是反的**：自动写入只落在
    `assert!(first)` 那个方向，真正的判据是第二帧的 `assert!(!second)`，
    自动写入永远只会让它 true 也就是**变红**。失败模式是安全的。
  - **W102 的 PE 量法带载**：评审自己读 PE 可选头，还做了**反事实**——
    把 `not(test)` 去掉重编，同一个哈希的测试 exe 立刻从 Subsystem=3(CONSOLE)
    变成 2(GUI)。
  - **W108 两条豁免都带载且最小范围**：逐条摘掉复跑，删 BSL-1.0 → licenses FAILED，
    删 RUSTSEC-2026-0192 → advisories FAILED。deny.toml diff 55 行**零删除零修改**，
    bans / licenses.private / yanked / 原有 8 项 allow 一个字没动。
    「无升级路径」评审自己查链条属实：iced_graphics 与 iced_tiny_skia 都钉
    `cosmic-text = "0.15"` → fontdb 0.23 → ttf-parser，迁移在上游手里。

**W112 的边界自述精确到评审用 N2b 变异复核时结果一字不差**：
  把选中态下划线从 ACCENT 换成 FAILED —— `tab_style` 的表驱动单测红，
  而 N2 差分快照**没红**（两帧仍然不同）。两条缺一不可成立。

--- 裁决 ---

Ruling W114（**本轮修，评审自己写出并验证了实现者说「做不到」的那条路**）：
  实现者的 W110 理由是「只能靠真启动窗口的端到端测试，或断言
  iced::Application 的私有字段（做不到）」。**后半是错的。**
  评审查到 `iced-0.14.0/src/application.rs:459` 有
  `impl<P: Program> Program for Application<P>`——
  也就是 `iced::application(..).title(..).theme(..).window(..)` 返回的 builder
  **自己就实现了公开的 iced::Program trait**，而
  `iced_program-0.14.0/src/lib.rs:44-116` 公开了
  `title()` / `window()` / `theme()` / `view()` / `boot()`。
  **装配结果全是公开可读的，不需要窗口、不需要私有字段。**

  评审在仓库外写了完整 PoC 并实测：一个 12 行的
  `pub fn program() -> iced::application::Application<impl iced::Program<...>>`，
  main() 缩成 `program().run()`，加两条测试（用**泛型 helper 绕开 Application
  的同名固有方法遮蔽**）。四枪全部变红：title 写 "Gateway"、窗口写死
  800×600+resizable、删 .theme(APP_THEME)、挂一个画 Gateway 的 evil_view。
  基线 17 passed + 6 ui passed，clippy -D warnings rc=0。

  **约 30 行、零新依赖、零新抽象，同时堵掉 R1/R2/M1/M2 四条。**
  形状与已认可的 window_settings() 抽取同源，也是 Task 5 那次
  「造抽象是过度设计」被驳回的先例的再一次。

Ruling W115（**评审补上了实现者变异表漏掉的两条，都比它列出的 R4/R5 严重**）：
  - **M2【高】**：`main()` 可以挂一棵**字面画着 "Gateway" 的控件树**，
    21 条测试全绿——B1/B1b 那道防线**在装配根被整个绕开**。
    实现者把 main() 描述成「只剩三个已测常量/函数的组装」，低估了它的面
    （实际是四个，含 .theme，再加 view/update 的接线）。
  - **M1【中高】**：删掉 `.theme(APP_THEME)` 全绿，**直接复活它自己刚修好的
    W109 深底黑字回归**。常量测了、main() 用没用没人管。
  变异表在「会变红」那一侧**完全诚实**（评审重做的每一条一条不多一条不少），
  在「不会红」那一侧**不完整**。W114 一并堵掉这两条。

Ruling W116（**撤回 W111 的措辞**）：原话「自动化够不着这一条」应改成
  **「当前实现够不着，成本极低的改法能够得着」**。R2（`.title()` 写成 Gateway
  会出现在任务栏与 Alt+Tab 而扫描看不见）经 W114 之后**能自动守住**。
  剩下真正只能人工验收的是 R3（cfg(windows) 的互斥体名，macOS 上连编译
  都不过一遍）与 R4/R5（纯视觉尺寸）。

Ruling W117（**本轮顺手，文案偏离要留痕**）：实现把标题栏从画板与 brief 的
  `Remote Maintenance` 改成了「远程运维客户端」，两份报告只顺带提了新文案、
  **没列进「与 brief/画板不符」的逐条记录**，而 theme.rs:1 的模块文档自己写着
  「取值来自已定版画板，改动前先改画板」——画板没改。
  **裁定：保留中文文案**（与「界面上叫运维服务器」的中文要求同向，方向是对的），
  但要在代码里留下这是一处**刻意偏离**的痕迹。
  画板本身的更新与另一处不一致（画板标题栏文字色 #3b3b3b vs 代码用的
  TEXT_SUB #6b6b6b，这条来自 brief、实现照抄）一起带进 Task 7。

Ruling W118（本轮顺手，两条一行级）：
  - iced 的 `advanced` feature **当前没有任何代码用到**（评审摘掉它仍全绿）。
    它是纯 re-export 开关、不引入新包，Task 7 做自定义控件大概率要用，
    留着无害，但现在是从 brief 继承的空转项，值一行说明。
  - **Linux 上 `cargo run -p rmc-app` 起不了窗口**（default-features = false
    砍掉了 x11/wayland），而仓库里没有任何东西会提醒踩到的人。
    在 Cargo.toml 的 features 注释里补一句。

Ruling W119（记录）：tests/ui.rs:48 的反向自证锚在字面量「运维」，
  Task 7 改标题栏文案会让它红。**是响亮失败不是静默失效**，可接受，但要知道它会响。

Task 6: 修复轮 1/5 已派发（W114 + W115 + W117 + W118）。

=== Task 6: complete ===
提交链：19bfda2（首版 iced 0.13 + wgpu）→ d5d52e3（返工：iced 0.14、
  砍 wgpu、iced_test 堵七条盲区、deny 两处豁免）→ fb34896（收口，我自己做的：
  W114/W115/W117/W118）。
最终状态：rmc-app **23 passed**（lib 17 + ui 6），workspace **415 passed / 18 ignored**，
  clippy --workspace -D warnings、fmt --check、
  cargo zigbuild -p rmc-app --tests --target x86_64-pc-windows-gnu、
  cargo-zigbuild clippy -p rmc-win 同 target、
  **cargo deny 四项全 ok**——全绿零告警。

**评审在被我索要 PoC 源码时，自己发现它原版那条测试犯了本项目第一号毛病**：
  名字叫 `program_view_is_the_app_view_and_says_no_gateway`，
  **实际只断言了「产品名和三个页签画出来了」，根本没扫禁用词**。
  它自己补上扫描、把原来的正向断言保留为反向自证，并把两半各打一枪独立验证。
  这是这条流水线第一次在「交付前」就抓住自己的假绿，而不是靠下一轮评审。

W114 落地，五枪我自己在仓库外副本复跑（独立 CARGO_TARGET_DIR、
  os.utime 推进 mtime、trap 清理），各红一条且**各打在不同断言上**：
  .title("Gateway") → 标题断言；绕开 window_settings → 尺寸断言；
  删 .theme(APP_THEME) → 主题断言；挂只有 text("Gateway") 的树 → 反向自证；
  挂 column![App::view(), text("网关直连模式")] → 禁用词扫描。
  **后两枪证明第二条测试的两半各自独立带载。**
  （我第一次写变异签名写错了——`App::view(&self)` 不带 window::Id，
   evil_view 的签名跟着错，编译不过、grep 出来是空的。改对后两枪都复现。）

Ruling W120（采纳评审对 W118 第二条的建议，**不用 compile_error!**）：
  评审的理由我认同且它自己标注了「这一条是推理不是实测」——
  **Linux 上 `cargo test -p rmc-app` 是能过也应该过的**（iced_test 是无头
  模拟器，不碰 winit 的窗口创建路径），起不来的只有 `cargo run`。
  而 compile_error! **按 target 判、不按用途判**：放 lib.rs 会让 Linux 上的
  `cargo check/clippy/test --workspace` 全红（连只想编 rmc-core 的人都被拦）；
  挪 main.rs 也绕不干净（cargo test 仍会把 bin 当普通 binary 编一遍）；
  而且将来真给 rmc-app 透出 x11/wayland feature 时它会变成过期的守卫。
  **落地为 Cargo.toml 的常驻注释**——评审另指出人工验收清单会随任务关闭，
  这条不该只活在清单里。

Ruling W121（本轮已做）：BANNED_WORDS 提成 `pub const`，
  lib.rs 的两条 + tests/ui.rs 三处防线共用一份。
  评审的理由：Task 7-11 还要加三个页面，词表一旦分叉迟早有一份漏掉新词。

Ruling W122（记录，advanced feature）：评审补测了我问的那件事——
  摘掉 advanced 前后 **Cargo.lock 一个字节没变、包数同为 400**，
  `cargo tree --edges all` 的差异**只有 feature 边、没有任何包的增删**。
  对照 iced-0.14.0/Cargo.toml:49-52 的定义（两侧都是已在图里的 crate 的
  feature、没有 dep: 开关），**纯 re-export 开关**判断成立。留着，注释留痕。

--- 带进 Task 7 的清单 ---
  - **产品决定，要问用户**：要不要跟随系统深浅色、补一套深色画板（W109）。
    现在是钉死浅色，反向只需改一行常量。
  - W106：固定 520×720 在 1080p @150% 缩放下（可用高度约 660 逻辑像素）
    大概率放不下。实现者与评审都判为真问题，但都没擅自改需求。
  - W117：标题栏文案从画板/brief 的 `Remote Maintenance` 改成了
    「远程运维客户端」，**画板没跟着改**；另有一处画板标题栏文字色 #3b3b3b
    vs 代码 TEXT_SUB #6b6b6b（这条来自 brief、实现照抄）。两条一起定。
  - W119：tests/ui.rs 的反向自证锚在字面量「运维」，改标题栏文案会让它红。
    **是响亮失败不是静默失效**，但要知道它会响。
  - W111 修正版（W116）：R2 已被 W114 堵住。真正只能人工验收的剩
    R3（cfg(windows) 的互斥体名，macOS 上连编译都不过一遍）与
    R4/R5（页签内边距、标题栏高度，纯视觉）。
  - 范围外：`#[cfg(windows)]` 那一层的老账在 rmc-app 里也开了口——
    现在只有 main.rs 一处、面很小，但 **Task 10 做托盘时这块会迅速长大**，
    「两条 windows 闸门都不跑测试」的结构性问题会原样搬过来。

下一步：Task 7（视图模型，395 行）。

=== 用户方针（两条，贯穿 Task 7-12）===

Ruling W123（用户拍板：**钉死浅色**）：不跟随系统深浅色、不补深色画板。
  APP_THEME = Theme::Light 保持不变，W109 那条修复就是最终形态。
  Task 8-11 三个页面只出一套浅色配色。
  （将来要跟随系统，改一行常量 + 补一套深色画板，代价明确。）

Ruling W124（用户方针：**先完成，再完善**）——这条改变我后面的裁决尺度：
  前六个任务我为「中低」「低」项也开过修复轮。从 Task 7 起收紧，
  判据是**成本会不会随时间涨**，不是严重度：

  **仍然当场修**（这些不是完善，是「现在便宜以后贵」）：
  - 正确性 bug、需求违反（如禁用词出现在界面上）；
  - **跨任务的契约**——trait 签名、公共常量、模块约定（W36 的
    next_token 改 Zeroizing、W45 的 begin_connection、W114 的 program()
    都属此类，它们的共同点是「下游消费者还是零」）；
  - **后面五个任务要在上面加东西的测试脚手架**（如禁用词全树扫描，
    Task 7-11 每加一个页面都靠它）。

  **一律记进「后续完善」不开轮**：
  - 纯视觉与文案打磨、画板与代码的不一致；
  - 文档措辞精度；
  - 低后果代码的覆盖缺口；
  - 命名、注释、以及任何「改与不改都不影响别的任务」的项。

  派发单从 Task 7 起也照这个尺度写：预检仍然照做（它便宜且防的是返工），
  但把「必修」的门槛提到上面第一组。

据此对两条挂着的画板不一致定案（**都进后续完善，不动**）：
  - W117：标题栏文案「远程运维客户端」与画板的 `Remote Maintenance` 不一致——
    保留中文（与「界面上叫运维服务器」同向），画板等后续完善时一并改。
  - 画板标题栏文字色 #3b3b3b vs 代码 TEXT_SUB #6b6b6b——不动。

=== 后续完善清单（不在任何任务的必修里，完成全部功能后再统一处理）===
  - 画板与代码的两处不一致（W117）
  - 固定 520×720 在 1080p @150% 缩放下放不下（W106）——**这条要留意**，
    它是唯一一条「不改就可能在真机上不可用」的完善项，Task 12 真机验收时必查
  - rmc-app 的页签内边距、标题栏高度零覆盖（R4/R5，纯视觉）
  - tests/ui.rs 的反向自证锚在字面量「运维」，改文案会响亮变红（W119）

=== Task 7 派发前预检（按 W124 的新尺度，必修门槛提高了）===
先核类型（Task 5 的教训）：TunnelEvent（5 变体）、State（**7** 变体）、
  RemoteSessionInfo（4 字段）、PreflightReport 我逐个对过 rmc-core 真实定义，
  **brief 全对**——与 Task 5 那份「Win32 代码从没被编译器看过」不同。
  `elapsed(now)` 把时刻当参数传也是对的（R92 的教训：start_paused 管不着 SystemTime）。

W125（**必修，需求违反，我 grep 出来的**）：
  **「界面上叫运维服务器，不叫 Gateway/网关」这条硬禁令在源头就被违反了。**
  rmc-core 的**用户可见字符串**里有五处 "Gateway"：
  - `error.rs:20` `"Gateway host key 与已记录的不一致，已拒绝连接（记录 {expected}，本次 {actual}）"`
  - `error.rs:23` `"Gateway TLS 证书链无效：{0}"`
  - `error.rs:59` `"Gateway 长时间未响应 keepalive，判定连接已断开"`
  - `preflight.rs:83-84` `STEP_GATEWAY_DNS = "Gateway 域名解析"`、`STEP_GATEWAY_TLS = "Gateway TLS"`
  - `config.rs:52` `"一体机地址不能与 Gateway 地址相同"`
  **我核实了它们真能上屏**：`supervisor.rs:1017` 是
  `State::Failed { class: e.class(), message: e.to_string() }`，
  Error 的文案原样进 message → `status_card().subtitle` → 渲染。
  preflight 那两个常量是诊断页（Task 9）要显示的步骤名。
  **而 Task 6 那道禁用词全树扫描抓不到**：它扫的是当前渲染出来的树，
  这些字符串只在特定状态出现，没有测试渲染那些状态。
  **更要命的是 brief 自己的测试夹具用的就是那句
  `"Gateway host key 与已记录的不一致"`**——实现者照抄就把它焊死了。
  处置：改掉这五处文案；并把禁用词扫描扩到 rmc-core 的用户可见字符串
  （按 W124 第三类：这是 Task 8-11 都要靠的脚手架）。

W126（必修）：`State` 有**七**个变体，brief 的 `status_colors_follow_the_state`
  表里只有**六**个——**缺 `State::Stopping`**。
  这正是 Task 2（7 变体里 3 个没身份测试）与 Task 3（10 变体）踩过的形状，
  而 Task 8 的维护页直接渲染 status_card()/buttons()，落错分支就是一屏乱码。
  Task 3 的解法是 macro + 定长数组让「加变体不进表」编译不过；
  `State` 在 rmc-core、宏用不上，改用**测试里的穷尽 match** 映射
  （rmc-core 加变体 → 这里编译不过）。

W127（必修，同 W22 的形状）：`no_countdown_anywhere_in_v1` 是纯粹的
  「只查不存在」断言——`status_card()` 若返回空字符串，它照样绿。
  加正向前置（title/subtitle 非空）再查「剩余」。

W128（必修，**这是预检里最值钱的一条**）：`Model` 把
  `credentials_visible` / `addresses_editable` 存成**字段**，
  而 brief 的测试里它们全部从 `state` 派生。
  **存成可变字段 = 影子状态**，正是 rmc-core 那三次隧道泄漏的形状
  （R71/R75/R78：ctx.state 落后于真实状态，准入判断放过了不该放过的东西，
  最后靠「准入判断一律改看同步字段」修掉）。
  这里的后果轻一些（显示错而不是泄漏隧道），但形状一模一样，
  而 Task 8/10 会往 Model 写东西。
  改成从 `state` 派生的方法。**若产品上需要用户手动切换「显示口令」，
  那是另一个来源，要用另一个名字，别让两个来源共用一个字段。**

W129（必修，第一号毛病）：`stopping_clears_sessions_and_elapsed`
  **名字说 stopping，实际 apply 的是 `State::Idle`**。
  要么改名，要么真的测 `State::Stopping`（与 W126 一并）。

记录不修（按 W124 进后续完善）：无。这份 brief 的问题都落在必修那一组。

Task 7: 实现完成 003807b（DONE_WITH_CONCERNS）。415 → **444 passed / 18 ignored**
  （rmc-app lib 17→40、rmc-core lib 210→216、tests/ui.rs 6 条一行未动），七道闸门全绿。
  新增 model.rs 820 行、**wording.rs 376 行**（禁用词脚手架），另动 rmc-core 六个文件。
  评审已派发（opus，评审包 review-fb34896..003807b.diff）。

W125-W129 五条全部落地。实现者自报的六条，四条值得记：

  - **W125 实际是八处不是五处**，它自己又核出三处同机制的：
    `transport/tls.rs:61` 的 `Error::Config(format!("Gateway 主机名不能用于 TLS…"))`
    ——**与我点名的 config.rs:52 一模一样的形状**（构造点拼文案、不在 `#[error]` 里，
    按变体走 Display 的扫描看不见）；以及 supervisor.rs:866/1376 两行审计日志。
    **审计那两条的上屏路径它没能验证**（Task 11 日志页还没写，不知道会不会原样渲染
    审计行）。若不会渲染，那两行是多改的（无害）。**带进 Task 11 确认。**

  - **这八处过去六个任务一直零测试覆盖。** 改完之后 rmc-core **一条测试都不用改**
    ——它自己指出这不是因为改得干净，是因为所有沾边的断言都只看非 Gateway 的部分
    （`contains("证书")` / `contains("host key")` / `contains("一体机")`、
    preflight 按常量名取值）。**这条硬禁令在 rmc-core 侧此前完全无人守。**

  - **它自己写的扫描器第一版有一个假绿，做变异时才发现**：把 `strip_placeholders`
    改成恒返回空串，源码扫描永远抓不到任何东西而照样全绿。已补第三段自证。
    **这是第三次有实现者在交付前抓住自己写的假绿**（前两次：Task 5 的挂死形态、
    Task 6 评审重建 PoC 时发现自己那条 `says_no_gateway` 根本没扫禁用词）。
    它还主动列了两处**没堵的已知空洞**：豁免表可以被撑大
    （过期检查守得住条目失效、守不住条目变多）；`mod tests {` 之后的生产代码扫不到。

  - **它写实现时发现了 brief 的一个真 bug**：backoff 副标题用 `as_secs()`，
    而 `backoff.rs` 首档 1 秒**带抖动可到 0.8 秒**，于是会显示「0 秒后重试」。
    改成向上取整最小 1。

自报「改什么都不会红」四处（判为纯文案/低后果，它记进了后续完善）：
  五条状态副标题的文字整句换掉不会红；ALL_STEPS 顺序打乱不会红；
  Error 任意一条无禁用词文案改掉不会红。
  **这正是我在派发里点名的 `contains` 成色问题**，交评审按用户方针判够不够格当场修。

三处偏离 brief（它在报告里各给了理由）：Connected 副标题不再编造
  `127.0.0.1:22001`（本任务 Model 没有配置，写死是编造，等 Task 8）；
  degraded 的「每 30 秒」取自 APPLIANCE_PROBE 不另写；backoff 秒数向上取整。

**一处产品决策挂着（按「先完成再完善」不阻塞，记这里）**：
  `config.rs` 的默认地址 `gateway.company.com` **会出现在界面地址框里**。
  它是方案设计.md §3.10 示意图原样给的**占位域名**（是域名、不是对这台机器的称呼）。
  实现者把它放进 wording.rs 的 ALLOWED 豁免表而**不是偷偷放过**，并有过期检查守着。
  若要求界面上一个 gateway 像素都不能有，那是改方案文档不是改代码。
  **我的倾向**：域名与称呼是两回事，且这条成本不随时间涨（一个常量），
  按方针进后续完善清单，Task 12 真机验收时连同截图一起定。

=== Task 7 评审结论：通过（8 条发现，只有 2 条够格当场修）===
评审按用户方针给每条发现都附了「够不够格当场修」的判断，而不只是严重度。
  七道闸门它用 `git archive 003807b` 导出到仓库外 + **三个全新 CARGO_TARGET_DIR**
  （测试一个、clippy 一个、windows 交叉一个）全部复跑，444/18 全对；
  **基线也独立复跑过**（fb34896 另一个副本另一个 target）415/18，增量 +29 对上。
  变异表 26 条抽 20 条重做，**条条相符、无一虚报**，连「不会红」的四条也诚实。

它独立重扫 rmc-core 确认**没有第九处**，并把剩余命中分成四类说清为什么不上屏
  （默认域名、`{gateway}` 占位符渲染出来是地址值、手写 Debug 的字段名、
  `#[cfg(test)]` 门住的 test_support）。还顺手扫了 rmc-win——
  **它目前没有任何用户可见文案**，所以扫描只覆盖 rmc-core 现在不漏。

四类埋点逐个实测，结果有信息量：`#[error]` 变体埋违规 → 三条防线一起红；
  **构造点 format! 埋违规 → 只有源码扫描抓得到**；审计行 → 同样只有源码扫描；
  **新增一个带 Gateway 文案的 Error 变体 → 编译期 E0004，绕不过去**。

--- 裁决 ---

Ruling W130（**当场修，已做，commit 0663ae3**）：禁用词源码扫描
  **对多行续行字面量整段失明**。原先逐物理行切词，跨行字面量第一行的引号
  永远等不到闭合，整条被丢掉且一声不响。
  **这不是假想**——rmc-core 生产代码已经在用这种写法写用户可见文案：
  `knownhosts.rs:388/398` 的 `corrupt(format!(..))` 经 Error 进
  `State::Failed{message}` 上状态卡；`supervisor.rs:1340` 的审计行经 Task 11 上屏。
  评审实测把禁用词埋进那条真实续行，**八条防线一条没响**。
  我加了 `join_continuations` 并两头对照：埋在续行第二行的「网关」现在变红
  **并报出拼好的整句**；把切词退回逐物理行，同一个埋点全绿。
  够格的理由（评审给的，我认同）：它落在方针点名的「脚手架」那一类，
  失败模式是**静默**——豁免表被撑大至少在 diff 里看得见，这一条不会；
  而现存代码风格已经会踩，晚修的代价是 Task 8-11 期间新写的多行文案全程无人守。

Ruling W131（**当场修，已做**，且我第一版改过头、被既有测试当场纠正）：
  `elapsed()` 在 Backoff/Failed 下继续计时，与它自己的文档不符。
  `connected_since` 只在 Idle 清（对的，断线重连不该从零重来），
  但 `elapsed` 无条件返回，于是 Task 8 照文档直接画就会在「连接失败」的
  卡片旁边显示一个还在往上涨的「已连接 00:01:30」。
  **我第一版守卫写成只认 Connected，当场打红了
  `stopping_keeps_showing_what_is_still_open_until_idle`**——那条测试编码的是
  实现者 W129 的**刻意选择**。正在停止时隧道确实还在、远程会话可能真的还开着，
  说「已连接」不是假话；假话是 Backoff（已经断了）与 Failed（根本没连上）。
  守卫据此放宽到 `Connected { .. } | Stopping`。
  **这是这一路上第一次「既有测试拦住了我这个裁决者改过头」**，值得记。
  变异验证：删掉状态守卫 → Backoff 那格当场红并打印 Some("00:01:30")。

Ruling W132（评审新找到的第五处同形状，与另外四处一并进后续完善）：
  `Failed` 的标题「连接失败」改成「出错了」全绿。
  连同实现者自报的四处（五条状态副标题整句换掉、ALL_STEPS 顺序打乱、
  Error::Tcp 文案整句换掉）——**评审的判断很中肯**：这些副标题现在被守着的是
  「非空 + 无禁用词」两条，**这两条本身是真钉子**（实测都会红），
  所以不是「断言空转」，只是「文字未被当契约」。纯文案，晚修不变贵。

Ruling W133（不修，评审同意实现者）：豁免表可以被撑大（实测加一条就能放过
  tls.rs 的真违规）。但那要一次**带理由字符串、在 diff 里明晃晃可见**的故意行为。
  另确认「豁免条目过期」那一侧是守住的：把 config.rs:27 的默认域名改掉 → 红。

Ruling W134（不修，记录）：扫描面塌缩的下限断言偏松——`wording.rs:331` 断言
  `lits.len() > 100`，实际 176。评审把结果截断到 120 条并同时埋一个真违规
  → **全绿**。也就是「扫描器瞎掉一半」兜不住（锚点断言只兜得住「整个瞎了」）。
  低后果且要人为制造。

Ruling W135（记录，评审抓到报告一处措辞不准）：报告说 deny「仍有那条既有的
  duplicate 警告」，**实际有 25 条**。评审把 base 与 head 的警告集合 diff 过、
  **逐字相同**，全是既有的。属措辞不准，不是隐瞒。

Ruling W136（带进 Task 11）：`supervisor.rs:866/1376` 那两行审计文案的**上屏路径
  未经验证**——Task 11 的日志页还没写，不知道会不会原样渲染审计行。
  若不会渲染，那两处是多改的（无害）。Task 11 接线时确认。

Ruling W137（带进 Task 9）：`ALL_STEPS` 的顺序没人守。`preflight.rs` 的宏文档
  承诺「按声明顺序 == run() 产出顺序」，评审核对过 `run()` 的 push 顺序
  **今天确实一致**，但打乱声明顺序全绿。Task 9 真按它排版时补一条断言。

=== Task 7: complete ===
提交链：003807b（实现，五条裁决全落地 + 它自己多找出三处违反）
  → 0663ae3（收口两条，我自己做的：W130 续行盲区、W131 elapsed 守卫）。
最终状态：**445 passed / 18 ignored**，七道闸门全绿零告警，无新依赖包。

下一步：Task 8（维护页，530 行——全计划最大的一个）。

=== Task 8 派发前预检（维护页，530 行，全计划最大的一个）===
先核两件事实：
  - **`Zeroizing` 的 `Debug` 是转发的**（zeroize-1.9.0/src/lib.rs:602
    `#[derive(Debug, Default, Eq, PartialEq)] #[repr(transparent)]
    pub struct Zeroizing<Z>(Z)`）——所以 `#[derive(Debug)]` 在 `Form` 上
    会把口令**原样打全**。brief 的 Form 只 derive 了 `Clone, Default`，
    于是那条 `debug_output_redacts_the_password` **压根编译不过**，
    除非手写 Debug。
  - **rmc-core 的权威校验只有两条规则**（config.rs:50-60 的 validate_addresses）：
    `appliance == gateway` 与 `appliance.is_loopback()`。
    而且它的文案**已经是「运维服务器」**——Task 7 的 W125 落地了。

W138（必修，**需求违反，这是头一条**）：brief 期望的校验错误文案里带着
  `"Gateway 地址"`（`bad_gateway_host_is_reported` 断言
  `errs.iter().any(|e| e.contains("Gateway 地址"))`）。
  **这是一条会上屏的用户可见字符串，里面是需求明令禁止的词。**
  而 Task 7 建的那道源码扫描**只覆盖 rmc-core**（评审核过 rmc-win
  目前没有任何用户可见文案，所以当时不漏）。
  **Task 8-11 四个任务全是界面文案，rmc-app 从这一轮起成为文案的主产地。**
  处置：把扫描扩到 rmc-app（按 W124 第三类：后面三个任务要在上面加东西的脚手架），
  并改掉这条期望文案。

W139（必修，**同一个缺陷类的第四次**）：
  `validate(&self) -> Result<(HostPort, HostPort), Vec<&'static str>>`
  ——`Vec<&'static str>` **说不出是哪个字段错了**，而维护页要做的正是
  「把出错的那个输入框标红」。
  前三次：Task 2 的 `resolve()`（不走代理 vs 解析失败）、
  Task 3 的 `next_token()`（协商成功结束 vs 失败结束）、
  Task 4 的 `load()`（没记住 vs 解不开）。三次的解法都是**带类型的出口**。
  这一次要带**字段身份**（哪个框）+ 原因。
  按 W124：这是跨任务契约（视图直接消费它、下游消费者现在是零），当场修。

W140（必修，**两份真相**）：`loopback_appliance_is_rejected` 让 Form 自己
  重新实现 rmc-core 已有的语义校验。`ValidatedAddresses::validate` 是公开的、
  是 Supervisor 处理 `Command::Start` 的**唯一入口**（R10 特意把「校验通过」
  做成拿到值本身的前提）。
  Form 自己写一份的后果有两层：一是两份规则会漂移；
  二是**重写就会把刚被 W125 清掉的那个词重新写回去**——
  rmc-core 现在的原话是「一体机地址不能与**运维服务器**地址相同」。
  处置：Form 只做**格式解析**（字符串 → HostPort），语义校验**调用**
  `ValidatedAddresses::validate`，把它的错误映射到字段上。

W141（必修，与 rmc-core 第 17 个假绿同族）：
  `debug_output_redacts_the_password` 的金丝雀是 `"pw"`——**两个字符**。
  rmc-core 栽过的那次是：断言本身是对的、泄漏确实发生了、事件确实被捕获了，
  但 `&[u8]` 的 Debug 渲染成十进制数组，ASCII 子串匹配根本认不出来。
  要求：手写 `Debug`（`Zeroizing` 转发，derive 会打全）、
  金丝雀换成一个**不会偶然出现**的独特串、
  并做变异验证（把手写 Debug 换成 derive 必须变红）。

W142（必修，顺手）：`all_errors_are_reported_at_once` 断言
  `unwrap_err().len() >= 3`——**只数个数、不看是不是那三条**。
  返回十条无关错误也能过。W139 落地之后这条改起来是顺手的。

W143（必修，Task 6 的教训）：接口清单里 `view::maintain::view` **零测试**。
  Task 6 已经证明 `iced_test` 能断言控件树，而且证明了
  **「值被测过」不等于「视图真的用了它」**（那一轮实测 main() 可以挂一棵
  字面画着 Gateway 的树而 21 条测试全绿）。
  维护页是密码框、地址框、按钮的所在地，必须有 ui 测试，且至少覆盖：
  Task 7 的 `credentials_visible` / `editable()` **真的被视图遵守**
  （不是「Model 算对了」而是「框真的藏了/锁了」）；整棵树的禁用词扫描。

Ruling W144（**纪律订正，这条是我的责任，从 Task 9 起写进每一份派发**）：
  这台机器上**没有 `timeout` 也没有 `gtimeout`**（我刚亲自确认：
  `which timeout gtimeout` 两个都是 not found）。
  而我在前八份派发里每一份都写着「给每次 `cargo test` 加超时」——
  **等于让每个实现者自己去发明一个超时机制**。
  Task 8 的实现者第一条命令因此失败，**它的宿主 zsh 变成一个 99.7% CPU 的
  孤儿，跑了 41 分钟才被发现并杀掉**。
  这是本项目**第二次**孤儿进程事故（第一次是 16 个进程占 930% 跑了 11 分钟），
  **两次同一个成因**：清理/超时机制没有真的可用，而命令在它生效之前就死了。

  **从此派发里给出可用的写法，不再只说「加超时」**：
    perl -e 'alarm shift; exec @ARGV' 900 cargo test -p rmc-app
  并且 `trap '...' EXIT INT TERM` 要写在**包装脚本内部**，
  不能指望外层 shell 被杀之后还能执行到。

Task 8: 实现完成 4b1fdb9。**490 passed / 18 ignored**（基线 445/18，+45）；
  rmc-app 从 lib 41 + ui 6 长到 **lib 70 + ui 18 + wording 3**。七道闸门全绿。
  六条裁决（W138-W143）全部落地。评审已派发。

实现者自报的六条（去掉上面那条纪律）：

  - **「填错的框标红」这条连线它没能让它变红**，自己报了出来。
    把 `input_border(invalid)` 改成 `input_border(false && invalid)`
    （填错的框永远不标红）——**一条测试都没响**。
    两端各自有测试守着（`Form::is_marked` 有单测、`theme::input_border`
    有表驱动），**断的是中间那一个表达式**。
    差分快照也救不了：`visible_errors` 同时驱动红框和红字，
    构造不出「只差边框」的两帧。同类的还有整页顺序倒过来、
    spacing/padding/align 全归零，都是零测试变红。
    **这是 Task 6 那个教训的下一层**：Task 6 解决的是「main() 有没有用上
    被测过的值」，这一条是「视图内部两个都被测过的东西之间的那根线」。

  - **它改了 brief 的一处页面结构，理由是可测性**：brief 让
    `credentials_visible` 为假时把**地址行一起藏掉**，那样「地址框真的锁了」
    就永远观察不到（框根本不在树里），W143 那一半没法验。
    改成地址两行任何状态都画、只有 `on_input` 跟着 `addresses_editable()` 走。
    它核过画板 `body-Connected.html` 的「链路」卡片确实把地址画出来了，
    所以判为顺带也对——但它明说「这是我的判断，不是 brief 的」。

  - **它把 `validate` 的成功侧从 `(HostPort, HostPort)` 收紧成了
    `ValidatedAddresses`**。下游消费者现在是零、改的成本是零，
    而 Task 10 的 Supervisor 要的正是它。偏离了 brief 写死的接口清单。

  - `Form::default()` 是全空的，不是画板上那几个示例地址。理由：真正的初始值
    该由 Task 10 从配置载入；把 `gateway.company.com` 搬进 rmc-app
    会把 rmc-core 那条豁免一起复制过来。**若产品希望首次打开就有占位地址，
    这是要回头改的一处。**

  - **口令在进程内存里仍有一份它管不到的副本**：iced `TextInput` 内部的
    `text_input::Value` 按字素存 `String`，`Zeroizing` 伸不进去。
    另外 `iced_test` 的 `Candidate::TextInput::state.text()` 返回的是**原始值**
    （遮蔽发生在绘制那一步），所以控件树那条禁用词扫描的失败信息里
    理论上可能带出口令片段——**测试期的事，不是生产泄漏**，但备案了。

  - **W138 的扫描器它选了「提到 rmc-core 生产代码、共用一份」**，
    代价是三个只有测试会用、会读文件系统的 `pub` 符号进了生产 crate
    （链接器会从 exe 里丢掉，但 rlib 的 API 面积变大了）。
    换来的是上一轮刚修的续行盲区不用修两遍。
    另一条路（在 rmc-app 里照抄一份）它否掉了，理由是 feature gate
    在 workspace 内部不成立（resolver 2 会统一 feature）。

Ruling W145（**纪律再订正——W144 那条药方本身造成了第三次事故，成因是我**）：
  Task 8 的评审照我 W144 写的「`trap '...' EXIT INT TERM` 要写在包装脚本内部」
  办，写成 `trap 'kill 0' EXIT INT TERM`。**`kill 0` 在 EXIT trap 里会把信号
  发给包含它自己的进程组**，于是那个 zsh 就地空转到 97.9%，ppid=1，
  跑了 14 分 37 秒。**本项目第三次孤儿事故，而成因恰恰是第二次事故开出的药方。**

  评审自己诊断清楚了：**成因不是缺超时**——
  `perl -e 'alarm shift; exec @ARGV' 1500 cargo test …` 每一次都正常工作，
  那次的 cargo 子进程其实干干净净跑完了（日志尾部 EXIT=0）。
  它把 trap 删掉之后，其后约 25 次运行（全部变异、闸门、release 构建、
  feature 实验）**一个残留都没有**。

  **定稿的纪律（从 Task 9 起每份派发照抄这一段）**：
    perl -e 'alarm shift; exec @ARGV' 900 cargo test -p rmc-app
  `perl` 的 `exec` 保证子进程就是那个 shell 本身、alarm 到点会把它一起带走，
  **不需要额外清理**。**不要再建议配 trap，明确禁止 `kill 0`**；
  真要清理只能 kill 明确记下的子 PID。
  收尾自查：`ps -eo pid,ppid,pcpu,etime,comm | awk '$2==1 && $3>20'`。

=== Task 8 评审结论：通过（8 条发现，2 条够格当场修）===
评审七道闸门在**仓库外 git archive 副本 + 四个全新 CARGO_TARGET_DIR** 复跑全绿，
  **基线 0663ae3 也独立复跑**（另一副本另一 target）445/18，+45 精确对上。
  Cargo.lock 只在 rmc-app 的 deps 列表加了一行 zeroize、**无新 [[package]]**。
  19 格变异表它重做 **18 格，条条相符、无一虚报无一漏报**，
  连三条「改什么都不会红」都诚实自报。

--- 两条够格当场修 ---

Ruling W146（**评审推翻了实现者的「做不到」，并写出 PoC 跑通**）：
  实现者说「填错的框标红」那条连线救不了，因为 `visible_errors` 同时驱动
  红框和红字、构造不出「只差边框」的两帧。
  **评审判它一半对一半错**：「`iced_test` 够不着边框颜色」**对**
  （它读了 iced_selector-0.14.0/src/target.rs:160-198，`Candidate` 六个变体
  只带 id/bounds/visible_bounds/content/state，样式颜色边框一个字段都没有）；
  但「差分快照救不了」**只对整页成立，作为一般结论错**。

  **第三条路（评审写了 PoC 并跑通）**：诀窍是 `Reason::Rejected`——
  它挂在 `Field::ApplianceHost` 上，但触发条件是**一体机与运维服务器这对地址
  的关系**，跟一体机那两个框里的字一个都不沾。于是能造出两份表单，
  一体机行的文字**逐字相同**、只有 `is_marked(ApplianceHost)` 不同：
    clean:  appliance 192.168.100.10:61001, server ops.example.com:443 → 合法
    marked: appliance 192.168.100.10:61001, server 192.168.100.10:61001
            → rmc-core 拒「一体机地址不能与运维服务器地址相同」→ 标红，
              **而一体机那两个框里的字一个都没变**
  再把**一体机那一行单独**（私有的 `addr_row`）喂给 simulator 而不是整页——
  两帧的唯一差别就只剩边框颜色。
  实测：未变异通过、反向自证通过；加上 `input_border(false && invalid)`
  → **PoC 红且只有它红，既有 18 条 ui 全绿**；负对照（同样两份表单走整页）
  变不变异两帧都不同，证实它「整页做不到」那一半成立。
  边框真会画：iced_widget-0.14.2/src/text_input.rs:1763-1767 默认 border.width = 1.0。
  成本约 30 行、零公开 API 变化、零新依赖。
  **够格的理由不是 N1 本身的严重度**（那确实偏观感），而是三条合起来：
  实现者给出的「做不到」是错的；**这个技法正是 Task 9-11 三页样式接线要复用的
  脚手架**，晚三个任务再立那三页的样式接线全程无人守；代价 30 行。

Ruling W147（**评审新找到的洞，与实现者自己刚补掉的两条同形状**）：
  **删掉「次按钮」整块渲染（maintain.rs:315-323），一条测试都不响。**
  `State::Backoff` 下 `Model::buttons()` 给的是 primary=「立即重试」/
  **secondary=「停止远程维护」**——**那是现场人员从重连循环里脱身的唯一出口**。
  没有任何 ui 测试点过次按钮。实测整块删掉 → workspace 0 failed。
  这跟实现者自己发现并补掉的 N4/N5（没人点过的勾选框）是**同一个形状**，
  它补了勾选框、漏了这个。

--- 评审推翻的两条技术论断（都已写进账本当既定理由，Task 9-11 会照着判）---

Ruling W148（**feature gate 那条理由不成立，评审实测了**）：实现者否掉
  「在 rmc-app 里照抄一份扫描器」时说「feature gate 在 workspace 内部不成立
  （resolver 2 会统一 feature）」。评审给 rmc-core 加了一个带
  `compile_error!` 的探针 feature、让 rmc-app 的 **dev-dependencies** 打开它：
    cargo build -p rmc-app      → EXIT=0（feature 关着）
    cargo build --workspace     → EXIT=0（feature 关着）
    cargo test -p rmc-app --no-run → error: PROBE（feature 开着）
  **这正是 resolver 2 承诺的：dev-dependency 的 feature 不会被统一进非测试构建。**
  所以选项 3 可行，而且**它不是选项 1 的替代，是选项 1 再加一道门**——
  既保住「只有一份扫描器」，又把那三个 pub 符号从生产 API 面积里拿掉。
  **不够格当场修**（改成 feature gate 今天和三个任务之后一样贵），
  但那段错误论断要在下一次动 wording.rs 时顺手订正。
  顺带评审**量了而不是推理**：release exe 6,357,968 字节，
  `nm -C` 与 `strings` grep 那几个符号 → **0 命中**；
  同样 grep 打在 librmc_core rlib 上 → 2 命中。rlib 有、exe 没有，属实。

Ruling W149（**实现者那条口令备案是事实错误，方向是高估风险**）：
  它自承「`Candidate::TextInput::state.text()` 返回原始值，所以禁用词扫描的
  失败信息里可能带出口令片段」。**评审实测：返回的是 `••••••••••`。**
  遮蔽发生在 **paragraph 被写入之前**（text_input.rs:328/407/462 先算
  `secure_value = is_secure.then(|| value.secure())`，进到 State 的就是遮蔽后
  那份，而 `operation::TextInput::text()` 读的正是它）。
  **那条风险不存在，备案撤销。**
  但另一条自承**属实而且它说轻了**：iced 的 `text_input::Value` 是
  `Vec<String>`（每个字素一个堆 String）、`#[derive(Debug, Clone)]`、不带 zeroize，
  widget 每次 view() 重建一次用完即扔且不抹，`.secure(true)` 再额外分配一份——
  **不是「内存里残留一份」，是每渲染一帧 churn 一整套。**

Ruling W150（记录，评审发现的第三处未报偏离）：brief 的 `Message` 含 `Tick`，
  实现是 10 个变体、**全 crate grep 不到任何 Tick**。后果是「已连接 HH:MM:SS」
  不会自己走字（没有 Subscription，那是 Task 10）。丢掉本身可辩护
  （留着就是死代码），**没写进偏离清单不该**。**Task 10 必须补回。**

Ruling W151（记录，不修）：`Field::Username` / `Field::Password`
  **结构上永远不可能被标红**——`validate` 只会给它们 `Reason::Empty`，
  而 `visible_errors` 把 `Empty` 过滤掉，于是那两处 `is_marked(...)` 是恒 false
  的死参数。设计上自洽（空框不糊红字），但没有测试把「这是刻意的」钉成契约。

Ruling W152（记录，带进 Task 10）：`detected_proxy` 本轮无人写入、
  「出网」恒为「直连」，而画板画的是「经系统代理 proxy.company.com:8080」。
  与 `ActionPressed` 一样是等 Task 10 的悬空数据，但实现者的后续完善清单
  列了 ActionPressed、**没列这一条**。

Ruling W153（范围外，快到了）：`rmc_core::wording` 的切词器仍不认
  `r#"..."#` 与 `'"'`（文档写明了）。今天 workspace 里两者都没有，
  锚点断言守着。**Task 9-11 写 raw string 文案之前要先补切词器。**

Ruling W154（记录，工具链陷阱，与 W39/W72 同族）：评审实测 M12 时发现，
  照报告那样直接把 `App::view` 的分支换成 `space::vertical()` 会 `E0283`
  编译不过，**要加类型标注才跑得起来**。已向评审索要可跑的写法。

Ruling W155（订正我自己的一个动作）：我根据评审第一版报告里「scratchpad 有 5.0G
  前几轮中间产物」的说法清了一批目录。**评审随后纠正：那个 5.0G 是它在
  `rm -rf` 刚发出、APFS 还没落完时量的**，前几轮实际只有约 22MB。
  我删掉的那批（tgt-gates / tgt-base 各 2.2G 等）是**它自己那一轮正在清理的**，
  清理时它已经交回、处于空闲，随后重跑一切正常，无损失。
  教训：**别拿一个正在变化的量当依据**——`du` 与 `rm -rf` 并发时读到的是中间态。

Ruling W156（记录，工具链陷阱，与 W39/W72/W154 同族）：变异注入的锚点
  **可能撞上你自己刚写的文档注释**。我复跑红框那一枪时，
  `input_border(invalid)` 在 maintain.rs 里命中 2 次——生产代码 :78 与
  我新写的测试文档 :377。**断言拦住了**（没注入就没有结论），
  换成带缩进的精确锚点 `"                color: input_border(invalid),"` 才对。
  没有那句 `assert s.count(old) == 1` 的话，这一枪会安静地不注入、
  然后报一个「全绿」的假结论。

=== Task 8: complete ===
提交链：4b1fdb9（实现，六条裁决全落地 + 它自己补掉两条没人点过的控件）
  → 54aa6ab（收口三条，我自己做的：W146 红框可观测、W147 止损按钮、
    外加口令遮蔽的 paragraph 层断言）。
最终状态：**494 passed / 18 ignored**（基线 445/18，+49），
  rmc-app 从 lib 41 + ui 6 长到 **lib 72 + ui 20 + wording 3**。
  七道闸门全绿零告警，无新依赖包。

三枪我自己复跑，各只红对应的那一条：
  input_border(false && invalid) → 「标红的框跟正常框画出来逐字节相同」
  删掉次按钮整块                 → SelectorNotFound "停止远程维护"
  .secure(true) → false          → paragraph 层与像素层两条同时红

**W146 那个技法要带进 Task 9-11 的每一份派发**（三页都要接样式）：
  「样式在 iced_test 这一层不可观测」不等于「不可测」。两步——
  一、找一个**让样式变化与文本变化解耦**的输入组合；
  二、把渲染范围缩到**能单独渲染的最小子元素**，而不是整页。
  代价是那个子元素得从本模块的测试里够得到，所以这类测试住在
  `view/<page>.rs` 自己的 mod tests 里，而不是 tests/ui.rs。

下一步：Task 9（诊断页与诊断包导出，327 行）。带进去的裁决有 7 条——
  W38（完整十格映射）、W43（不得轮询 effective_proxy）、W54（连接边界）、
  W55（文案矛盾）、W137（ALL_STEPS 顺序）、W146（样式可观测技法）、
  W153（切词器不认 raw string，写 raw 文案前要先补）。

=== Task 9 派发前预检（诊断页与诊断包导出，带 7 条历史裁决进场）===

W157（**必修，头一条，这是整个产品安全面最要紧的一个测试**）：
  brief 的 `bundle_creates_a_zip_containing_the_report` **只断言三件事**：
  `zip.exists()`、`extension == "zip"`、`len() > 0`。
  **它从头到尾没有打开过那个 zip。**
  而**诊断包是这个产品里唯一会离开这台机器的东西**——W36 当初要把
  `next_token` 的返回改成 `Zeroizing<String>`，给出的全部理由就是
  「真正让它值得堵的是 Task 9 要做**诊断包导出**：哪天有人往包里加进程
  内存快照，这两个 String 就是现成的凭据派生物」。
  现在那个任务到了，而它的测试连包里有什么都不看。
  形状上它同时是 W22 那一族（空转）：生成一个**空 zip** 也能过全部三条。
  要求：
  - 打开 zip、逐条目断言内容；
  - **把一个独特的金丝雀口令与账号灌进 bundle 能看到的每一个来源**，
    然后断言**任何一个条目的字节里都不出现它**（不是只查文件名）；
  - **反向自证**：断言包里确实有该有的东西，否则空包也能过；
  - 变异验证：把脱敏那一步去掉必须变红。

W158（**必修，结构性——不然 W38 会落进测不了的那一层**）：
  **`rmc-win` 是 rmc-app 的 `cfg(windows)` 专属依赖**（Cargo.toml:67-70）。
  于是 W38 要求的那张「CONNECT 结果 × `last_outcome()`」**完整十格映射**
  在 macOS 上根本够不着 `AuthOutcome`——写出来就会落在
  `#[cfg(windows)]` 里，而那一层**闸门 5 是 build、6 是 clippy，都不跑测试**，
  Task 5 已经用八枪实测过「任何还能编译的语义改动按构造检测不到」。
  处置：诊断页消费一个**平台中立的摘要类型**（放 rmc-app 或 rmc-core），
  由 rmc-win 负责把 `AuthOutcome` 映射进去。
  这样十格映射住在 macOS 能跑的那一层，而 rmc-win 那边只剩一次转抄。

W159（**必修，同一个缺陷类的第五次**）：
  - `advice_for(&PreflightReport) -> Option<(String, String)>`：
    两个裸 String 的元组**说不出哪个是标题哪个是建议**，
    而 `Option` 又把「没有失败项」与「有失败项但给不出建议」压平。
  - `rows(report, proxy: Option<&str>, host_key: Option<&(String, bool)>)`：
    `Option<&(String, bool)>` 是元组套 Option，读的人无从知道那个 bool 是什么。
  前四次：Task 2 的 `resolve()`、Task 3 的 `next_token()`、
  Task 4 的 `load()`、Task 8 的 `validate()`。四次的解法都是**带类型的出口**。

W160（必修，落实 W43）：**诊断页不得调用 `Transport::effective_proxy`**
  ——它会在协商途中改写 `ProxyEndpointRecorder` 且**无测试会红**。
  brief 的 `rows(..., proxy: Option<&str>, ...)` 收的是一个已经取好的值，
  形状上是对的（不是自己去查），但**要把这条写进函数文档**，
  并确认 Task 10 接线时不会违反。

W161（必修，落实 W137）：`ALL_STEPS` 的顺序没人守
  ——`preflight.rs` 的宏文档承诺「按声明顺序 == `run()` 产出顺序」，
  Task 7 的评审核对过今天确实一致，但**打乱声明顺序全绿**。
  **Task 9 正是按它排版的地方**，在这里补上断言。

W162（提醒，落实 W153）：`rmc_core::wording` 的切词器**不认 `r#"..."#`**
  （文档写明了，今天 workspace 里没有 raw string 所以不漏）。
  诊断页的处置建议文案**很可能想用 raw string**。
  要么先补切词器，要么明确不用 raw string——**两者都行，但不能默默用了**，
  那会让禁用词扫描对那段文案整段失明（与 W130 的续行盲区同一形状）。

W163（记录，依赖，**我已实测，不是政策事件**）：brief 要加
  `zip = { version = "2", default-features = false, features = ["deflate"] }`。
  我建了临时工程实测：解析出 25 个包，但**对本工作区真正新增只有两个**
  ——`zip` 与 `displaydoc`（其余 flate2/crc32fast/indexmap/thiserror/syn
  等本来就在锁里）。用本仓库的 deny.toml 跑，**licenses ok、advisories ok**。
  实现者照加即可，但要把四项 deny 的实际输出贴进报告。

W164（必修，落实 W55）：`http_connect` 抛的错误文案是
  「代理要求 Negotiate，**本机无法协商**」，而 SSPI 那边的诊断行说的是
  「凭据格式没问题，**是代理不接受当前用户**」——**两句互相矛盾**，
  而 W45 落地后这个矛盾从罕见变成了最常见的形状。
  **Task 9 是这两句相遇的地方**，在这里定哪句对、另一句怎么改。

Task 9: 实现完成 6dd37cd。**529 passed / 18 ignored**（基线 494/18，+35）；
  rmc-app lib 96 / ui 26 / wording 4，rmc-core lib 221，rmc-win 136。
  七道闸门全绿零告警，deny 四项全 ok。**16 个文件 +3095/−182，动了 rmc-core 与 rmc-win。**
  孤儿自查干净，全程用 perl alarm、没配 trap、没用 kill 0。评审已派发。

变异 25 枪、19 红 6 不红。W157 那四枪（三个写入点各绕过一次脱敏 +
  把 apply 写成 String::new()）全部实测红，**第四枪打红的是反向自证那三条**
  ——证明「空包也能过」这个形状确实被堵住了。

**订正我一个数（W163）**：我写「zip 对本工作区真正新增只有两个包」。
  它核出**不对**：Cargo.lock 新增 5 条，其中 arbitrary/derive_arbitrary
  在 zip 的 `cfg(fuzzing)` 下（zip-2.4.2/Cargo.toml:254）永不编译；
  **真正会编译的新包是三个——zip、displaydoc、`zopfli`**（被 deflate
  feature 拉进来，我漏了）。deny 四项仍全 ok。

W164 它定的是：**诊断行那一句对，`http_connect` 那一句改掉**。
  理由不是语气而是**谁知道真相**——`AuthOutcome` 分得清十种结局，
  而 `http_connect` 在那一行手上只有一个 `None`，**结构上说不出原因**。
  新文案只陈述事实并把原因指给诊断页那一行，两个 crate 各一条测试
  守这条指路不成死指针。

--- 它自报的五条疑虑 ---

  1. **它删掉了 Task 3 交付过的 `AuthOutcome::diagnostic()`。** 那张十格表
     整个搬到 rmc-core 并加了 W38 要的第二根轴（**十格变二十格**），
     rmc-win 侧换成转抄测试，它说 rmc-win 测试数不变、覆盖只增不减。
     **但这动了别的任务交付过的代码**，交评审核实
     （尤其 `declare_auth_outcome!` 那个「加变体不进表编译不过」的保证还在不在）。
     它给的替代方案：保留并转调 `summary().line(...)`，
     代价是多一个零生产调用方的公开方法。

  2. **一处真盲区它没堵并如实报了**：`diag_line` 把「行首文字」与「说明」
     **画反**，N7 实测**一条都不红**——两者都是 `Candidate::Text`，
     只有字号与上下顺序不同，`iced_test` 两样都看不见。
     按用户门槛（低后果覆盖缺口不做）记进了后续完善，但它指出
     **这是「语义画反而全绿」那一族，跟项目抓到的 20 个假绿同形**。
     它说要堵需要给 tests/ui.rs 写一个按 `bounds` 收集全部文本的收集器
     （`Simulator::find` 只返回第一个命中，够不着）。
     **已让评审试第三条路**——上一轮它的前任在同一类问题上找到过。

  3. **诊断包没有任何大小上限。** 日志目录里有个 500MB 的 rmc-*.log 时，
     bundle 会整个读进内存再脱敏再写。是健壮性缺口不是视觉打磨，
     但**轮转策略要 Task 11 才定**，这一轮没有合适的数可钉。

  4. **它对 W157 的自我评估很克制，值得记**：那条测试证明的是
     **「登记过的东西抹掉了」，不是「包里没有凭据」**。后者它写不出测试
     （要能认出任意凭据）。**测试名刻意叫 `carries_the_canary_password_or_account`，
     不是 `carries_no_credentials`。**

  5. **W160 的源码扫描只看 `src/`、`tests/` 不扫**，所以 Task 10 若把
     `effective_proxy` 写进集成测试这道闸门看不见。它判断「那条纪律针对的是
     每重画一帧查一次，测试里调不构成同一危害」，但**明说这个判断不确定**。
     已让评审给结论。

  另两处**预测失误，错在安全的一侧**：N4（Undecided 换成正文色）
  与 N5（日志条目不放 logs/ 子目录）它预测不会红、实测都红了。

Task 10 接线要做的三件（它写进报告了）：把 `Form::password`/`username`
  登记进 `Redaction`；接上 `%LOCALAPPDATA%\rmc\`（W28 那个落点）；
  `Model.proxy` 本轮无人写入，诊断页那三行在真实运行里一行都不会出现
  （与 W152 的 `detected_proxy` 同类悬空数据）。

=== Task 9 评审结论：通过（10 条发现，1 条够格当场修）===
评审七道闸门在仓库外副本 + 全新 CARGO_TARGET_DIR 复跑全绿零告警，
  **基线也独立复跑** 494/18，+35 逐目标对账：rmc-app lib 72→96、ui 20→26、
  wording 3→4、rmc-core lib 217→221、**rmc-win 136→136（删一条加一条）**，
  全 crate 函数名 diff 只有一个被替换。**25 枪变异全部重做，条条相符、
  连打红的测试名与条数都对得上，无一虚报无一漏报。**
  七条本轮裁决 + 六条历史债（W38/W43/W55/W137/W146/W153）**全部 ✅**。

Ruling W165（**评审第二次推翻实现者的「做不到」，而且前提本身是错的**）：
  实现者判「两段文字画反了」守不住，理由是「都是 Candidate::Text、
  只有字号与上下顺序不同，iced_test 两样都看不见；要堵得写一个按 bounds
  收集全部文本的收集器，因为 Simulator::find 只返回第一个命中」。
  **前提错在**：`iced_selector` 的 `&str` 选择器按**内容整段相等**匹配
  （iced_selector-0.14.0/src/lib.rs:53-83），只要两段文字本身不同，
  两次 find 就分别拿得到各自那一个候选；而 `target::Text::bounds()`
  （target.rs:266-272）直接给出 Rectangle。**不需要收集器。**
  差分快照在这里反而够不着——颜色那条用的是每次现建的临时基线，
  画反之后基线与对照帧**一起变**，恒为真。
  我已落地（commit 92a61f2），两枪各红一条且各打在不同断言上：
  整个画反 → 报位置（name.y 24.9 > detail.y 7.0）；
  只对调字号 → 报字号（height 15.6 < 16.9）。

  **这条与 W146 并列成第二个技法，Task 10/11 的派发都要带**：
  **`iced_test` 看不到样式，但看得到位置与尺寸。**
  凡是「谁在上、谁更大、谁更宽」这类版面语义都能用 bounds 钉住，
  不必等一个收集器。

Ruling W166（**当场修，已做**）：W157 那条测试里「条目名也脱敏了」
  **是一条空转断言**——代码对条目名过了一次 `apply`、测试也断言了
  条目名不含金丝雀，但**没有任何来源把金丝雀灌进文件名**。
  评审实测把 `apply(name)` 换回 `name` **一条都不红**。
  我补了一份按账号命名的日志（出问题时按人找日志是常见形状），
  补的时候那条精确条目清单断言**当场拦住了新条目**，
  并顺带证明脱敏确实在工作（新条目进包时叫 `logs/rmc-[已脱敏].log`）。
  变异复跑：去掉条目名脱敏 → 当场红。
  够格的理由不是威胁大，是**它出现在本任务唯一的安全断言里，
  而这条测试是后面每一轮都要照抄的样板——空转断言留着会被继承**。

评审自己加了两枪本该有人做的（实现者没做）：
  - **X1 往包里塞一个没登记的新条目** → 红 3 条。逮住它的**不是字节扫描，
    是那条精确等值的条目清单断言**——意味着这条测试比实现者自己声称的
    更强：**新增任何一个条目都过不去**。
  - **X2 在已登记条目里、脱敏内容之后再追加一份原文**（条目名一字未变）
    → 红 1 条，逮住它的是逐条目解压之后的字节扫描。

**它对实现者那句自我评估的裁定值得记**：「证明的是『登记过的东西抹掉了』，
  不是『包里没有凭据』」——评审判**准，而且是这份报告里最有价值的一句**，
  并补全了边界：它证明不了的是「一段谁也没登记、也不带 Authorization 字样的
  密文会原样进包，而这条测试连知道都不知道」。测试名如实反映了边界，没有虚报。

**删掉 AuthOutcome::diagnostic() 判为值得**，两端编译期保证都还在：
  P4（加变体不动 summary）→ E0004；P7（加变体并处理、只不动测试表）→ E0308；
  P3/P6 对二十格表同样。唯一**故意**丢掉的是「永不 Some(true)」——
  那正是 W38 要推翻的那条（TokenIssued × Established 现在就该是 Pass），
  不是覆盖损失。替代方案（保留转调）评审判不必采纳。

**我那个数它订正对了**：zip 真正会编译的新包是三个——zip、displaydoc、
  **zopfli**（被 `deflate = [... "deflate-zopfli" ...]` 拉进来，我漏了）；
  arbitrary/derive_arbitrary 挂在 `cfg(fuzzing)` 下任何 target 都不编译。

--- 记进后续完善的（评审逐条判「不够格当场修」）---
  F2 「一切正常时不画处置建议卡」有注释承诺、无断言（实测 5 行可补）
  F3 diag.rs 的「改红提示」与实测相反（只有代码注释写错，报告正文是对的）
  F4 rmc-app/Cargo.toml 的注释照抄了我那个错数，漏了 zopfli
  F5 `Model.host_key` 仍是裸 `(String, bool)`（换它要动 rmc-core 的 TunnelEvent）
  F7 `advice_for` 按 rmc-core 的错误**文案**分派（今天三条都命中，但无测试钉住
     这条跨 crate 的字面依赖；W125 那种改名会让它们静静落到 Unrecognized）
  F9 脱敏过程在堆上留未抹除的口令副本（与 W149 的 iced 每帧 churn 同族，量级更小）

Ruling W167（**带进 Task 11**）：F8 诊断包**没有任何大小上限**——
  500MB 的日志会整个读进内存、再脱敏、再写，三份同时在堆上。
  是真实的健壮性缺口不是观感问题，但**轮转策略要 Task 11 才定**，
  这一轮没有合适的数可钉。

Ruling W168（**带进 Task 10 的派发，否则会被当成误报去改闸门**）：
  W160 那道闸门的真正约束是「**rmc-app 的 `src/` 里一次都不能调
  `effective_proxy`**」。于是 Task 10 若想在 rmc-app 侧亲手取一次代理来填
  `Model.proxy`，**会被这道闸门当场拦下**；正确的路是让代理从 rmc-core 一侧
  （预检/Supervisor 已经在 preflight.rs:381 取过）**作为事件送上来**。
  评审同时给了 W160 那个不确定的结论：**判不修**——W43 要堵的危害是
  「界面每重画一帧就查一次」，测试里单独调一次不构成同一危害，
  把 tests/ 纳入扫描反而会挡住将来合法的端到端测试。

Ruling W169（**带进 Task 10 的派发，安全关键**）：
  **`Redaction` 至今没有生产调用方**，所以「把 `Form::password` /
  `Form::username` 登记进去」这件事完全落在 Task 10 身上，
  而**现在没有任何闸门会因为 Task 10 忘了登记而变红**。
  Task 10 必须有一条**从 `Form` 到 zip 字节的端到端测试**。

=== Task 9: complete ===
提交链：6dd37cd（实现，七条裁决 + 六条历史债全落地）
  → 92a61f2（收口两条，我做的：W165 bounds 技法、W166 空转断言补带载）。
最终状态：**530 passed / 18 ignored**（基线 494/18，+36），七道闸门全绿零告警。

下一步：Task 10（日志页与接线，317 行）。**这是真正的收口点**——
  前九个任务做出来的东西到现在**一个都还没接上**。带进去的裁决至少八条：
  W28（%LOCALAPPDATA% 三处落点一次接完）、W54（谁来划连接边界）、
  W82/W94（sys.recv 吞掉 Lagged/Closed）、W93（删错的 feature）、
  W150（Tick 补回）、W152（detected_proxy 悬空）、W168（代理要走事件）、
  W169（Redaction 端到端）。

=== Task 10 派发前预检（日志页与接线——真正的收口点）===

W170（**必修，头一条，而且它自证了 brief 的接线代码从没被编译器看过**）：
  brief 的 `spawn_core` 里那段 SSPI 接线**四处都不对**，我逐条核过真实签名：
  - 真实签名是 `SspiProxyAuthenticator::new(endpoint: Arc<dyn ProxyEndpoint>, factory: F)`
    （sspi.rs:822），**两个参数**；brief 只传了一个闭包。
  - 真实的工厂是 `F: Fn(SspiPackage, &str /*SPN*/) -> Option<Box<dyn SspiContext>>`
    （sspi.rs:820）；brief 写的是 `Fn(&str)`。
  - **brief 写的是 `NegotiateContext::new(&format!("HTTP/{scheme}"))`，
    而那个 `scheme` 是认证方案（"Negotiate" / "NTLM"）——
    这正是 W3 当年花一整轮修掉的那个 bug**，SPN 必须用**代理主机名**。
    Task 3 至今留着一条专门抓它的测试：
    `the_spn_uses_the_proxy_host_not_the_auth_scheme`（sspi.rs:1696）。
    W3 把工厂签名改成收 SPN，正是为了让 `HTTP/{scheme}` **写都写不出来**。
  - **`ProxyEndpointRecorder` 整个缺席**。W3 引入它就是为了让协商器知道
    「这次连接实际要用的那台代理」；brief 直接把 `SystemProxyResolver`
    当 resolver 传进去，协商器无从得知代理是谁。
  **这与 Task 5 是同一个形状**（那次 brief 的 Win32 代码按原样抄进去编译不过，
  两个常量在错的模块里、一处真类型错误）。照抄必错，按真实签名重写。

W171（**必修，结构性，这是同一个坑的第七次**）：`spawn_core` 是
  `#[cfg(windows)]` 与 `#[cfg(not(windows))]` 一对孪生块。
  macOS 上只有 `No*` 那一支会跑，**Windows 那一支只有 build + clippy**——
  而 Task 5 已经用八枪实测过：那一层**任何还能编译的语义改动按构造检测不到**
  （连把 `Box::leak` 换成悬垂栈指针都六道全绿）。
  **而 W169 那件安全关键的事（Redaction 登记）恰恰落在这一支里。**
  处置：把**所有可判定的东西**挤进一个平台中立的函数，两支都调它；
  `cfg` 块里只剩「构造那四个实现」这一层纯搬运。
  形状参照 Task 9 的 W158（把十格映射搬进 rmc-core，rmc-win 只剩转抄）。

W172（**必修，安全关键，落实 W169**）：**`Redaction` 至今零生产调用方。**
  Task 10 要把 `Form::password` / `Form::username` 登记进去，
  而**今天没有任何闸门会因为忘了登记而变红**——诊断包照样导出，
  只是里面带着明文口令。
  要求：**一条从 `Form` 到 zip 字节的端到端测试**。
  Task 9 那条 `no_entry_in_the_bundle_carries_the_canary_password_or_account`
  是现成样板（我刚把它的条目名断言从空转补成带载的）。

W173（**必修，落实 W168——不然会被当成误报去改闸门**）：
  W160 那道闸门的真正约束是「**rmc-app 的 `src/` 里一次都不能调
  `effective_proxy`**」。Task 10 若想在 rmc-app 侧亲手取一次代理来填
  `Model.proxy`，**会被这道闸门当场拦下**。
  **正确的路是让代理从 rmc-core 一侧作为事件送上来**
  （预检/Supervisor 已经在 preflight.rs:381 取过）。
  **看到闸门变红不要去改闸门。**

W174（**必修，同一个缺陷类的第六次**）：
  - `parse_line(raw) -> Option<LogLine>`：把「这行根本不是日志」与
    「是日志但格式坏了」压平。
  - `tail(path, limit) -> Vec<LogLine>`：**静默吞掉 IO 错误**。
    「日志目录读不了」与「还没有日志」在界面上长得一模一样——
    而日志页正是用户在出问题时唯一会去看的地方。
  前五次：Task 2 的 `resolve()`、Task 3 的 `next_token()`、Task 4 的 `load()`、
  Task 8 的 `validate()`、Task 9 的 `advice_for()`。**五次的解法都是带类型的出口。**

W175（**必修**）：`counts(lines) -> [usize; 4]` 是**按位置索引的裸数组**
  ——把「警告」和「错误」两个计数对调，编译照过。
  Task 9 的解法是穷尽映射 + 定长表让「加一格不进表」编译不过，照那个办。

W176（**必修，一次接完，别分几次**）：这一轮到期的接线债：
  - **W28**：`%LOCALAPPDATA%\rmc\` 这个落点要**一次性**给审计日志、
    known_hosts、密码存储**三处**都接上。
  - **W54**：`next_token` 的第二个调用方若出现，必须先回答「谁来划连接边界」。
  - **W150**：brief 的 `Message::Tick` 被 Task 8 静默丢掉了，
    后果是「已连接 HH:MM:SS」不会自己走字。这一轮补回（要 `Subscription`）。
  - **W152**：`Model.proxy` / `Form::detected_proxy` 至今无人写入，
    诊断页那三行在真实运行里一行都不会出现。
  - **W82 / W94**：`supervisor.rs:1110` 的 `Ok(event) = sys.recv()` 在 select 里
    **把 `Err(Lagged)` 与 `Err(Closed)` 静默吞掉、零日志**。
    EventHub 若被 drop，系统事件从此永久停摆，「唤醒立刻重连」
    静默退化成「等满退避」而没有任何地方会说一句。
  - **W93**：`crates/rmc-win/Cargo.toml` 的 `Win32_System_SystemServices`
    feature 与它上面那条注释**都是错的**（符号在 `Win32_UI_WindowsAndMessaging`，
    而那个 feature 本来就开着）。全仓库 grep 唯一命中就是那一行。删掉。

Task 10: 实现完成 7628363。**600 passed / 18 ignored**（基线 530/18，+70；
  rmc-app lib 97→152、ui 26→31）。七道闸门全绿零告警，
  另加跑了 windows 目标的 `clippy -p rmc-app` 也零告警。
  **21 个文件 +4330/−34，动了全部三个 crate。** Cargo.lock 只多 4 行依赖边、零新包。
  报告含 40+ 条变异表、一张 17 行的「接了哪些线 × 断掉它什么会红」对照表、
  以及 7 处「改什么都不会红」。评审已派发。

**一件我先核实并处理的事**：它自承第一版测试**每跑一次 cargo test 就往开发机
  真实的 `~/.rmc/` 里扔一个诊断包**（攒了 27 个才发现）**并弹出文件管理器**。
  我核过：`~/.rmc/` 现在**不存在/为空**，近两小时无写入，也无残留进程。
  **它的改法值得记**：不是在测试里绕开，而是**让实现在没有内核时不许去猜落点**
  ——那才是根因。**这条纪律已写进给评审的派发**（变异时要查仓库与 scratchpad
  之外有没有被写到）。

--- 它自报的八条疑虑 ---

  1. **它为一个可能只存在于测试环境的崩溃改了产品外观。** 画板给日志三列
     都上了等宽字体，而它实测 `Font::MONOSPACE` **配中文**会让渲染管线 panic
     （cosmic-text-0.15.0/src/glyph_cache.rs:100 的 `attempt to add with overflow`
     ——同一段中文用默认字体没事、同一个 MONOSPACE 画 ASCII 也没事，
     **只有两者凑一起会炸**），于是把正文列改回默认字体。**它没查到根因。**
     已让评审独立复现并判：时间与等级那两列仍是等宽，安不安全。
     **Windows 人工验收要专门看一眼。**

  2. **两个 tokio 运行时并存的安排没真跑过。** 内核一个、iced 自己一个，
     `runtime.enter()` 的守卫只罩住 `spawn_core` 那一行。macOS 上起不了窗口
     （default-features=false 没有 x11/wayland），只验证了编译通过与内核侧全绿。
     Windows 上第一次真跑要留意 "Cannot start a runtime from within a runtime"。

  3. **W28 只接完三分之二。** 落点算好了、`Core::secrets` 也造出来了，
     但**整个 rmc-app 没有任何生产读方**（实测把它换成 `None` 全工作区全绿），
     **「记住密码」勾选框仍然什么都不做**。Task 4 的 DPAPI 零件仍然悬空。
     **这是本轮最大的一处「接了一半」。**

  4. **`main()` 仍然完全测不到，而且这一轮它第一次能造成整机失效。**
     实测：删掉 `install_event_source(&core)` 或把 `program(Some(core))`
     换成 `program(None)`，**七道闸门全绿**——后果分别是
     「界面永远收不到任何内核事件」与「内核根本没起」。
     已让评审去找出路（Task 6 在同形状问题上找到过：把装配提成 `program()`，
     用 `Application<P>` 实现的公开 `Program` trait 去读）。

  5. `Platform::detect` 的 Windows 那一支仍是盲区（W171 只能挤到这里为止）：
     把 `sealer: Some(DpapiSealer)` 改成 `None`，三道相关闸门全绿。

  6. **它自己写了两条假绿并在交付前抓住**，都是「两帧确实不同，
     但不同的不是我声称的那件事」：日志行差分快照先拿两个**等级**去比
     （等级那一列的文字本来就不同，**三处取色全写死照样绿**），
     改掉之后**只写死底色仍然绿**。现在每轮只动 `LogRowPalette` 的一个字段。
     **这是第四次有实现者在交付前抓住自己写的假绿。**

  7. **一条实情值得记**：`Err(Closed)` 在当前生产接线里**不可达**
     （`Deps.events` 持有 `Arc<EventHub>`，发送端跟着 Supervisor 活到最后），
     W82 描述的「EventHub 被 drop」今天发生不了；**真正可达的是 `Lagged`**。
     `Closed` 那一格仍照实现了（trait 不保证实现者持有发送端），
     测试用 `BorrowedEvents` 假实现刻画那种形状。

  8. **变异脚本自己出过一次事故**：同一文件多处变异时**第二次备份覆盖了
     原始备份**，还原后留下半个变异（丢了 `sys_open = false;` 与两处 `emit_proxy`）。
     **是靠 `grep -c` 数出来的，不是靠测试。** 已修脚本并重跑全量闸门确认树干净。
     这条与 W39/W72/W154/W156 同族，已写进给评审的纪律。

=== Task 10 评审结论：通过（8 条发现，4 条够格当场修 + 1 条便宜守卫）===
七道闸门评审在仓库外副本 + 全新 CARGO_TARGET_DIR 复跑全绿；
  **+70/−0 的账目用 `cargo test --workspace -- --list` 排序后 `comm` 对过**
  ——**被删掉的测试名 0 条、新增恰好 70 条**。逐 crate 全部对上。
  **接线表 17 行它全碰了，其中 14 行真的把线断掉看红**，15 行与报告逐字相符，
  1 行如实自承无测试，**1 行虚报**（见 W178）。
  40+ 条变异重做 33 条，**没有把绿说成红**；自报 7 处盲区复现 6 处全部属实。

--- 四条够格当场修 ---

Ruling W177（**F1，评审写了 PoC 并跑通，两枪各红一条不同断言**）：
  `main()` 那两根线仍然零闸门，而这一轮它们第一次能造成**整机失效**——
  删 `install_event_source(&core)` → 界面永远收不到任何内核事件；
  `program(Some(core))` → `program(None)` → 内核根本没交给界面。
  两者实测 **600 全绿 + clippy 全绿**。
  **出路是 Task 6 那把钥匙再往前一步**：`iced_program-0.14.0/src/lib.rs:47` 的
  **`Program::boot(&self) -> (Self::State, Task)` 是公开的**，
  Task 6 只用它取 title/theme/window/view，**没有用它取状态**。
  把 main() 剩下的两步搬进 lib 的 `assemble(core)`，两枪就各有靶子：
  - 删 install_event_source → 红「进程级事件源没有登记」
  - program(None) → 红「界面没拿到内核（日志尾部是 NotWrittenYet）」
  **不需要任何新 API**：`App::with_core` 本来就会 `reload_logs()`，
  而 `wiring::read_tail(None)` 按设计返回 `NotWrittenYet`——于是
  「读到了这个内核目录下的那一行日志」**就是**「内核交到界面手上了」的证据。
  够格的理由：**成本随时间涨**，main() 每多一行装配这块无人区就大一寸，
  而 Task 6 的报告已经为同一件事记过一次债。

Ruling W178（**F2，报告里唯一一条经不起复核的断言，背后是没列出的盲区**）：
  接线表第 6 行「电源/网络事件 → Supervisor」声称断掉会让某条测试变红。
  **不会**：评审把 `spawn_core` 里 `Deps { events }` 换成新造的 `NoSystemEvents`
  （Platform 给的那个 hub 被直接丢掉），**600 条全绿**。
  Windows 上的后果就是「合盖唤醒之后不再立刻重连」——
  **正是 W82/W94 花一整轮堵的那个形状，从另一头漏了出来**。
  评审给了 15 行的 SpyEvents PoC（数 `subscribe()` 被调几次 + 反向自证），
  实测干净树上 153 全绿、变异上当场红（left: 0）。

Ruling W179（**F3，评审查到了实现者没查到的根因，而且结论相反**）：
  实现者说等宽字体配中文会 panic、没查到根因，于是**改了产品外观**
  （正文列改回默认字体），并把「时间与等级两列安不安全」留给人工验收。
  **评审查到了根因，结论更严重**：
  `cosmic-text-0.15.0/src/font/system.rs:158` 把默认等宽族**硬编码**成
  `Noto Sans Mono`——这台机器没装，**默认安装的 Windows 11 也不带**
  （它出厂是 Consolas / Cascadia Mono / Courier New / Lucida Console）。
  于是 `Font::MONOSPACE` 解析不到任何字面，ASCII 走得通别的回退路，
  CJK 那条回退路算出巨大的字形 x 坐标，`glyph_cache.rs:100` 的
  `pos as i32` 饱和到 i32::MAX 再 `trunc + 1` 就溢出。
  **三条判断（评审全部实测）**：
  - **不是 iced_test 特有的**。`iced_graphics-0.14.0/src/text.rs:121` 用
    `FontSystem::new_with_fonts`，而它**照样 `load_system_fonts()`**，
    内嵌 Fira Sans 只是多加两个 face、补不上那个硬编码的族名。
    **所以这个崩溃很可能在目标平台上同样复现。**
  - **`Font::with_name("Menlo")`（本机真实存在的等宽族）+ 中文实测不崩**
    ——换一个**真实存在**的族就能同时拿回画板外观与安全。
  - **时间与等级那两列现在并不安全，只是恰好没踩到**：它们跑在同一个
    解析不到的族上，唯一挡着的是 `logs.rs:166` 那条「时间必须全 ASCII」的校验，
    **而那条校验的文档一个字都没说它兼着挡一次渲染崩溃**。
    下一个人为了显示带毫秒/时区的时间放宽它，就会同时拆掉崩溃防线。
    评审另做一枪：把时间夹具换成「11时52分」→ 不 panic，但那一列被挤出可见区，
    **行为损坏在 panic 之前就发生了**。
  够格的理由：**方向是错的且会被继承**——「MONOSPACE 对 ASCII 是安全的」
  这条错误结论会作为既定判断进入后面几轮。
  最小当场修：两处 `Font::MONOSPACE` 换成真实存在的族（Consolas/Cascadia Mono），
  注释订正成「不能用 Font::MONOSPACE，cosmic-text 把它绑到一个通常没装的族上」，
  并在 logs.rs:166 那条校验上写明它兼着挡渲染崩溃。

Ruling W180（**F4，那条防事故的测试名不副实，而且首跑有洞**）：
  `pressing_buttons_without_a_core_is_harmless_and_touches_no_disk`
  开头建了临时目录当假 HOME、断言它是空的，**然后既没有 set_var("HOME")、
  也没有再查一次**——那三行是**纯死代码**，测试名里的 `touches_no_disk`
  **没有任何断言支撑**（与上一轮当场修掉的 W166 空转断言同形状）。
  更要紧的是评审实测出的**首跑洞**：把那个回退改回去之后——
  **第一次跑**（落点里还没有 logs/）：bundle 先建出 zip、随后 read_dir 失败返回 Err，
  于是 `last_export` 仍是 None ⇒ **测试绿，而 zip 已经落在盘上**（评审复现过）；
  第二次跑才会红。
  **也就是说：这条测试在干净机器上的第一次运行不会拦住那次事故，
  而那正是事故发生的时刻。**
  它是这个仓库里唯一防住「往开发机家目录乱写」的测试，而这个事故已经烧掉两轮。

Ruling W181（F5 的那半条，便宜守卫，顺手）：`spawn_core` 在
  `sealer: Some(..)` 时断言 `secrets.is_some()`——5 行，至少拦住
  「落点被默默摘掉」。**但它不会让勾选框工作**，那是 Task 11 的功能缺口，
  两件事别混为一谈。

--- 记录 ---

Ruling W182（**带进 Task 11，这条比想象中严重**）：**CI 完全不覆盖
  rmc-app / rmc-win**——`.github/workflows/` 只有两个 ubuntu job 跑 rmc-core。
  **本轮的 600 条里有 320 条 CI 一次也不会跑。**
  而闸门 5 已经在本机产出 Windows 的测试可执行文件、**从不执行它**。
  这让 F6 从「Windows 特有盲区」升级成「整个客户端在 CI 里不存在」，
  也是 N1（Platform::detect 的 Windows 支）唯一的出口：
  加一个 windows-latest job 跑 `cargo test -p rmc-app -p rmc-win`。

Ruling W183（记录，评审核实的两条实情）：
  - **两个 tokio runtime 的安排成立**，风险很低。评审核了四环：
    iced 的执行器是 `Runtime::new()`，只在**当前线程已进入运行时上下文**时 panic；
    `main.rs:61-64` 的守卫是**具名 `_guard` 且限定在块里**，
    `run()` 在守卫之外执行；跨运行时的都是 runtime-agnostic（try_send、broadcast）。
    **唯一脆弱点是纪律性的**：正确性完全取决于那一对花括号的位置，
    而没有任何东西守着它。等价且更难写错的写法是
    `runtime.block_on(async { wiring::spawn_core(..) })`——作用域天然只罩一行。
  - **W82/W94 那条实情成立**，评审核了因果链每一环：`Deps.events` 被 `run()`
    整个持有到结束，EventHub 与 NoSystemEvents 内部就装着 `broadcast::Sender`，
    所以生产接线里 `Err(Closed)` 不可达、真正可达的是 `Lagged`。
    **那条「至多一行」的设计评审判为这轮最好的一处测试工程**——
    删 `sys_open = false` 造忙循环，实测 **left: 6272 / right: 1**，
    **靠日志行数抓住了「不是绿，是永不结束」那个形态**。

Task 10: 修复轮 1/5 已派发（W177-W181 五条，评审的 PoC 都跑通了）。

Task 10 修复轮 1：实现者交回 5d4885a。**610 passed / 18 ignored**（+10）。
  我自己复跑过：workspace 610、clippy -D warnings 零告警、fmt 干净、
  `~/.rmc/` 与 `crates/rmc-app/logs` 都是 0 个。定向复审已派发。
  （它的报告没随通知送达，我直接读了 task-10-fix-1-report.md。）

五条裁决全部落地，另外三件它自己带出来的：

  - **W179 它订正了自己上一轮的结论，而且订正得对。** 它原话：
    「上一轮我写『这个崩溃可能只存在于 iced_test 的字体栈』，并据此只把
    正文列改回默认字体、把『时间与等级两列安不安全』留给人工验收。
    **两条都错。**」它自己核了评审给的两处源码并确认：
    `iced_graphics` 运行时用的是同一个 `FontSystem::new_with_fonts`，
    内嵌 Fira Sans **补不上那个硬编码的族名**——所以 Windows 上同样会复现。
    它的话：「『MONOSPACE 对 ASCII 是安全的』这个判断要是留着进了后面几轮，
    代价是 Windows 上点开日志页当场崩——**而 CI 一个字都不会说**。」
    落地时它**没有**用一对 cfg，理由是「Windows 那一档是唯一真正要用的一档，
    写成 cfg 就没有东西看得见它」——这正是 W171 那条约定。

  - **它在落地过程中又抓到自己写的两条不设防断言（F8/F11），当场修掉。**
    **这是第五次有实现者在交付前抓住自己的假绿。**

  - **它顺带修了一个真 bug**：裁决 W180 背后带着「首跑必失败且留下打不开的
    zip」——干净机器上第一次导出，`bundle` 先建出 zip、随后读日志目录失败，
    于是留下一个打不开的半成品。

--- 它自己的疑虑里两条是方法论，值得单独记 ---

Ruling W184（**方法论，写进后续每一份派发**）：实现者自承——
  **F8 与 F11 两条第一版断言不设防，而且两条都写着「改红：…」的注释，
  「注释里写的改法我当时没有真的跑」。**
  这个项目的文档惯例就是在测试上写「改红：改哪一行」，
  **如果那句话可以不经验证就写下，整套惯例的可信度要打折。**
  从此派发里明说：**写「改红」注释＝承诺你真跑过那一枪**，
  没跑过就别写，或者写成「未验证」。已让复审抽查有没有第三条同样没跑过的。

Ruling W185（记录，实现者对自己上一轮的复盘，值得照搬进方法）：
  它原话：「我上一轮把 W179 判成『测试环境特有』是一次方向性错误，
  而且我在报告里把它列为**『疑虑第 1 条』而不是『缺陷』**。
  回头看，当时手上已经有足够的线索（iced_graphics 用的是同一个
  font_system()，翻一下就知道），**我停在了『现象可复现』就没有再往下走一层**。」
  ——「现象可复现」不等于「根因已知」，而把一条未定性的东西记成「疑虑」
  而非「缺陷」，会让它在下一轮被当成已知风险接受下来。

它自承的两处残余：
  - **Consolas 那一档是资料判断、不是实测**（macOS 上验不了 Windows 字体栈）。
    这是本轮唯一一处「改了行为而验证只能靠人工」的地方。
    若 Windows 上仍崩，下一步是族名可配置或内嵌一个等宽字体。
  - `assemble()` 因为 `OnceLock` **只能被一条测试用**——这是
    `iced::Subscription` 身份设计逼出来的全局带来的第二笔利息。

=== Task 10 修复轮 1 的定向复审：五条全 ✅，判可以收口 ===
复审七道闸门在仓库外副本 + 独立 CARGO_TARGET_DIR 复跑：610/18 与自报逐字相符。
  12 枪变异它重做，**11 枪与报告逐字相符、没有一枪把绿说成红**；
  唯一瑕疵是 F3b 那一行的**归属**写错（红的是结构断言不是行为那一半）。
  它还自己加了 F11b（守卫与测试一起摘掉）证明**两者互相独立、各自带载**。

**W184 那条抽查的结果：本轮没有第三张空头支票。** 复审把本轮新增测试里
  写着「改红：…」的 5 条**逐条按注释字面去改，全部真红**。那个文档惯例
  就这一轮而言可信度是恢复了的。
  但它另找到**两条不带「改红」注释的打空测试**（见下）。

**W179 的根因复审逐环独立证实**：两处源码引对了（它还多查一层——
  `new_with_fonts` → `load_fonts` 第一句就是 `db.load_system_fonts()`，
  所以运行时与 iced_test 走同一套字体库、同一个硬编码族名）；
  崩溃它自己复现了（**9 条里红 7 条：1 条溢出 + 6 条 PoisonError**）；
  **「panic 毒掉全局字体锁」这个论断成立**——正是那 1+6 的形状，
  所以「结构断言排在行为断言之前」这个安排是对的。

--- 我自己做的两条收口（commit 9c8f546）---

Ruling W186（**订正一个错措辞**）：「打不开的 zip」是错的。
  复审实测：`ZipWriter` 的 `Drop` 会把中央目录补完，首跑失败留下的是
  **131 字节、打得开、条目只有 environment.txt** 的包。
  **危害换了一种**：不是「远程那头解不开」，而是**界面报了失败、
  盘上却躺着一个看上去完整的包**——发的人和收的人都不会知道少了日志。
  三处注释 + 一个测试名已改
  （`a_failed_export_leaves_no_half_filled_bundle_behind`）。

Ruling W187（**复审这条建议是错的，我照做之后实测不成立，撤回并写明边界**）：
  复审说等宽那条测试的行为那一半「夹具换成 log_row 形状即可带载
  （我已验证那个形状在坏族名／MONOSPACE 下真会炸）」。
  **我照做之后实测仍然不红**，两枪都做了（都先把两条结构断言一起废掉）：
  `mono()` 换成不存在的族名 → 九条全绿；换成 `Font::MONOSPACE` → 九条全绿。
  **根因是设计本身：生产代码里中文根本不走等宽字体。**
  消息列是整行里唯一可能出现中文的地方，而它用默认字体；
  走 `mono()` 的只有 ASCII 的时间与 ASCII 的等级标签。
  **上一轮之所以炸，是因为当时正文列也加了 `.font(mono())`**——
  所以任何「生产形状」的夹具都触发不了那次溢出。
  于是这一半只剩「mono() 至少画得出中文而不 panic」这条弱保证；
  真正守着这件事的是那两条结构断言与 `parse_line` 对时间列的 ASCII 校验
  （都带载）。要让它真带载得造一个**非生产形状**的夹具，那属于为测试造场景。
  **已撤回夹具改动，改成把这段边界如实写进测试文档。**

Ruling W188（**我一度否掉复审的判断，被一条测试的反向自证当场纠正**）：
  复审判「单个日志文件读不出来会让整包被删」**不够格当场修**，
  我不同意并动手改成优雅降级——结果
  `a_failed_export_leaves_no_broken_zip_behind` 那条的反向自证
  （「夹具没能让导出失败，下面那条断言是空转的」）**当场拦住我**：
  它的夹具正是「用目录冒充日志文件触发读失败」，也就是我刚改成优雅降级
  的那一档，改完就**没有夹具能让导出失败了**。
  **那不是 5 行的改动**，复审的「不够格」判对了，我撤回。
  这是本项目第二次「既有测试拦住了裁决者改过头」（第一次是 W131）。

--- 带进 Task 11 的 ---

Ruling W189（**本轮唯一一处行为变差，Task 11 第一件事**）：
  `bundle` 对**单个日志文件读不出来**（Windows 上被占用、正在轮转、
  杀软挡住——都是现场常见形态）：`?` 冒出去 → 整次导出判失败 →
  修复轮新加的 `remove_file` 把包删掉。
  **改之前**工程师至少拿到 environment.txt + preflight.txt，**改之后什么都没有**。
  这与它自己立的原则（「静默少东西才是最糟的」「现场要包的时候多半正是
  出了乱子的时候」）矛盾：**对「列不出目录」宽容，对「读不出其中一个文件」
  反而更严**。修法与已有那一支同形（照样出包 + 写一条说明），
  但要连同 W188 一起想清楚那条守卫测试换什么夹具。

Ruling W190（带进 Task 11，与 W182 捆在一起）：复审指出
  `a_time_column_with_non_ascii_still_renders` **整条无任何变异能让它红**
  （F2/F3c 下都绿，连 `bounds.width > 1.0` 都过），报告把它描述成「钉住」
  属**溢美**（不属虚报——变异表里没为它记过红）。
  连同 W187：Consolas 那一档在 macOS 上没有东西验得到，
  **出口只有 W182 的 windows-latest job**。

Ruling W191（记录，不修）：`assemble()` 丢掉了 `install_event_source`
  的返回值（`wiring.rs:481` 返回 `bool`），「重复装配」今天是静默的，
  一行 `assert!` 可以关掉。另：`the_platform_event_source_is_handed_to_the_supervisor`
  用 `sleep(200ms)` 等调度，换成轮询到超时更抗负载。

=== Task 10: complete ===
提交链：7628363（实现，接线第一次真的连起来）→ 5d4885a（修复轮 1，五条
  + 它自己抓到的两条不设防断言 + 一个真 bug）→ 9c8f546（收口两条，我做的）。
最终状态：**610 passed / 18 ignored**（基线 530/18，+80），
  七道闸门全绿零告警，`~/.rmc` 与 `crates/rmc-app/logs` 均 0 个。

下一步：Task 11（托盘与通知，252 行）。带进去的有
  W167（诊断包大小上限）、W182（**CI 完全不覆盖 rmc-app/rmc-win，
  600+ 条里有 320 条 CI 一次也不跑**）、W189（行为回退）、W190、
  W83（2 秒轮询没有停止通道）、以及 Task 4 那个「记住密码勾选框仍然
  什么都不做」的功能缺口。

=== Task 11 派发前预检（托盘与通知）===

Ruling W192（**必修，头一条，我实测之后改掉了 brief 的技术选型**）：
  brief 要用 `tray-icon = "0.19"`。**我建临时工程实测了两次**：
  - 直接加（放在 `[target.'cfg(windows)'.dependencies]` 下）：
    锁文件解析 134 个包，**对本工作区真新增 48 个**——
    里头是**整个 GTK3 栈**（gtk / gdk / glib / pango / cairo / atk /
    libappindicator / libxdo / x11 / winapi 那一套）。那些是 tray-icon 的
    **Linux** 依赖，在我们的 target 上一行都不编译，**但会进 Cargo.lock**。
    `cargo deny` 直接红：**licenses 2 条 rejected + advisories 1 条
    （proc-macro-error unmaintained）**。
  - 加 `default-features = false`：**没用**，仍然 45 个新包、GTK 仍在、
    deny 照样两项红。GTK 是它 Linux target 上的硬依赖，而锁文件不分平台。

  **改用 Win32 自己做。** 我核过 `windows-0.62.2` 自带：
  feature `Win32_UI_Shell`（Cargo.toml:702）、`NOTIFYICONDATAW`（mod.rs:52111）、
  以及气泡通知要的 `NIF_INFO`（mod.rs:51986）。**零新包、零 deny 事件。**
  代价是 `#[cfg(windows)]` 层多几十行 unsafe——而**这个 crate 本来就全是
  这么做的**（CreateMutexW、WinHTTP、SSPI、DPAPI、PowerRegister…），
  两层划分的约定现成，纯逻辑（tooltip / icon_color / notification_for）
  按 brief 本来就是平台中立的。
  **这个取舍我拍板了**：48 个永不编译的包 + 两项 deny 豁免，
  换不来任何东西；而把它们写进豁免表会让那张表从「刻意拍板的少数几条」
  变成噪音（Task 6 的 BSL-1.0、Task 9 的 ttf-parser 都是一条一条论证过的）。

W193（必修，**同一个缺陷类的第七次**）：
  `notification_for(prev, next, sessions_delta) -> Option<(String, String)>`
  ——两个裸 String 的元组**说不出哪个是标题哪个是正文**，
  而 `Option` 又把「没什么值得通知」与「该通知但给不出文案」压平。
  前六次：Task 2 的 `resolve()`、Task 3 的 `next_token()`、Task 4 的 `load()`、
  Task 8 的 `validate()`、Task 9 的 `advice_for()`、Task 10 的
  `parse_line()`/`tail()`。**六次的解法都是带类型的出口。**
  另：`sessions_delta: i64` 把「开了几个」「关了几个」压成一个数，
  而通知文案要分开说。

W194（必修）：`icon_color(&Model)` 必须对 `State` 的**七个变体**都有定义，
  而 brief 的测试只碰了两个。照 Task 9 的解法——穷尽 match + 定长表，
  让「加变体不进表」编译不过。`tooltip` 同理。

W195（必修）：brief 的通知断言全是 `contains`（`n.1.contains("远程会话")`、
  `contains("结束") || contains("关闭")`）。这个项目对 `contains` 的教训是
  「空串上永远为假、长串上很容易碰巧为真」——**每条都要配一个反向变异**
  证明它真的在看那一段文字。

W196（必修，Task 10 带下来的**本轮第一件事**，见 W189）：
  `bundle` 对**单个日志文件读不出来**（Windows 上被占用、正在轮转、
  杀软挡住——都是现场常见形态）会让**整包被删**，而对「整个目录列不出来」
  反而宽容。这是 Task 10 修复轮引入的**行为回退**，与它自己立的原则矛盾。
  修法与已有那一支同形（照样出包 + 写一条说明），**但要连同 W188 想清楚
  那条守卫测试换什么夹具**——它现在的夹具（用目录冒充日志文件触发读失败）
  正是要改成优雅降级的那一档，改完就没有夹具能让导出失败了。

W197（必修，W167 到期）：诊断包**没有任何大小上限**——500MB 的日志会
  整个读进内存、再脱敏、再写，三份同时在堆上。当初记的理由是
  「轮转策略要 Task 11 才定」，**现在就是 Task 11**。

W198（必修，W83 到期）：`register_network` 那个 **2 秒轮询没有任何停止方式**，
  进程在跑它就在跑。Task 10 接线没给它关闭路径。笔记本上一个永不停歇的
  2 秒定时唤醒，这一轮定。

W199（带进 Task 12，不在本轮）：**W182——CI 完全不覆盖 rmc-app / rmc-win**，
  610 条里**有 320 条 CI 一次也不跑**；闸门 5 已经在产出 Windows 测试可执行
  文件却从不执行它。Task 12 的 brief 正好要建 `.github/workflows/app.yml`，
  那里加一个 windows-latest job 跑 `cargo test -p rmc-app -p rmc-win`。
  **W190 也捆在那里**：Consolas 那一档在 macOS 上没有东西验得到。

W200（记录）：「记住密码」勾选框**至今什么都不做**——Task 10 把落点与
  `Core::secrets` 造出来了，但 rmc-app 里没有任何生产读方。
  这是功能缺口不是测试缺口，按 brief 它不在 Task 11 的范围内，
  但**产品上它是 Task 4 整个任务的唯一出口**。本轮不做就要明确记成
  「V1 不含记住密码」，否则是一个做了却接不上的零件。

Ruling W200 落定（**用户拍板：记住密码在 Task 11 接上**）：
  Task 11 顺带接三处界面行为——
  1. 连接成功且勾了「记住密码」→ 按 `账号@运维服务器` 存进 `SecretStore`；
  2. 启动时按同一个 key 取回、填进密码框；
  3. 取回失败把 Task 4 那四种分类（`NotRemembered` / `Unreadable` /
     `UnsealFailed` / `NotUtf8`）的诊断话画在密码框旁。
  代价是 Task 11 的量大约一倍（它本来是最小的一个，252 行）。
  理由：Task 4 那一整轮（105 条测试）不白做，
  而且**「换了 Windows 账号解不开」那条诊断话才有地方显示**
  ——那正是 W21 当初要求带类型出口的全部意义。

Task 11: 实现完成 86c5cc9。**671 passed / 18 ignored**（基线 610/18，+61）；
  rmc-app lib 162→206、ui 31→33。七道闸门全过、deny 四项 ok、
  **Cargo.lock 一个字节没变**（W192 的 Win32 自制方案兑现了「零新包」）。
  12 文件 +3599/−115，动了 rmc-app 与 rmc-win。评审已派发。
  孤儿与副作用自查干净（~/.rmc 0、logs 0、无 rmc-data）。

九条裁决全部落地：W192 托盘 Win32 自制、W193 出口带类型
  （`Notification` 具名 / `Notify` 三格 / `SessionDelta{opened,closed}`
  **按会话 id 算差**而不是一个 i64）、W194 八个显示分支穷尽表、
  W195 文案逐字比对、W196 单文件读失败优雅降级、
  W197 大小上限（单文件 4MB / 总 16MB，**seek 读尾部**）、
  W198 轮询停止路径（`#[must_use]` 句柄 + Drop 即停 + **循环骨架上移到纯逻辑层**）、
  W200 记住密码三处接线全通。变异 25 枪 + 盲区 7 枪，全部实跑。

--- 它自报的五条，两条是方法论级的 ---

  1. **`mod win` 那 110 行 unsafe 一次都没在 Windows 上跑过**，它用 7 枪实测，
     **结论比 Task 5 的更精确也更难看**：「**只要改动没让某个 `use` 变成孤儿，
     四道语义闸门就是全绿的**」——通知标题与正文对调、托盘图标换成空句柄、
     换状态时永远不换图标、Platform::detect 把轮询句柄丢掉，**五枪全绿**。
     它点名三处自己最没把握的：`CreateIcon` 用 32bpp DDB 传 RGBA
     （MSDN 例子是 1/4bpp）、用预定义 `STATIC` 类建 `HWND_MESSAGE` 宿主窗口
     （标准做法是自己注册窗口类）、`Drop` 里 `NIM_DELETE` 与 iced 窗口销毁的先后。
     报告 §6 有 12 条人工验收清单冲着这些去。

  2. **两枪第一次打空，而且都不是测试写错，是实现里有一条路没有任何夹具够得着。**
     - M9：`poll_loop` 的 `while` 条件当时是冗余的（循环体中段还有一次判停），
       换成 `loop` 一条都不红——补了「已经停了就一次都不读」。
     - **M11 更该记**：单个日志读失败的降级分支被上游一道 `is_file()` 筛
       **完全挡住**，它在那一支上写的「改红：把它换回 `?`」**当时是假的**；
       **它改的是实现**（去掉那道筛让它走完整条路）。
     **这是第六次有实现者在交付前抓住自己的假绿，而且形态是新的**：
     不是断言写松了，是**注释承诺的那条路在实现里根本走不到**。
     它接着担心：这一轮里其他**没打过枪**的分支（`LogTake::Skipped` 在真实
     导出路径上那一支、`remember::save` 的「密文写成了但账号记录写不成」回滚）
     可能同样零覆盖。**已让评审各打一枪。**

  3. `last-account.txt` 是它对 W200 的一处**扩大**：派发单只说三条界面行为，
     但 key 是「账号@运维服务器」而启动时表单全空，**不存一份（不含秘密的）
     账号记录，第 2 条就是永远不会发生的死代码**。交评审判合不合理、
     以及有没有把不该存的东西存进去。

  4. W196 那条守卫**此后覆盖变窄**，它如实写进了报告与测试文档注释：
     现在只证明「一旦失败不留半成品」，**不再证明 `write_bundle` 真的会失败**
     （W196 之后它没有任何现实输入能失败了）。

  5. **它在 W197 的测试里抓到一个自己刚写的 bug**：预算耗尽时落进
     `Tail{bytes:0}`，会在诊断包里放一个**空条目**，
     让收到包的人以为那一天一条日志都没写过。已改成 `Skipped`。

=== Task 11 评审结论：通过（8 条发现，3 条够格当场修）===
七道闸门评审全部独立复跑，671/18 与自报逐字相符；基线 610/18 独立副本复跑。
  **+61 且一条旧测试都没被删或改名**——`--list` 两边取名排序、`comm -23` 差集为空。
  `git diff -- Cargo.lock` **输出为空**（W192 那个取舍的直接证据）。
  **26 行变异表逐条重做，一枪都没把绿说成红。**

它自承那两枪「第一次打空」评审都做了复现，**其中 M11 它按旧形状重建**：
  把 `is_file()` 那道筛连同说明一起加回来、同时把降级支换回 `?`
  → **全绿**。**坐实了那条「改红」注释当时确实是假的，
  而实现者改的是实现（去掉那道筛）不是把测试往实现上凑。**
  W184 那条纪律这一轮**没有第三张空头支票**——评审按字面复跑的
  20 多条「改红」注释全部真红。

口令那条线评审自己造了三枪，全红：把口令写进账号记录文件、密文写成明文、
  以及它补的第三枪（保留密封但另写一份明文）——**第三枪证明「明文落盘」
  本身带载，不只是「取不回来」**。`Zeroizing` 它逐点走过没找到漏的：
  `Recall::fill` 消费 self、`into_secret()` 直接 **move** 进 `Form::password`，
  中间没有第二份。诊断包那条端到端测试仍带载。

**托盘那一层评审复现了 6 枪（要求 3 枪），并自己加了一枪 B8 验证机制**：
  删掉 `DestroyWindow` → 只有闸门 6 红，原因是 `unused import`——
  **与实现者记的 B1/B2 一模一样的机制**。所以
  「只要改动没让某个 `use` 变成孤儿，四道语义闸门就是全绿的」独立成立。
  两层划分评审自己数过：**rmc-app/src/tray.rs 生产代码一行 `#[cfg(windows)]`
  都没有**（145 行全纯逻辑 + 407 行测试），rmc-win 那边纯逻辑 53 行、
  `mod win` 114 行、测试 92 行，两文件纯逻辑共 25 条测试。

--- 三条够格当场修 ---

Ruling W201（**F1，中，评审在那 114 行 unsafe 里读出来的真顺序错**）：
  `rmc-win/src/tray.rs:267-275` 的 `set_status` 在
  `Shell_NotifyIconW(NIM_MODIFY, &data)` **之前**就 `DestroyIcon(old)`，
  而**紧挨着的注释写的是「旧图标要等这一次 NIM_MODIFY 之后才不再被
  通知区引用」——代码和自己的注释顺序是反的**。
  在通知区仍持有旧 HICON 的窗口期销毁它，轻则换色时托盘图标闪空白，
  重则 GDI 句柄号被复用后 Explorer 引用到别的对象。
  **这一层没有任何自动化闸门看得见**（B7 那一枪已经证明）。修法 3 行。

Ruling W202（**F2，中，口令线上，评审写了 PoC 并跑红**）：
  `remember.rs:131-147` 的 `save` 只按**当前表单**拼出的 key 去清。
  用户记住 `A@S` 之后把账号改成 `B`、再取消勾选「记住密码」→
  `clear` 清的是 `B@S`（本来就不存在），`last-account.txt` 被删掉，
  而 **`A@S` 的密文永久留在盘上，且再也没有任何路径指得到它**
  （下次启动 `recall` 直接 `NoAccount`）。
  密文是 DPAPI 绑定的、不是明文泄露，但**用户明确说了「不再记住」
  而东西还在，且再也删不掉**。
  修法：`clear` 之前先读一次 `last-account.txt`、`decode` 出旧 key
  也一并 `store.clear`，约 5 行 + 1 条测试（PoC 现成）。

Ruling W203（**F3，中，实现者自己的疑虑被坐实**）：
  `remember.rs:148-155` 的**回滚分支零覆盖**——评审两枪双绿
  （删掉 `store.clear` / 把失败分支改成返回 Saved），**那条分支根本进不去**。
  它守的是「不留一份谁也找不回来的孤儿密文」，**跟 W202 是同一个危害面**。
  修法：把 `last-account.txt` 那个路径先建成一个**目录**，
  `std::fs::write` 必失败，于是 `save` 走进回滚支；
  断言 `SaveOutcome::Failed` 且 `store.load(key)` 为 `None`。约 12 行。

--- 带走 ---

Ruling W204（**并进 Task 12，一行配置**）：F5——`events.rs:652` 的
  `#[must_use]` **不闸**：调用点在 rmc-app，而**闸门 5（zigbuild）没有
  `-D warnings`、闸门 6（带 -D warnings 的 clippy）只覆盖 rmc-win**。
  评审实测把返回值整个丢掉，**七道闸门全过**，只在闸门 5 留一行 warning。
  W198 那道「结构上的防线」目前靠人眼。
  Task 12 给闸门 5 加 `-D warnings`，或补一条
  `cargo-zigbuild clippy -p rmc-app --target …windows-gnu -- -D warnings`。

Ruling W205（进人工验收 + Task 12，评审判得出成因、验不了结果）：F6——
  用 `HWND_MESSAGE` 消息专用窗口当托盘宿主 + 没有窗口过程
  ⇒ **收不到 `TaskbarCreated` 广播**（消息专用窗口按定义不接收广播消息），
  全仓 grep 零命中。**Explorer 崩溃/重启后托盘图标永久消失且无法恢复**，
  此后每次 `set_status` 的 `NIM_MODIFY` 只会静默返回 FALSE（返回值被 `let _` 丢掉）。
  人工验收加一条「杀掉 explorer.exe 再起来，托盘图标还在吗」。
  不够格当场修（要自己注册窗口类 + 写窗口过程 + RegisterWindowMessageW，
  而自己注册窗口类正是实现者为了不开 GDI 才绕开的那条路）。

Ruling W206（记账，不修）：F4 `LogTake::Skipped` 在真实导出路径上那一支
  零覆盖（S1 绿）。最省的做法是把两个预算常量改成 `BundleInput` 上的字段
  （纯函数 `plan_logs` 已经收参数了），但要动结构。成本不随时间涨。
  F7 `write_account` 用裸 `fs::write` 没走 `write_private_file`
  （文件不含秘密，但含运维账号名与运维服务器地址）。
  F8 报告一处措辞略强（zip 对重名条目会返回 Err，所以「没有任何现实输入」
  可以收一点）。

Ruling W207（**方法论，评审的收尾判断，值得单独记**）：
  评审原话——「**它已经学会怀疑自己的注释，还没学会把怀疑清单打完**
  ——它把两条可疑分支写进了报告，却没有各打一枪，而那两枪一共只要十几分钟。」
  **两条都被评审坐实为零覆盖。**
  从此派发里明说：**报告里每写一条「这里可能没覆盖」，就要附上你为它打的那一枪**；
  打不了要说明为什么打不了。**列出怀疑而不验证，等于把活推给下一轮。**

Ruling W208（记录，范围外，**这个缺口又扩大了**）：W182/W199——
  本轮之后 671 条里有 **395 条**（rmc-app 243 + rmc-win 152）CI 一次都不跑，
  比上一轮的 320 条更多。**Task 12 的 windows-latest job 现在是这一整块
  （含托盘那 114 行 unsafe 与 DPAPI）唯一的出口。**

Task 11: 修复轮 1/5 已派发（W201、W202、W203 三条）。

Task 11 修复轮 1：实现者交回 0ac7775。**676 passed / 18 ignored**（+5）。
  七道闸门全过、deny 四项 ok、`git diff -- Cargo.lock` 仍为空。
  三条裁决全修：W201（DestroyIcon 挪到 Shell_NotifyIconW 之后，注释跟代码对上）、
  W202（save 先读 previous_key；换账号继续记住时**在新的两样都写成之后**才清旧 key）、
  W203（按评审给的造法补夹具，评审那两枪现在都红）。

**W207 那条新纪律当轮见效，而且命中率高得意外。** 实现者原话：
  「我上一轮写进报告的『可能』，**这一轮一打就是三中二**。」
  它多打的两枪全绿、两条都是真缺口、已当场补测：
  - **F5 守的是生产里最常发生的一条路**：勾着记住密码时每连成功一次走一遍 `save`，
    第二次起 `previous == key`——**没有那道筛会把刚存的清掉**。去掉它全绿。
  - F6：把 `clear` 的 `.and(..)` 换成 `?` 提前返回全绿——**从没有测试让
    `store.clear` 失败过**。

Ruling W209（**新纪律，实现者自己撞上并自报**）：它说——
  「报告 §6 第 3 条我**差点又犯同一个错**：初稿里先写下『结果：RED，两条红』
  才去跑，**实跑是三条**。」
  **写下枪的结果之前先开枪。** 这是 W184（写「改红」等于承诺真跑过）
  的二阶版本：不只是注释，**报告里的变异结果也不许先写后跑**。

Ruling W210（**工具事故，影响整条流水线的可信度，我已核实属实**）：
  实现者报告上一轮的变异脚本放在会话 scratchpad **根目录**，而**那个目录
  跨 agent 共享**——中途它被另一个进程的同名 `mutate.py` 覆盖，
  **它的调用退化成 no-op、返回 0 且没有任何输出**。
  **我核实了**：scratchpad 根目录有 **394 个文件**，`mutate.py` 与 `mutate2.py`
  都躺在根上，碰撞是结构性的、不是偶然。
  它是靠「**怎么一条输出都没有**」这个反常去查的，**不是测试告诉它的**；
  当场 `git status` 核过没有文件被改坏。脚本已改放进带 pid 的私有子目录。

  **为什么这条要紧**：**一个静默 no-op 的变异脚本，产出的「全绿」
  与「这一枪确实打不红」长得一模一样**——而这条流水线的全部结论都建立在
  「打了枪、没红」之上。已有的那条纪律（替换前 `assert` 锚点命中次数为 1）
  **挡不住这一档**：脚本根本没跑，断言也就没跑。
  **定稿的防线**：注入之后、跑测试之前，**在目标文件里 `grep -c` 一次
  确认变异真的在那儿**——这正是 Task 10 实现者发现自己备份被覆盖时用的办法
  （「是靠 `grep -c` 数出来的，不是靠测试」）。脚本一律放私有子目录。

它自报的另两条（均带枪）：
  - **W201 修对了这件事本身没有任何自动化证据**：把顺序退回去，
    四道语义闸门 `&&` 串起来跑 → `rc=0，676 passed`，**全绿**。
    它能拿出的只有 MSDN 对 NIM_MODIFY / hIcon 生命周期的约定，
    以及代码现在跟自己的注释一致了。人工验收加了第 13 条。
  - `LogTake::Skipped` 的说明行仍零覆盖（把那一支静默化 → 36 passed 全绿），
    按 W206 记账不修。后果是「日志超预算时被挤掉的那几天静默消失」，
    **正是 LOGS_INCOMPLETE 存在的理由**。
  - `main.rs` 那条**本轮没重新打枪**，沿用 Task 6 修复轮的旧结论
    （本轮没动 main.rs）——它明确要求按「沿用旧结论」而不是「本轮实测」来读。

=== Task 11 修复轮 1 的定向复审：三条全 ✅，判可以收口（带三条当场修）===
复审**按 W210 的新纪律办**：脚本放私有 pid 子目录 `scratchpad/rev-64675/`
  （它自己数了根目录 **395** 个文件，确认跨 agent 共享），
  **每枪注入后在目标文件 `grep -c` 一次并打印计数（全部 = 1）**，
  备份按 label 编号 LIFO 还原。收尾 `git status` 0 行。
  W202 三枪、W203 两枪全部自己重跑，与自报吻合。
  上一轮 26 行变异表挑四条重做全部仍红（M25 红 11 条、M18 红 3 条、
  M19、以及 rmc-win 纯逻辑的 T1），**纯逻辑层的检测力没被稀释**。

Ruling W211（**第三张「改红」空头支票，而且是在我刚记下「没有第三张」之后**）：
  F6 那条注释写的是「把 `result = result.and(store.clear(old))` 换成
  `store.clear(old)?`」——**复审按字面注入，实测 211 全绿**。
  原因很清楚：那条测试让**第一步**（当前 key）失败，而那个 `?` 挂在
  **第二步**（旧 key，它是成功的）上，早返根本不触发。
  复审换成真正对应的形状（第一步那个 `.and`）才红。
  **测试本身是好的**，守的是「第一步失败也要走完后面几步」；
  错的是**注释与报告对「什么能杀死它」的描述**。
  **`clear` 第二步的早返至今零覆盖**——真发生时会跳过删账号记录，
  用户点了「不再记住密码」而 `last-account.txt` 还在。
  我已订正注释（commit 8818cd5），覆盖按 W206 记账不修。

Ruling W212（**当场修，已做**）：「新的两样写成之后才清旧 key」这个顺序
  **零覆盖**——复审把它改成「先清旧、后写新」→ **211 条全绿**。
  因为**从来没有任何测试让 `store.save` 在存在 `previous` 时失败过**，
  而那正是这个顺序唯一守的东西：反过来时新密文写失败、旧的那份已经被毁，
  **用户两边都没了**（账号记录还指着旧账号 → 下次启动是「记过但取不回来」）。
  我给 `RecordingStore` 加了 `save_fails` 开关并补测；
  变异实测：把清旧挪到 `store.save` 之前 → 当场红，**并报出被误清的那个 key**。

Ruling W213（**当场修，已做——一条历史叙述不实**）：F5 那道筛
  **与它守的危害面都是本轮新引入的，不是历史缺陷**。
  复审核过 `git show 86c5cc9:…/remember.rs`：上一版的 `save` 里
  **根本没有 `previous` 这个概念**，`clear` 也只有三个参数——
  每次连成功只是用同一个 key 覆盖写一遍，**不存在「把刚存的清掉」这条路**。
  所以「记住密码第二次连接就失效」这个 bug **从来没有发生过**。
  原注释写成「上一轮那一枪全绿」，容易被读成「旧代码里一直有这个坑」。
  **这条要记正，否则会误导后面判「这个 bug 影响过多少用户」。**

Ruling W214（**W209 的二阶形态，新纪律**）：复审抽查「先写后跑」，
  发现**两处变异计数取自中途树**：
  §3 表 F1 的「19 passed; 1 failed」= 20 条，而最终树 remember 过滤是 22 条；
  §4 S1 的「36 passed … 173 filtered out」= 209，而最终树 lib 是 211。
  **两处结论都不受影响**（复审在最终树上重打，F1 仍红、S1 仍绿），
  但这是 W209 的二阶形状：**不是「先写后跑」，是「跑过一次就不再跟着树走」**。
  **定稿纪律：报告里每个计数必须来自最终提交的那棵树。**

Ruling W215（记录，复审对 W201 替代证据的判断）：把 `DestroyIcon` 的顺序
  退回去，**四道语义闸门全绿**——实现者的自承成立。
  但复审判它给的替代证据**够，而且是能拿到的最强口径**：
  MSDN `DestroyIcon` 的参数约定原文就是 "The icon must not be in use."，
  而 `Shell_NotifyIcon` 文档**从未承诺通知区会复制 `hIcon`**；
  在「壳是否仍引用」不可知的前提下，只有「调用返回之后再销毁」满足那条约定，
  **新顺序严格不劣于旧顺序**。人工验收第 13 条仍是唯一实检。

Ruling W216（记录，复审今天打枪确认旧结论仍成立）：
  `main.rs:75` 的 `rmc_app::assemble(core).run()` 换成 `{ let _ = core; Ok(()) }`
  → **四道语义闸门全绿**。Task 6 修复轮的旧结论今天仍然成立：
  **没有任何东西证明 `main()` 真的装配并跑起来。**
  另两条自报零覆盖复审也各打一枪确认：`LogTake::Skipped` 说明行
  （**workspace 级也一条不红**，比实现者的 36 条 diag 过滤口径更强）、
  以及 W201 的顺序。

Ruling W217（记账，不修，W202 的残留尾巴）：`store.clear(&old)` 失败时只 `warn`，
  那一份密文从此是**永久孤儿**，且之后任何一次「取消勾选」都够不到它
  ——**文件名是 key 的 SHA-256 前 16 字节，扫目录也认不出属于谁**。
  要修得给 store 加反向枚举。另：`previous_key` 读到坏记录退化成 `None` 时，
  换账号 + 取消勾选仍会留孤儿（要三件事同时发生）。

=== Task 11: complete ===
提交链：86c5cc9（实现，九条裁决 + 记住密码三处接线）
  → 0ac7775（修复轮 1，三条 + 它自己多打两枪发现的两条真缺口）
  → 8818cd5（收口三条，我做的：W211 假注释、W212 顺序补枪、W213 历史订正）。
最终状态：**677 passed / 18 ignored**（基线 610/18，+67），
  七道闸门全绿零告警，**Cargo.lock 全程零变动**，副作用自查干净。

**功能全部完成。** 下一步 Task 12（打包、签名与 CI）——最后一个任务。
  带进去的：W199/W208（**677 条里有 395+ 条 CI 一次都不跑**，
  windows-latest job 是托盘那 114 行 unsafe 与整个 DPAPI 唯一的出口）、
  W204（闸门 5 没有 `-D warnings`，`#[must_use]` 形同虚设）、
  W205（Explorer 重启后托盘图标永久消失，进人工验收）、
  W190（Consolas 那一档只有 Windows job 验得到）、
  以及 13 条人工验收清单。

=== Task 12 派发前预检（打包、签名与 CI——最后一个任务）===
好消息先说：**brief 自带 `windows-2022` job 跑 `cargo test -p rmc-win -p rmc-app`**，
  W199/W208 那笔最大的债（677 条里 395+ 条 CI 一次不跑）brief 本身就解了。
  而且那个 job 的 `cargo clippy -p rmc-win -p rmc-app --all-targets -- -D warnings`
  **在 Windows 上原生跑**，顺带关掉 W204（闸门 5 没有 `-D warnings`、
  `#[must_use]` 形同虚设）——**这一条要在报告里点明是被谁关掉的**。

W218（**必修，头一条，硬错误**）：brief 的两个 job 都写
  `dtolnay/rust-toolchain@1.82`，而**本仓库 MSRV 是 1.89**
  （`rust-toolchain.toml` 的 `channel = "1.89"`、workspace `rust-version = "1.89"`）。
  更要紧的是**既有的 `core.yml` 已经写的是 `@1.89`**，而且它顶部有一段注释
  专门讲「`rust-toolchain.toml` 是目录级 override、优先级比这一步高」，
  还有一条测试 `unit_job_pins_the_toolchain_to_the_documented_msrv` 钉着它。
  所以 `@1.82` 不只是过时——**它与同一个仓库里已经写下的结论直接矛盾**。
  改成 `@1.89`，并让新工作流也被同一类测试钉住（见 W220）。

W219（**必修，这是这一轮真正的发现**）：**`cargo deny` 根本不在 CI 里。**
  我 grep 过 `.github/workflows/`：`deny.toml` 在 `core.yml` 的 path 过滤里
  （改它会触发工作流），但**没有任何一步真的运行 `cargo deny`**。
  也就是说这十二轮里所有依赖审计的结论——Task 6 的 BSL-1.0 拍板、
  Task 9 的 ttf-parser ignore、Task 9「zip 只新增三个包」的分析、
  Task 11「托盘改 Win32 换来 Cargo.lock 零变动」——**全部零强制**。
  任何人加一个 GPL 依赖、或者引入一条新的 RUSTSEC 公告，**没有一处会红**。
  Task 12 是 CI 任务，这一步就该在这里补上：
  `cargo deny check advisories bans licenses sources`。

W220（**必修，照既有惯例**）：这个仓库**有用测试守住 CI 配置的惯例**
  ——`crates/rmc-core/tests/ci_workflow.rs` 21 条，带 `run_code()`
  （剥注释，防「断言被 run: 脚本里的注释喂饱」，那是第 18 个假绿）、
  `step_is_disabled()`、`toolchain_channel()` 等一整套辅助。
  新的 `app.yml` 要照同一形状被钉住，**至少**：两个 job 都存在、
  windows job 真的跑 `cargo test -p rmc-win -p rmc-app`（这是 395 条的唯一出口）、
  toolchain 与 `rust-toolchain.toml` 一致、deny 那一步在。
  **别新开一套辅助**——复用或搬到共享位置，理由写清楚。

W221（必修，人工验收清单要收全）：`docs/windows-验收清单.md` 是这一整条
  流水线里**所有「本机验不了」的东西的唯一出口**，十二轮攒下来至少这些：
  - **W205**：杀掉 explorer.exe 再起来，托盘图标还在吗
    （消息专用窗口收不到 `TaskbarCreated` 广播，图标会**永久消失**）；
  - **W190 / W179**：Consolas 那一档——日志页的时间与等级列用的是
    `monospace_family()` 挑的族，**macOS 上没有任何东西验得到**；
  - **W201**：换状态时托盘图标闪不闪空白（`DestroyIcon` 的顺序，零自动化证据）；
  - **W106**：固定 520×720 在 1080p @150% 缩放下放不放得下
    （可用高度约 660 逻辑像素，**这是唯一一条「不改就可能在真机上不可用」的**）；
  - **W113**：两个 tokio runtime 并存，第一次真跑留意
    "Cannot start a runtime from within a runtime"；
  - **记住密码**：换一个 Windows 账号登录同一台机器，密码框必须为空**且不报错**，
    并且密码框旁要出现 `UnsealFailed` 那句话（W21 要带类型出口的全部意义）；
  - **Task 11 报告 §6 那 13 条**（冲着 `CreateIcon` 32bpp、`HWND_MESSAGE` 宿主、
    `NIM_DELETE` 与 iced 窗口销毁的先后去的）；
  - **W216**：`main()` 的装配与启动至今零自动化证据。

W222（记录，brief 判断对的地方）：**签名刻意不在 CI 做、证书不进仓库**
  （从 CI 下载便携包、在持证机器上 `signtool`）。这个安排是对的，别改。

W223（提醒，先核实再照抄）：ubuntu job 装了
  `libxkbcommon-dev libwayland-dev`。而我们的 iced 是
  `default-features = false`、**没有 x11/wayland**（W113），
  测试又全是 `iced_test` 无头模拟器。**先验一下这两个包到底需不需要**——
  不需要就删掉，装一堆用不上的系统依赖会让下一个人以为那是必需的。

Ruling W219 **撤销——这条裁决是错的，而且错在我**：
  我断言「`cargo deny` 根本不在 CI 里」。实现者核实并否掉了它，
  **我自己复核确认它对**：`core.yml:212` 有一个名叫 `deny` 的 job，
  `uses: EmbarkStudios/cargo-deny-action@v2`（不带 `with:` 即四类全查），
  而且 `deny_job_uses_the_cargo_deny_action` 与
  `cargo_deny_step_checks_all_four_categories_not_a_narrowed_subset`
  两条测试**从 `12f1ff2` 起就钉着它**。

  **我的错误是方法性的**：`grep -n 'deny' .github/workflows/core.yml`
  实际有 **7 处命中**，而我的管道接了 `head -3`，
  然后照着被截断的三行（全是注释与 paths）写下「空=没有」。
  **截断的搜索结果不能用来证否。** 这与项目里记过的几条同族
  （W155「别拿一个正在变化的量当依据」、W156「锚点撞上自己的文档注释」）——
  **共同点都是：工具给了一个看起来干净的答案，而那个答案是残缺的。**

  实现者的处置也对：它**没有**照我说的在 app.yml 里重复一份，
  理由是「`core.yml` 的 paths 已覆盖 `crates/**`/`Cargo.toml`/`Cargo.lock`/
  `deny.toml`，**重复的成本恰恰是随时间涨的那种**」。

Ruling W224（**它顺着我那条错裁决查出一个小一号的真洞**）：
  `Cargo.lock` 与 `deny.toml` **从来没被 paths 断言钉过**——
  手滑删掉一条，一次只动锁文件的 `cargo update`（新 RUSTSEC 公告、
  新许可证）**就再也不触发审计**。
  已补 `dependency_audit_triggers_on_every_file_that_can_change_the_dependency_graph`
  （**先正向确认那个步骤真在，再查 paths**），原有 paths 断言从 3 条扩到 8 条。

Task 12: 实现完成 2cb2af9。**697 passed / 18 ignored**（基线 677/18，+20 =
  5 manifest_embed + 14 app_workflow + 1 ci_workflow）。七道闸门全绿零告警、
  Cargo.lock 零变动。

**两笔大债确实关掉了，但实现者如实指出「不是被我关掉的」**——
  是 brief 自带的 `windows-2022` job 关掉的（`cargo test -p rmc-win -p rmc-app`
  关 W199/W208，同 job 的原生 clippy 关 W204），**它做的是把它们钉住**。
  **顺带订正我一个数**：我说「395+ 条」，它核出基线实为 **401** 条
  （212+33+4+152），现在 406。

**变异 21 枪全红，最值钱的是 M10b**：把清单关键词挪进 pwsh 的 `#` 注释、
  同时把断言从 `run_code` 换成 `run_text` → **rc=0，14 条全绿**，
  **第 18 个假绿一字不差复现**。这证明 M10 能打红的功劳全在 `run_code()`。

**它途中自查出一处自己的假绿，形态是新的**：M5 第一版的「注入确认」needle
  **带了换行**，`grep -F` 把它当成两个模式、**空模式匹配每一行**，
  计数打出 142——**那道确认当场退化成 no-op**。
  已在探针脚本里 `assert "\n" not in needle` 堵死。
  **这是第七次有实现者在交付前抓住自己的假绿**，而且这一次栽的正是
  W210 刚立的那道「注入后 grep -c 确认」的防线本身。

W223 核实结论：那三个系统包**全都不需要**——依赖图里没有任何 wayland crate，
  `xkbcommon-dl` 是 dlopen 绑定、无 build.rs，228 个包里带 `-sys` 的
  只有两个纯 Rust 包。整步删掉。

Task 12: 评审与修复轮 b8685f6（去掉 `panic = "abort"`——理由是假的，
  `events.rs:712` 有生产 `catch_unwind`；step 级 `if` / `continue-on-error`
  两个静默出口改成全等断言）。Task 12: complete。**十二个任务全部完成。**
  收尾状态：697 passed / 18 ignored，七道闸门全绿。

=== 第一次真上 GitHub Actions（用户 push 了 feat/rmc-win）===
unit / integration / deny 三个 job 绿；`app.yml` 的两个 job **全红**。
两个都是**真的平台缺陷**，不是 CI 配置问题，本机与 windows-gnu 两道闸门
**按构造都看不见**。

Ruling W225（Linux：**W113 的结论推错了**）：
  W113 写的是「Linux 上窗口大概率起不来」，W223 又据此删了系统包。
  实情是**整个 crate 在 Linux 上编不过**：`iced_tiny_skia` 以
  `default-features = false` 依赖 softbuffer，而 softbuffer 的 Linux 后端
  （x11 / wayland / kms）全靠 feature 开、只能从 `iced/x11`、`iced/wayland`
  传下来；两个都关 → 后端枚举为空 → 25 条 E0004/E0392/E0282。
  macOS / Windows 上后端按 target 自动选，所以哪儿都看不见。
  **「推理出来的结论」在这个项目里第 N 次输给「跑一遍」。**
  修法：`[target.'cfg(target_os = "linux")'.dependencies]` 给 iced 开 `x11`
  （全是 dlopen，不需要任何系统包——W223 删包那一半仍然成立）。
  Cargo.lock +11 个 Linux-only 包，deny 四项 ok。
  在 `rust:1.89` 容器里用最小探针**两头验证**过（零 feature → 同款错误；
  开 x11 → 编过）。

Ruling W226（Windows：**路径分隔符**）：
  `wording.rs` 的扫描器用 `Path::display()` 给文件起名，Windows 上得到
  `view\maintain.rs`；`tests/wording.rs` 的锚点表写的是 `view/maintain.rs`。
  前三个锚点（`lib.rs`/`theme.rs`/`form.rs`）不含分隔符所以过了，
  **恰好死在第一个带 `/` 的条目上**——这个形状本身就是证据。
  修法：`portable_name()` 按 component 用 `/` 重新拼。
  **这条红测是好消息**：它是「扫描真的扫到了本 crate 源码」那条反向自证，
  它红说明那道防线在 Windows 上是真在跑的。

Ruling W227（两条 CI 测试命令加 `--no-fail-fast`）：
  Windows job 死在 rmc-app 的 wording 上，cargo 就此停手，
  **rmc-win 的 152 条在真 Windows 上至今一条没跑过**。
  一次 CI 往返要用户手动 push + 转述，单次往返的信息量必须拉满。
  `TEST_COMMAND` 同步改，注释写明这是唯一允许的额外 flag。

Ruling W228（容器忠实复现 linux job 之后，又抓到 2 条只在 Linux 红的测试）：
  `view/logs.rs` 的 `each_operating_system_has_its_own_monospace_family`
  末尾有一句 `monospace_family(本机 OS).is_some()`，
  而它上面第四格刚断言 `monospace_family("linux") == None`——
  **同一条测试里两句话在 Linux 上自相矛盾**；
  `the_monospace_font_really_draws_chinese` 里有一句 `.expect("本机该有等宽字体")`。
  根因同一个：**把一条环境假设（「测试跑在 macOS 或 Windows 上」）
  写成了性质断言**。本机恒真，所以十二个任务里没人见过它红。
  修法：`mono()` 拆出 `font_for(Option<&'static str>) -> Font`，
  `None → Font::default()` 那一支**从此在 macOS 上也验得到**
  （此前它在生产里只有 Linux 会走到、**从来没被任何一次测试执行过**）。
  新增 `a_system_without_a_known_family_falls_back_to_the_default_font`。
  变异四枪全红、各自被该红的那条抓住：
    K1 `mono()`→`Font::MONOSPACE`            → draws_chinese 红
    K2 `"windows"`→`None`                     → each_operating_system 红
    K3 `font_for` 的 `None`→`Font::MONOSPACE` → 新测试红（**在 macOS 上**）
    K4 `mono()`→`Font::with_name("Courier")`  → draws_chinese 红
  途中 K1/K4 的锚点撞了 2 次（4 空格缩进的生产行是 12 空格缩进的测试行的
  子串），`assert n == 1` 当场拦下；改成**整行精确相等**匹配后重打。
  （W156 同族：锚点要按「整行」而不是「子串」想。）

事故记录（磁盘）：容器第一次跑到一半 `No space left on device`。
  宿主盘 98%，**scratchpad 里攒了 47GB 的各轮评审 `CARGO_TARGET_DIR`**。
  确认无进程占用后清掉 → 66MB，腾出 53GB。
  **纪律：每一轮评审/修复结束就清自己的 target 目录，别留到下一轮。**
  仓库自己的 `target/` 25GB 没动（那是用户的，已口头提过 `cargo clean`）。

CI 修复提交：3f81090（六个文件）。容器复验 linux-checks 三条命令全 rc=0
  （rmc-app lib 218 / ui 33 / wording 4，rmc-win 152）；本机七道闸门全绿，
  **698 passed / 18 ignored**。
  提交前自查又订正了我自己刚写的两句不实注释（`TEST_COMMAND` 旁那句把
  152 条说成「DPAPI、托盘、电源事件」——**`#[cfg(windows)]` 那几层根本没有测试**；
  `portable_name` 文档里那句「豁免表写的也是 `/`」——豁免表今天唯一一条是
  不带目录的 `config.rs`）。**假注释第 4、5 处，这次是我自己的。**
  Windows 侧预排查结论：无 windows 专属测试；读源码的测试都走 `.lines()`
  （CRLF 检出无碍）；按文件名前缀判断的只用到顶层文件；unix API 全有门控。
  **剩下的只有真 runner 验得到**——等用户 push 后转述 windows-build 的结果。

=== 2026-09-21：用户 push 3f81090 后，GitHub Actions **全绿** ===
unit / integration / deny / linux-checks / windows-build 五个 job 全过。
**这一次关掉的盲区（此前全部「只有真 runner 验得到」）：**
  - rmc-win 152 条 + rmc-app 255 条**第一次在真 Windows（windows-2022, MSVC）上跑过**
    ——W199/W208 那笔债到这里才算真的还清（Task 12 只是把出口钉住）；
  - `build.rs` 的 `/MANIFEST:EMBED` + `/MANIFESTINPUT:` 两个 MSVC 链接参数
    **第一次被真的 link.exe 吃下去**，「确认清单已嵌入」那一步第一次真跑；
  - 原生 MSVC clippy（W204）第一次真跑；release 构建与便携包上传第一次真跑；
  - W225 的 `iced/x11` 修法在 ubuntu-24.04 真 runner 上成立（容器复现的结论没有偏差）。
**仍然没有任何自动化证据的**（交接清单，不因为 CI 绿而消失）：
  `main()` 的接线；`#[cfg(windows)]` 那几层 Win32 封装（DPAPI / 托盘 / 电源事件 /
  WinHTTP / SSPI）**零测试**——只能靠 `docs/windows-验收清单.md` 人工验；
  W205 Explorer 重启后托盘图标丢失；W106 520×720 窗口在 150% 缩放下；Consolas 字体路径。
状态：feat/rmc-win = origin/feat/rmc-win = 3f81090，领先 main（1bda177）31 个提交，
  main 是它的祖先，`--ff-only` 可行。**合并与 push main 留给用户决定。**
