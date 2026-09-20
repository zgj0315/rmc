//! 状态机。唯一改变 [`crate::state::State`] 的地方，界面只读事件、只发命令。
//!
//! 见方案 3.5/3.6。行为规约（何时重连、何时退避、何时判 Fatal）几乎全部
//! 落在这个文件里，是整个内核裁决密度最高的一块。
//!
//! # 与 brief 不同的几处，逐条写明理由
//!
//! 1. **（Task 10 时点）不依赖 `crate::audit`**——那个模块和 `Ctx::audit`
//!    字段当时都还不存在，Task 10 的实现不引用它，也不调用任何
//!    `audit.record(...)`。Task 11 已经把它接上了，见 `Ctx::audit` 与
//!    下面「评审第五轮」小节；这一条留着只是如实记录 Task 10 交付时的
//!    状态，不再是当前事实。
//! 2. **全程用 `tokio::time::Instant`，不用 `std::time::Instant`**——
//!    `retry_at`/`probe_at`/`port_busy_since` 都要喂给
//!    `tokio::time::sleep_until`，测试跑在 `#[tokio::test(start_paused =
//!    true)]` 的虚拟时钟上；如果这几个字段是 `std::time::Instant`，
//!    `std::time::Instant::now()` 拿到的是真实挂钟时间，虚拟时钟推进
//!    之后 `now() + delay` 算出来的截止点会变成一个已经过去的时刻，
//!    `sleep_until` 立刻返回；`PortBusy` 分支里的 `since.elapsed()`
//!    同理，量的是真实时间，虚拟时间里恒为 0，120 秒预算永远到不了。
//!    两者叠加的后果不是测试失败，是**挂死**。
//! 3. **`port_busy_since` 在任何非 `PortBusy` 错误发生时都会被清空**——
//!    不止在建连成功和 `Command::Start` 时清。否则"端口占用→网络错误
//!    →五分钟后全新的端口占用"这个序列会在第三步被误判成"预算已经用
//!    完"，一次重试都不给就直接 `Failed`。
//! 4. **`ErrorClass::ApplianceUnreachable` 不与 `Network` 共用退避分支**
//!    ——方案 §3.6 要的是"隧道保持、转 degraded、每 30 秒探测"，跟
//!    `Network` 类"整条隧道拆了重建、指数退避"是两种完全不同的处置。
//!    这条路径目前没有任何生产调用点会走到（见 [`schedule_retry`] 上的
//!    说明），但 `schedule_retry` 是按 `Error::class()` 泛化处理的，
//!    错误的默认值一旦以后被某个新增调用点撞上，后果是把"探测一体机"
//!    误判成"网络抖动"，所以照样单独给一条分支、并且有一条直接调用
//!    `schedule_retry` 的单元测试钉住它。
//! 5. **`Backoff { attempt }` 在 `PortBusy` 路径上不再恒为 0**——原
//!    brief 那条路从不调用 `backoff.next_delay()`/推进 `Backoff` 的
//!    计数，导致界面在整整 120 秒里一直显示"第 0 次重连"。这里单独
//!    维护一个只在 `PortBusy` 序列里递增的计数，供 `State::Backoff`
//!    上报，不与网络类的指数退避计数混用（两者的语义不同：一个是
//!    "第几次固定 5 秒重试"，一个是"退避表走到第几项"）。
//! 6. **预检经 Task 9 交付的 [`crate::preflight::Preflight`] trait 注入**
//!    ——不直接调用 `preflight::run` 自由函数。`Deps::preflight` 是
//!    生产用 `TransportPreflight`，测试用一个立即返回全 `Pass`（或按
//!    需要脚本化）的假实现，`Scripted` 假隧道工厂才有机会被真正调用到。
//! 7. **公开的 `Command::Start` 一定会先校验地址关系**——处理该命令时
//!    先调用 `config::ValidatedAddresses::validate(gateway, appliance)`，
//!    校验通过才会继续（跑预检、建隧道）；校验失败直接进
//!    `State::Failed { class: Fatal, .. }`，`Deps::factory` 一次都不会
//!    被调用。需要 loopback 一体机地址的测试（`degraded_probe_recovers_
//!    when_the_appliance_comes_back` 一类）不走这条公开入口，改用
//!    `Supervisor::spawn_with_validated_start`——见该函数上的说明，
//!    这是唯一的另一条路，`#[cfg(test)] pub(crate)`，生产构建里根本
//!    不存在这个符号；`pub enum Command` 的任何变体字段在 Rust 里都无法
//!    单独收紧可见性（试过给字段标 `pub(crate)`，编译器报 `E0449`：
//!    "enum variants and their fields always share the visibility of the
//!    enum they are in"），所以这条内部入口不是 `Command` 的又一个
//!    变体，而是一个独立的、`#[cfg(test)]` 门控的构造函数。
//!
//! # 评审第二轮追加的修复（R58-R70），逐条写明理由
//!
//! 8. **[R58] Preflight/Connecting 期间 `Cancel`/`Stop` 现在真的会立刻
//!    生效**。上一版把预检 + 建隧道整段 `.await` 在处理
//!    `Command::Start` 的那一个 `select!` 分支里，期间 `select!`
//!    不会再去看下一条命令——预检卡住多久，`Cancel` 就要等多久才生效。
//!    现在预检 + 建隧道被拆进独立的后台任务
//!    [`run_connect_sequence`]，主循环靠 [`ConnectEvent`] 通道跟踪
//!    进度，`Cancel`/`Stop` 到达时如果这个任务还在跑，直接
//!    `JoinHandle::abort()`。见 `Ctx::connect_task`。
//! 9. **[R61] 迟到的 `TunnelMsg`/`ConnectEvent` 不会污染新的一次尝试**
//!    ——[`spawn_connect`] 每次都新建一对 `msg_tx`/`msg_rx` 与
//!    `connect_tx`/`connect_rx`，主循环里的 `msg_rx`/`connect_rx`
//!    局部变量随之整体替换，旧的接收端直接被丢弃。旧的后台任务
//!    （已经被 `abort()`，或者已经跑完但对应的隧道已经被拆掉）手里还
//!    攥着的发送端只要 `.send()`，会因为对应的接收端已经不存在而直接
//!    返回 `Err`（已经用 `let _ = ...` 忽略），不可能被"新"的这一次
//!    尝试听到。不需要给消息加会话代号/世代号，channel 的生命周期本身
//!    就是唯一性凭证。
//! 10. **[R62] `Command::Start` 地址校验失败时会清空 `ctx.creds`**——
//!     否则用户改错地址后点"重试"（`Failed` 状态下允许 `RetryNow`）
//!     会拿旧地址旧口令去连，界面刚报的地址错误跟实际连接的目标对
//!     不上。
//! 11. **[R58 附带] `Command::Cancel`/`Command::Stop` 现在处理路径
//!     完全一致，但行为不再等价**——上一版由于 Preflight/Connecting
//!     不可中断，两者在那两个阶段实际上都要等到建连流程结束才生效，
//!     观察不出差异；现在 `Cancel`/`Stop` 在 Preflight/Connecting 期间
//!     都会真的中断在建立中的连接，差异只体现在**响应速度**上（见
//!     `cancel_during_preflight_takes_effect_immediately_not_after_
//!     the_whole_sequence`），命令语义本身仍按 brief 原样合并，等
//!     后续任务如果需要更细的区分再拆。
//!
//! 与状态机行为无关、纯粹是测试基础设施/文档的修复（R59/R63/R69/R70）
//! 分别记在 `ssh/pump.rs`、本文件测试模块对应测试上方、以及
//! `docs/方案设计.md` §3.4。
//!
//! # 评审第三轮追加的修复（R71-R74），逐条写明理由
//!
//! 第二轮的结构性重构（拆出后台连接任务）引入了两条新的、同源的
//! 并发缺口，都只在**真正多线程**下才会现形——本文件其余测试全用
//! 单线程 `current_thread` 运行时，观察不到。
//!
//! 12. **[R71] 三处命令准入判断改看同步字段，不再看 `ctx.state`**——
//!     `ctx.state` 要等后台连接任务送回第一条 `ConnectEvent` 才会
//!     离开 `Idle`，这中间有一段异步延迟。如果调用方背靠背发两条
//!     命令、中间没有任何 `.await`（例如 `Start` 之后立刻
//!     `Cancel`，或者连续两次 `Start`），第二条命令被处理时
//!     `ctx.state` 可能仍然是 `Idle`：`Cancel` 的准入判断
//!     `matches!(ctx.state, Idle) { continue }` 会把它当成"没有什么
//!     可取消"直接吞掉；第二次 `Start` 的准入判断
//!     `matches!(ctx.state, Idle | Failed)` 会误判为"可以开始"，
//!     调 `spawn_connect` 覆盖 `ctx.connect_task`——旧的 `JoinHandle`
//!     被直接丢弃，`JoinHandle` 的 `Drop` 不会 `abort()` 它，那个任务
//!     会在后台裸跑到底，即使它建成了隧道，句柄也没人接手、没人
//!     `shutdown()`，Gateway 上会留下一条活着的会话和一个已注册的
//!     反向端口。
//!
//!     修法：`connect_task`/`handle`/`retry_at` 三者都是在处理对应
//!     命令的**同一步**同步写入的，不存在这段异步延迟，用它们（而不
//!     是 `ctx.state`）做准入判断——见 [`connecting_or_connected`]。
//! 13. **[R72] `Cancel`/`Stop` 与"建连刚好成功"撞车时，隧道曾经会
//!     永远不被 `shutdown()`**——`teardown()` 原来只 `abort()` 任务，
//!     不等它真正停下来、也不排空 `connect_rx`。被 `abort()` 的任务
//!     如果当时正好在另一个线程上跑到 `establish()` 刚返回、准备
//!     `connect_tx.send(Established(handle))` 那一步，`abort()` 生效
//!     前这条消息仍可能被送出；`ctx.connect_task` 这时已经被
//!     `teardown()` 清空，`connect_rx` 分支的 guard 随之关闭，这条
//!     "卡在半路"的 `Established` 连同它携带的隧道句柄从此没有任何
//!     人会再看它一眼——既不会被主循环认领（`ctx.handle` 不会被设
//!     置），也不会被 `shutdown()`。界面显示"已停止"，Gateway 上却
//!     有一条活着的会话和一个占着的反向端口，且从界面完全无法诊断。
//!     这正是方案 §3.6"端口占用"那条故障的成因之一。
//!
//!     修法：`teardown()` 现在 `abort()` 之后 `.await` 那个
//!     `JoinHandle`，确保任务真正结束（不管是被取消，还是恰好在这
//!     之前就跑完）之后才去 `try_recv()` 排空 `connect_rx`——`.await`
//!     这一步是必需的，单纯 `abort()` 后立刻 `try_recv()` 不能排除
//!     "消息还在路上、还没被送进 channel"这个窗口；等 `JoinHandle`
//!     完成之后，任务不可能再发送任何东西，排空才是完整的。排空时
//!     如果翻到一条 `Established`，直接 `shutdown()` 它带的隧道句柄。
//! 14. **[R73] 把多线程竞态从"靠时序赢"改成"结构上不存在"**——第二轮
//!     用 `biased` 让 `connect_rx` 排在 `msg_rx` 前面赢下了这条竞态，
//!     但 `biased` 只决定"两者同时就绪时先看哪个"，不能排除
//!     "`msg_rx` 已经就绪、`connect_rx` 还没就绪"这个窗口——它能让
//!     那条已知的竞态消失，不能证明**不存在**别的、还没被观察到的
//!     变体。把 `msg_rx` 分支的 guard 从
//!     `handle.is_some() || connect_task.is_some()` 收紧成单纯
//!     `handle.is_some()`：建连期间产生的 `TunnelMsg`（哪怕是隧道刚
//!     建成那一刻就跟着来的）会先在 256 容量的 channel 缓冲区里等着，
//!     只有 `ctx.handle` 真的被设置之后（即 `Established` 已经被
//!     处理过）guard 才会打开，`msg_rx` 里排在前面的消息才会被按 FIFO
//!     顺序处理到——`Established` 必然先于任何 `TunnelMsg` 被处理，
//!     这是 channel 的顺序保证给出的结构性事实，不再依赖调度谁先跑。
//! 15. **[R74] 顺手带上的四处**：
//!     - 连接任务如果 panic（`Preflight`/`TunnelFactory` 实现里的
//!       bug），原来会让状态机永久卡在 `Preflight`/`Connecting`——
//!       没有人观察 `JoinHandle` 的错误。`run_connect_sequence` 内部
//!       现在有一个 [`FailOnPanic`] scope guard：只要函数还没走到任何
//!       一条终态 `send`（`PreflightFailed`/`Established`/`Failed`）
//!       就先把 guard 解除武装，panic 引发的栈展开会经过这个 guard 的
//!       `Drop`，未解除武装就送一条兜底的 `ConnectEvent::Failed`，
//!       状态机照常转入 `Backoff`/`Failed`，不会永久挂起。
//!     - `Command::Start` 与 `Supervisor::spawn_with_validated_start`
//!       初始化一次新会话的逻辑原来是两份几乎相同的重复代码，抽成了
//!       共享的 [`begin`]。
//!     - 已经在
//!       `degraded_stays_degraded_while_the_appliance_is_still_down`
//!       补了一层自检：绑一个端口立刻释放当"死地址"存在理论上的极窄
//!       复用窗口（另一个并发测试的 `bind(0)` 抢先复用同一个端口
//!       号），现在绑完立刻回连一次确认真的被拒绝，不行就换一个重试
//!       几次。
//!     - `ssh/pump.rs` 里 R59 那条测试的哨兵断言原来只检查"捕获到过
//!       至少一条日志"，换成 `set_global_default` 之后，全 crate 唯一
//!       那行 `warn!` 还有另一条测试也会触发它，哨兵现在只能证明
//!       "这个 callsite 能被捕获"，不能证明"是本测试自己那次触发被
//!       捕获"——已经改成对捕获内容做匹配来加固。
//!
//! # 评审第四轮追加的修复（R75-R78），逐条写明理由
//!
//! 16. **[R75，必现] 系统事件分支是"用 `ctx.state` 做准入判断"的第三
//!     个入口，而且是唯一一个必现的**——第三轮（R71）把
//!     `Start`/`Cancel`/`Stop`/`RetryNow` 四处准入判断都改成了看同步
//!     字段，但 `sys.recv()` 那条分支被漏掉了，它仍然写着
//!     `matches!(ctx.state, State::Backoff { .. })`。
//!
//!     `retry_at` 触发（或者 `RetryNow`）之后，`spawn_connect` 已经
//!     **同步**写好了 `ctx.connect_task`，而 `ctx.state` 要等后台任务
//!     回 `EnteredConnecting` 才离开 `Backoff`。这个窗口里再来一条
//!     网络/唤醒事件，分支里的 `spawn_connect` 会直接覆盖
//!     `ctx.connect_task`（旧 `JoinHandle` 被丢弃、从不 `abort()`）
//!     **并且覆盖 `pending_handle` 槎位**——旧任务建成的隧道写进的是
//!     已经没人持有的那个槎位，`Arc` 归零后句柄被 drop。
//!
//!     触发条件是现场最普通的一条路径：笔记本从睡眠恢复时本来就会
//!     同时产生 `ResumedFromSleep` 与 `NetworkChanged`（方案 §3.9 明确
//!     要求两者都接），而恢复那一刻状态机几乎必然正在 `Backoff`。这
//!     不是竞态：单线程下 `spawn_connect` 起的任务在主循环真正 park
//!     之前根本没机会被调度，第二条事件必然撞在这个窗口里，本地
//!     实测 20/20 必现。修法与 R71 一致：`retry_at.is_some() &&
//!     !connecting_or_connected(&ctx)`。
//!
//!     这已经是同一个根源第三次造成隧道泄漏，所以这一轮同时在
//!     `SshTunnel` 上加了 `Drop`（R76，见 `ssh/mod.rs`）做纵深防御
//!     ——逐个堵调用点是治标，让"句柄被丢弃"这件事本身不再等于
//!     "Gateway 侧泄漏"才是治本。
//! 17. **[R77] 三处被证伪的说法已订正**——`degraded_stays_degraded_
//!     while_the_appliance_is_still_down` 里那段解释"死地址加固为何
//!     失败"的注释、`preflight.rs` 模块文档里"真实 I/O 会让
//!     `start_paused` 测试挂起"那一条、以及
//!     `cancel_racing_a_successful_establish_never_leaks_the_tunnel_
//!     handle` 上"删掉槎位兜底第 0 次迭代就失败"那一条，成因/结论都
//!     写得不准确。真相记在各自的注释里（一句话版本：`start_paused`
//!     的自动前进量取自时间轮**层级槽的边界**，不是定时器的真实到期
//!     时刻，所以一次真实 I/O 的 `await` 会让虚拟钟一步跳掉 262 秒）。
//!     那个当时被回退的自检也零风险地加了回来——改用阻塞的
//!     `std::net::TcpStream::connect_timeout`，完全不经过 tokio 的
//!     I/O driver，不会让运行时 park。
//! 18. **[R78，安全] `Failed` 状态下 `Stop` 必须仍然有效**——R71 的新
//!     准入条件让 `Failed` 下 `Cancel`/`Stop` 都成了空操作。按方案
//!     §3.5 的表格，`Failed` 只允许"重试、查看诊断"，从状态机角度这
//!     更贴规格；但副作用是 `Failed` 期间那份 `Zeroizing<String>`
//!     口令会一直留在进程内存里，直到下一次 `Start` 或进程退出——而
//!     §3.8 当时明确要求口令"仅存于进程内存，认证后清除"，工程师遇到
//!     失败之后合上笔记本走人恰恰是最常见的收尾方式。（R82：§3.8 的
//!     措辞已经订正，不再写"认证后清除"——断线重连要复用凭据，实际
//!     行为一直是留到会话结束/`Stop`/认证失败/地址校验失败为止，这
//!     里保留的是当时发现冲突时的原始措辞，方便理解这条裁定从何而来。）
//!
//!     裁定：两条规格冲突时安全那条优先。`Failed` 下 `Stop` 有效
//!     （走 `teardown`、清 `creds`、回 `Idle`），`Cancel` 保持空操作
//!     ——`Cancel` 是"取消正在进行的这次开启"，`Stop` 是"我不玩了"，
//!     后者在任何状态下可用符合直觉。两者受理之后的动作完全相同，
//!     抽成了共享的 [`stop_everything`]，差别只在准入判断上。
//!
//! # Task 11（审计日志）复审追加的修复（R80-R91）
//!
//! 19. **[R80] `retry_at` 收进 `Ctx`，抽出 [`in_backoff`]**——原来
//!     `retry_at: Option<Instant>` 是 `run()` 的局部变量，靠
//!     `retry_at.is_some()`/`retry_at.is_none()` 表达"处于 Backoff"
//!     这件事，散在 `Command::Start`、`Command::Cancel`、
//!     `Command::Stop`、`sys.recv()` 四处，没有单一出处，容易在新增
//!     入口时漏抄。现在字段随 `Ctx` 走，四处判断都改叫
//!     [`in_backoff`]。[`schedule_retry`] 也顺带改成直接写
//!     `ctx.retry_at`（不再靠调用方把返回值转赠出去）。
//!
//!     **第五处入口**：重试定时器分支
//!     （`tokio::time::sleep_until(sleep_until), if retry_at.is_some()`）
//!     是四个 `spawn_connect` 调用点里唯一一个准入判断不含
//!     `connecting_or_connected` 的，只写了 `in_backoff(&ctx)`。上一轮
//!     复审追到底：不变量 `ctx.retry_at.is_some() ⟹
//!     !connecting_or_connected(&ctx)` 目前成立（`retry_at` 与
//!     `connect_task`/`handle` 从不同时被置位——凡是让其中一个变
//!     `Some` 的路径都会先把另一侧清空），这一处现在没有缺陷，但它的
//!     正确性完全靠一条从未被写下、也没有断言保护的不变量，形状与
//!     R71/R75 连栽三次的那类缺口一模一样。这里把
//!     `!connecting_or_connected(&ctx)` 显式加成第二个 guard 条件——
//!     不改变任何现有行为（不变量本来就成立，现有覆盖 Backoff/重试
//!     路径的测试全部继续通过就是证据）。
//!
//!     **R89（复审订正）**：上一版这里写的是"把隐性假设变成一处会在
//!     假设被打破时立刻炸掉的检查"——这句话是反的。真实的失效模式
//!     正相反：不变量一旦被打破，这个 `select!` 分支的 guard 会变成
//!     `false`，分支被静默禁用，`retry_at` 会一直留在 `Some`、重试
//!     定时器再也不会触发——**静默卡死在 Backoff**，没有断言、没有
//!     日志、`cargo test` 也不会报错（除非正好有测试在等这一次重试，
//!     那会在 300 秒虚拟超时后才报"等待状态超时"）。加固本身的方向
//!     没错：把"双重建连"这一类更严重的后果（R71/R75 那三次真实
//!     泄漏）换成了"卡住"这个更安全但更隐蔽的后果——只是不该用
//!     "立刻炸掉"这种话来形容它，误导下一个人以为这里有主动报警。
//! 20. **[R81] `SshTunnel::Drop` 兜底触发时补一条 `tracing::warn!`**
//!     ——见 `ssh/mod.rs` 里 `impl Drop for SshTunnel` 上的说明。这条
//!     兜底本身是 R76 加的纵深防御；上一轮实现者拒绝在 `Drop` 里打
//!     日志，理由是 `ssh/pump.rs` 那条哨兵测试对全 crate 的 `warn!`
//!     分布有依赖——那条测试现在已经改成对捕获内容做匹配（含
//!     "22002"、不含转发内容特征字节），不再要求"全 crate 只有一处
//!     `warn!` callsite"，这个顾虑不成立了。信号放在 `tracing`、不放
//!     审计日志：兜底生效意味着代码本身有 bug（某处又漏了
//!     `shutdown()`），这是给开发者/维护者看的实现缺陷信号，不是给
//!     现场工程师或事后追责审计看的运维事件——审计日志的受众关心
//!     "谁连到了哪台一体机"，不关心"哪一行 Rust 代码忘了收尾"。
//! 21. **[R83，最要紧] `teardown()` 里残留的远程会话不再被静默丢弃**
//!     ——评审用探针实证：`RemoteSessionOpened{7}` →
//!     `RemoteSessionBytes{111,222}` → `Disconnected`（没有显式的
//!     `RemoteSessionClosed`），审计日志原来到"远程会话 7 已开启"
//!     为止，没有任何关闭记录。这正是最常见的收尾路径：远程工程师
//!     正连着客户一体机，现场笔记本断网，或者现场人员点"停止"。
//!     不是时序运气：`msg_rx` 的 guard 是 `ctx.handle.is_some()`，
//!     `teardown()` 已经把 `self.handle` 取走，即使 pump 补发了
//!     `RemoteSessionClosed` 也永远不会被 `handle_msg` 处理到，是
//!     结构性的必然。修法：`teardown()` 现在对 `self.sessions` 里
//!     残留的每一条都补一次收尾账，跟正常关闭共用抽出来的
//!     [`record_session_closed`]，口径一致。
//! 22. **[R84] 审计内容原来除了口令测试那四条粗断言之外零覆盖**——
//!     评审把 `begin()` 的"Gateway，一体机"整段、
//!     `RemoteSessionOpened`/`RemoteSessionClosed`/`ForwardRegistered`
//!     四处审计行全删，183 个测试全绿。"连到了哪台一体机"这个
//!     Task 11 自己定义的核心追责要素，一次重构就能悄悄消失，没有
//!     任何测试会报警。补法：`remote_sessions_are_reported_with_
//!     traffic_and_removed_on_close` 现在额外读回审计日志内容；
//!     `schedule_retry` 那一行错误原文的覆盖在
//!     `auth_failure_returns_to_idle_and_does_not_retry` 里补上。
//! 23. **[R90] `audit.prune()` 不再只在启动时跑一次**——见
//!     [`AUDIT_PRUNE_INTERVAL`] 上的说明：现场笔记本经常连续开机
//!     运行数周不重启，`RETENTION_DAYS` 因此事实上失效。`run()` 主
//!     循环现在每隔这么久重新清理一次。
//! 24. **[R91] 四条零碎**：`TunnelMsg::Disconnected` 原来先记一行
//!     "SSH 隧道断开"，`schedule_retry` 紧接着又记一行"SSH 链路
//!     中断"——同一次断线连续两行几乎同义的记录，实测相邻，现在只在
//!     `ctx.creds` 已经是 `None`（`schedule_retry` 不会被调用）这个
//!     防御性分支里才补记一次；`Ctx::set_state` 原来用 `{:?}` 拼状态
//!     迁移行，日志里会出现 `Connected { degraded: false }` 这类 Rust
//!     结构体语法，改用 [`describe_state`] 写成人话；`docs/方案
//!     设计.md` §3.5 表格下的说明与 `ssh/pump.rs` 里两处"全 crate
//!     唯一那行 `warn!`"的注释都已经跟着 R81/R82 一并订正。

use crate::audit::{Audit, Level};
use crate::backoff::{Backoff, Jitter};
use crate::config::{Config, ValidatedAddresses};
use crate::error::{Error, ErrorClass};
use crate::platform::{SystemEvent, SystemEvents};
use crate::preflight::{self, Preflight};
use crate::state::{Command, RemoteSessionInfo, State, TunnelEvent};
use crate::transport::Transport;
use crate::tunnel::{TunnelFactory, TunnelHandle, TunnelMsg, TunnelParams};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const PORT_BUSY_RETRY: Duration = Duration::from_secs(5);
pub const PORT_BUSY_BUDGET: Duration = Duration::from_secs(120);
pub const APPLIANCE_PROBE: Duration = Duration::from_secs(30);
/// R90（复审发现）：`audit.prune()` 原来只在 `run()` 启动时调用一次。
/// 现场笔记本经常连续开机运行数周不重启，`RETENTION_DAYS` 因此事实上
/// 失效——保留期清理逻辑本身没坏，只是没有第二次被叫到的机会。这里
/// 让 `run()` 的主循环每隔这么久重新清理一次，不需要重启进程。
pub const AUDIT_PRUNE_INTERVAL: Duration = Duration::from_secs(24 * 3600);

const EVENT_CAPACITY: usize = 256;
const MSG_CAPACITY: usize = 256;
const CONNECT_EVENT_CAPACITY: usize = 8;

pub struct Deps {
    pub factory: Arc<dyn TunnelFactory>,
    pub transport: Arc<Transport>,
    pub preflight: Arc<dyn Preflight>,
    pub events: Arc<dyn SystemEvents>,
    pub jitter: fn() -> Box<dyn Jitter>,
}

/// 一次 Start 之后持有的凭据，断线重连时复用，不需要界面再问一遍口令。
/// R——第九条：`Credentials` 只在本文件内部构造与消费（唯一的构造点在
/// 处理 `Command::Start` 与 `Supervisor::spawn_with_validated_start` 的
/// 初始化逻辑，唯一的输入是一份 `ValidatedAddresses`），换成直接持有
/// `ValidatedAddresses` 而不是拆开的 `gateway`/`appliance: HostPort`
/// 在这里是"免费"的——不像 `tunnel::TunnelParams`/`ssh::SshTunnelFactory`
/// 那样有外部集成测试（`tests/ssh_tunnel.rs`，用 127.0.0.1 一体机地址）
/// 依赖着裸 `HostPort` 的字段类型，改了会让那个外部 crate 编译不过（见
/// `tunnel.rs` 顶部 R20/R48 的详细权衡）。这里没有类似的外部依赖，直接
/// 把"这对地址已经校验过"这件事在类型上多留一层证据。
struct Credentials {
    username: String,
    password: Zeroizing<String>,
    addrs: ValidatedAddresses,
}

impl Credentials {
    /// R96：`gateway` 也从这里出去。这是 `Command::Start` 携带的那台
    /// Gateway 第一次真正参与拨号——在此之前它只流向地址关系校验、
    /// `Preflight::run` 与审计日志，隧道实际连的是 `SshTunnelFactory`
    /// 构造时就固定的另一个地址，两者失配时没有任何东西会报错。因果
    /// 与实测见 `tunnel::TunnelParams` 上的 R96 说明。
    ///
    /// 会让 `start_passes_the_commanded_gateway_all_the_way_to_the_
    /// factory` 变红的实现改法：把下面这一行换成任何别的地址。
    fn params(&self, reverse_port: u16) -> TunnelParams {
        TunnelParams {
            username: self.username.clone(),
            password: self.password.clone(),
            reverse_port,
            gateway: self.addrs.gateway().clone(),
            appliance: self.addrs.appliance().clone(),
        }
    }
}

pub struct Supervisor;

impl Supervisor {
    pub fn spawn(
        cfg: Config,
        deps: Deps,
    ) -> (mpsc::Sender<Command>, broadcast::Receiver<TunnelEvent>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (ev_tx, ev_rx) = broadcast::channel(EVENT_CAPACITY);
        tokio::spawn(run(cfg, deps, cmd_rx, ev_tx, None));
        (cmd_tx, ev_rx)
    }

    /// 仅供本 crate 内部测试：跳过 `Command::Start` 对地址关系的校验，
    /// 直接携带一份已经用 `config::ValidatedAddresses::for_test`
    /// 构造好的地址对，在 Supervisor 启动后立即当作第一个「开启」动作
    /// 处理——等价于把 `Command::Start` 换成一个跳过校验的版本，见模块
    /// 顶部第 7 条对"为什么不是给 Command 加一个变体"的说明。
    ///
    /// 用途：需要一体机地址是 `127.0.0.1:{port}` 的测试（探测恢复、探测
    /// 持续失败两类场景）——这类地址会被公开的 `Command::Start` 拒绝
    /// （一体机不能是本机回环），必须绕过公开入口，但又不能削弱公开
    /// 入口本身的校验。
    #[cfg(test)]
    pub(crate) fn spawn_with_validated_start(
        cfg: Config,
        deps: Deps,
        username: String,
        password: Zeroizing<String>,
        addrs: ValidatedAddresses,
    ) -> (mpsc::Sender<Command>, broadcast::Receiver<TunnelEvent>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (ev_tx, ev_rx) = broadcast::channel(EVENT_CAPACITY);
        let initial = Some((username, password, addrs));
        tokio::spawn(run(cfg, deps, cmd_rx, ev_tx, initial));
        (cmd_tx, ev_rx)
    }
}

/// 一次"开启"过程中，后台连接任务（[`run_connect_sequence`]）往主循环
/// 上报的进度/结果。见模块顶部第 8 条（R58）：Preflight/Connecting 这
/// 两步现在跑在独立的 tokio 任务里，主循环靠这个通道拿到进度，同时
/// 仍然能继续处理命令——尤其是 `Cancel`/`Stop`，能在任务跑到一半时把
/// 它 `abort()` 掉，不用等整个序列（预检 + 建隧道）跑完。
enum ConnectEvent {
    EnteredPreflight,
    PreflightReport(preflight::PreflightReport),
    PreflightFailed {
        class: ErrorClass,
        message: String,
    },
    EnteredConnecting,
    /// R72 深化：这个变体不再携带 `Box<dyn TunnelHandle>`，只是一个
    /// "去 `PendingHandle` 槎位里取"的信号——见 [`PendingHandle`] 上的
    /// 说明。原来直接把句柄装在这个变体里传递，句柄的存亡就绑在这条
    /// 消息能不能被稳妥送达/取出上；如果 `establish()` 成功返回之后、
    /// `connect_tx.send(Established(handle))` 完成之前，任务被
    /// `abort()` 打断（哪怕这个窗口极窄——例如 tokio 的协作式调度
    /// budget 恰好在这两步之间强制插入一次让步），`handle` 会随着
    /// 任务被取消而直接被丢弃，永远没有机会被送进 channel，
    /// `teardown()` 排空 `connect_rx` 也救不回它，因为它压根没被送
    /// 出来过。
    Established,
    Failed(Error),
}

/// R72 深化：`establish()` 成功之后，句柄先同步写进这个槎位，再发送
/// `ConnectEvent::Established` 这个信号——写槎位这一步不跨越任何
/// `.await`，不可能被 `abort()` 打断。无论后续的"发信号"这一步有没有
/// 顺利完成（正常发出、或者被取消打断），句柄都已经安全地待在槎位里；
/// `handle_connect_event` 处理 `Established` 信号时从这里取出句柄，
/// `Ctx::teardown` 在 `abort()` 之后也会检查这个槎位——不管走的是
/// 哪条路径，只要句柄进过这个槎位，就一定会被某一方接手，不会因为
/// 任务被取消的精确时机而丢失。
type PendingHandle = Arc<std::sync::Mutex<Option<Box<dyn TunnelHandle>>>>;

struct Ctx {
    cfg: Config,
    deps: Deps,
    ev: broadcast::Sender<TunnelEvent>,
    state: State,
    creds: Option<Credentials>,
    handle: Option<Box<dyn TunnelHandle>>,
    /// 当前正在跑的"预检 + 建隧道"后台任务；`Some` 意味着状态是
    /// `Preflight` 或 `Connecting`。`Cancel`/`Stop` 会 `.abort()` 它——
    /// 见模块顶部第 8 条（R58）。
    connect_task: Option<JoinHandle<()>>,
    sessions: BTreeMap<u64, RemoteSessionInfo>,
    /// 网络类错误的指数退避序列状态。
    backoff: Backoff,
    /// 端口占用固定节奏下"第几次重试"，只用于上报 `State::Backoff`，与
    /// `backoff`（指数退避序列）各自独立计数——见模块顶部第 5 条。
    port_busy_attempt: u32,
    /// 端口占用重试预算的起点。`None` 表示当前不在一段连续的端口占用
    /// 序列里；任何非 `PortBusy` 的结果（成功、其他类别的错误、一次新
    /// 的 `Start`）都会清空它，见模块顶部第 3 条。
    port_busy_since: Option<Instant>,
    /// 下一次自动重连的时刻，`None` 表示不在 Backoff 等待中——见
    /// [`in_backoff`]。R80：原来是 `run()` 的局部变量，靠散在四处的
    /// `retry_at.is_some()`/`retry_at.is_none()` 表达"处于 Backoff"，
    /// 收进 `Ctx` 之后只有一个出处。
    retry_at: Option<Instant>,
    audit: Audit,
}

/// 是否处于自动重连的等待期（`State::Backoff`，但这个字段是同步维护
/// 的，没有 `ctx.state` 那段异步延迟）——R80，把原来散在
/// `Command::Start`/`Cancel`/`Stop`/`sys.recv()` 四处的
/// `retry_at.is_some()`/`retry_at.is_none()` 收成单一出处。
fn in_backoff(ctx: &Ctx) -> bool {
    ctx.retry_at.is_some()
}

/// 把 `State` 写成人话，不是 Rust 的结构体 Debug 语法——R91（复审
/// 发现）：审计日志面向事后追责，读的人未必是开发者，`Connected {
/// degraded: false }`/`Backoff { attempt: 1, delay: 1s }` 这类语法
/// 对非开发者不友好。`delay` 那个 `Duration` 仍然用 `{:?}`（`5s`/
/// `500ms` 这种，本身已经是人能读的形式），不额外重新实现一遍时长
/// 格式化。
fn describe_state(s: &State) -> String {
    match s {
        State::Idle => "空闲".to_string(),
        State::Preflight => "预检中".to_string(),
        State::Connecting => "建立连接中".to_string(),
        State::Connected { degraded: false } => "已连接".to_string(),
        State::Connected { degraded: true } => "已连接（一体机不可达，降级）".to_string(),
        State::Backoff { attempt, delay } => {
            format!("退避重连中（第 {attempt} 次，{delay:?} 后重试）")
        }
        State::Stopping => "正在停止".to_string(),
        State::Failed { class, message } => {
            format!("失败（{}）：{message}", describe_class(*class))
        }
    }
}

fn describe_class(class: ErrorClass) -> &'static str {
    match class {
        ErrorClass::Fatal => "致命错误",
        ErrorClass::Auth => "认证失败",
        ErrorClass::PortBusy => "端口占用",
        ErrorClass::Network => "网络问题",
        ErrorClass::ApplianceUnreachable => "一体机不可达",
    }
}

impl Ctx {
    fn set_state(&mut self, s: State) {
        let level = match &s {
            State::Failed { .. } => Level::Error,
            State::Backoff { .. } | State::Connected { degraded: true } => Level::Warn,
            _ => Level::Info,
        };
        self.audit.record(
            level,
            &format!(
                "状态：{} → {}",
                describe_state(&self.state),
                describe_state(&s)
            ),
        );
        self.state = s.clone();
        let _ = self.ev.send(TunnelEvent::State(s));
    }

    fn publish_sessions(&self) {
        let list = self.sessions.values().cloned().collect();
        let _ = self.ev.send(TunnelEvent::RemoteSessions(list));
    }

    /// 停掉当前的一切：先取消还在跑的连接任务（如果有——对应
    /// Preflight/Connecting 阶段），再关掉已经建立的隧道（如果有——
    /// 对应 Connected/degraded 阶段）。两者互斥（连接任务跑完才会有
    /// `handle`），但都检查一遍，不假设调用方已经知道当前处于哪个
    /// 阶段。
    ///
    /// R72：`connect_rx` 由调用方传入而不是存在 `Ctx` 里——`abort()`
    /// 之后必须 `.await` 那个 `JoinHandle`，确保任务真正结束之后才能
    /// 安全地排空 `connect_rx`；单纯 `abort()` 后立刻 `try_recv()`
    /// 不能排除"消息还在被送进 channel 的路上"这个窗口，见模块顶部
    /// R72 的说明。排空时如果翻到一条 `Established`，这条隧道从没被
    /// 主循环认领过，直接在这里 `shutdown()` 它，不能放着不管。
    async fn teardown(
        &mut self,
        connect_rx: &mut mpsc::Receiver<ConnectEvent>,
        pending_handle: &PendingHandle,
    ) {
        if let Some(task) = self.connect_task.take() {
            task.abort();
            // 等它真正停下来——不是为了安全性（那件事现在完全交给下面
            // 的 `pending_handle` 槎位负责，见该类型上的说明与
            // `run_connect_sequence` 里写槎位那一步的顺序），单纯是
            // 不想留一个已经被判定"不再需要"的任务在后台继续裸跑：
            // `.await` 让 `teardown()` 返回时能保证这个任务真的已经
            // 彻底停止，调用方不需要猜它是不是还占着 CPU/等着某个
            // 早就没人关心的 I/O。
            let _ = task.await;
            // `connect_rx` 里剩下的都只是信号（见 `ConnectEvent` 上的
            // 说明），不带句柄——真正要救回来的句柄从下面的
            // `pending_handle` 槎位里取，这里排空只是为了不留着没处理
            // 的消息。
            while connect_rx.try_recv().is_ok() {}
        }
        // R72 深化：不管 `connect_task` 刚才是不是 `Some`——这一路径
        // 专门兜住"任务已经把句柄写进槎位，但携带 `Established` 信号
        // 的那次 `send` 从没有机会被主循环处理过"这种情况（不管原因是
        // 被 `abort()` 打断，还是别的什么导致这条消息没被正常消费），
        // 见 `PendingHandle` 上的说明：写槎位这一步不跨越任何
        // `.await`，只要 `establish()` 成功返回过，句柄就一定已经在
        // 槎位里，跟上面 `task.await` 有没有等到、`connect_rx` 有没有
        // 收到消息都无关——槎位里只要还留着句柄就必须 `shutdown()` 它。
        // 先把 `MutexGuard` 在这条语句结束时丢掉，再 `.await`——
        // `std::sync::MutexGuard` 不是 `Send`，跨 `.await` 拿着它会让
        // 整个 `run()` 的 future 也丢失 `Send`，`tokio::spawn` 编译不过。
        let leaked = pending_handle.lock().unwrap().take();
        if let Some(h) = leaked {
            h.shutdown().await;
        }
        if let Some(h) = self.handle.take() {
            h.shutdown().await;
        }
        // R83（复审发现，中等严重）：隧道非正常结束时仍开着的远程会话
        // 原来在这里被静默丢弃——`RemoteSessionOpened` 有审计记录，
        // `RemoteSessionClosed`/用时/字节数永远没有，因为这条消息从此
        // 不会再被处理到：`msg_rx` 的 guard 是 `ctx.handle.is_some()`
        // （见 `run()` 主循环里那个分支上的说明），上面几行已经把
        // `self.handle` 取走了，即使 pump 补发了 `RemoteSessionClosed`
        // 也不会被 `handle_msg` 看到，不是时序运气，是结构性的必然。
        //
        // 而这正是最常见的收尾路径：远程工程师正连着客户一体机，现场
        // 笔记本断网，或者现场人员点"停止"——事后追责问"他连了多久、
        // 传了多少"，日志原来只能到"会话已开启"为止。这里补一次账,
        // 跟 `TunnelMsg::RemoteSessionClosed`（正常关闭）共用同一份
        // `record_session_closed`，口径一致。
        if !self.sessions.is_empty() {
            for (id, info) in &self.sessions {
                record_session_closed(&self.audit, *id, info);
            }
            self.sessions.clear();
            self.publish_sessions();
        }
    }
}

/// 在独立任务里跑"预检 + 建隧道"，通过 `connect_tx` 把每一步的结果送回
/// 主循环。`do_preflight = false` 用于断线重连之后的重试——预检只在
/// 一次 `Start` 里做一次，不是每次重试都重新探测一遍。
///
/// 这个函数本身不碰 `Ctx`——拿到的都是 `Arc`/拷贝出来的值，这正是它能
/// 被 `tokio::spawn` 成一个独立任务、被 `JoinHandle::abort()` 取消的
/// 前提：`Ctx` 留在主循环那一侧，两者只通过 `connect_tx`/`msg_tx`
/// 通信。
/// [`run_connect_sequence`] 需要的一切输入，打包成一个结构体纯粹是为了
/// 躲开 `clippy::too_many_arguments`（拆开传正好卡在默认上限 7 上）——
/// 合并成结构体不改变每个字段各自的含义。
///
/// R96：原来这里还有 `gateway`/`appliance` 两个字段，专供
/// `Preflight::run` 使用，跟 `params` 里的地址是两份独立的拷贝。既然
/// `TunnelParams` 现在自己带着这两个地址（见 `tunnel::TunnelParams`
/// 上的 R96 说明），这两个字段就删掉了——预检探测的地址与随后
/// `establish` 拨号的地址此后是同一个值的两次读取，不可能分叉。删掉
/// 它们不是为了少两行，是为了让「诊断页描述的那台机器就是实际连上的
/// 那台」这件事在结构上无从违反。
struct ConnectRequest {
    do_preflight: bool,
    preflight: Arc<dyn Preflight>,
    factory: Arc<dyn TunnelFactory>,
    params: TunnelParams,
}

/// R74：栈上的 scope guard——只要函数还没送出任何一条终态
/// `ConnectEvent`（`PreflightFailed`/`Established`/`Failed`）就一直
/// "武装"着；`Preflight`/`TunnelFactory` 的实现里如果有 bug 导致
/// panic，栈展开会经过这个 guard 的 `Drop`，还是武装状态就送一条
/// 兜底的 `ConnectEvent::Failed`，不让状态机永久卡在 `Preflight`/
/// `Connecting`——没有这个 guard，`connect_task` 会因为对应的
/// `JoinHandle` 从没被任何人观察过而一直是 `Some`，`ctx.state` 永远
/// 停在 panic 发生前的最后一步。
///
/// `Drop::drop` 是同步函数，不能 `.await`；用 `try_send`——
/// `CONNECT_EVENT_CAPACITY` 有余量，这条兜底消息只在真的 panic 时才
/// 会触发，不会跟同一次尝试的其他消息挤占同一个槎位（一次尝试最多
/// 产生 2-3 条 `ConnectEvent`，容量 8 绰绰有余）。
struct FailOnPanic {
    armed: bool,
    connect_tx: mpsc::Sender<ConnectEvent>,
}

impl FailOnPanic {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for FailOnPanic {
    fn drop(&mut self) {
        if self.armed {
            let _ = self
                .connect_tx
                .try_send(ConnectEvent::Failed(Error::SshTransport(
                    "连接任务异常终止（内部出现未捕获的错误）".into(),
                )));
        }
    }
}

async fn run_connect_sequence(
    req: ConnectRequest,
    msg_tx: mpsc::Sender<TunnelMsg>,
    connect_tx: mpsc::Sender<ConnectEvent>,
    pending_handle: PendingHandle,
) {
    let ConnectRequest {
        do_preflight,
        preflight,
        factory,
        params,
    } = req;
    let mut guard = FailOnPanic {
        armed: true,
        connect_tx: connect_tx.clone(),
    };
    if do_preflight {
        let _ = connect_tx.send(ConnectEvent::EnteredPreflight).await;
        // R96：探的就是下面 `factory.establish(params, ..)` 要拨的那
        // 一对地址——同一个 `params` 的两个字段，不是另一份拷贝。
        let report = preflight.run(&params.gateway, &params.appliance).await;
        let passed = report.passed();
        let failure = report.first_failure().cloned();
        let _ = connect_tx.send(ConnectEvent::PreflightReport(report)).await;
        if !passed {
            let (class, message) = match failure.map(|s| s.outcome) {
                Some(preflight::StepOutcome::Fail { class, detail }) => (class, detail),
                _ => (ErrorClass::Network, "预检未通过".to_string()),
            };
            guard.disarm();
            let _ = connect_tx
                .send(ConnectEvent::PreflightFailed { class, message })
                .await;
            return;
        }
    }
    let _ = connect_tx.send(ConnectEvent::EnteredConnecting).await;
    match factory.establish(params, msg_tx).await {
        Ok(handle) => {
            // R72 深化：先同步写进槎位，再解除 guard 的武装，最后才
            // 发信号——这个顺序是故意的。写槎位这一步不跨越任何
            // `.await`，不可能被 `abort()` 打断；即使紧随其后的
            // "解除武装"或者"发信号"这两步出于任何原因没有走完（无论
            // 是被取消，还是别的意外），句柄已经安全落地，`teardown()`
            // 与 `handle_connect_event` 两条路径里总有一条会把它接手。
            *pending_handle.lock().unwrap() = Some(handle);
            guard.disarm();
            let _ = connect_tx.send(ConnectEvent::Established).await;
        }
        Err(e) => {
            guard.disarm();
            let _ = connect_tx.send(ConnectEvent::Failed(e)).await;
        }
    }
}

/// 发起一次新的连接尝试：为这次尝试创建全新的 `TunnelMsg`/`ConnectEvent`
/// 通道（见模块顶部第 9 条，R61——不复用旧通道，杜绝一条已经被取消/被
/// 取代的旧尝试的迟到消息污染新尝试的状态），把后台任务的
/// `JoinHandle` 记进 `ctx.connect_task`。
///
/// 没有凭据时返回 `None`、什么都不做——这是防止 `retry_at`/网络事件
/// 之类的定时器在 `ctx.creds` 已经被清空之后还误触发一次连接尝试的
/// 最后一道防线：真正挡住"停止之后还会重试"的是这里（没有凭据就不会
/// 有任何后续动作），不是调用方有没有记得同时清 `retry_at`——两者都做
/// 了，但这里才是决定性的那一层。
fn spawn_connect(
    ctx: &mut Ctx,
    do_preflight: bool,
) -> Option<(
    mpsc::Receiver<TunnelMsg>,
    mpsc::Receiver<ConnectEvent>,
    PendingHandle,
)> {
    let creds = ctx.creds.as_ref()?;
    // R96：地址不再单独拷一份出来——`params` 自己带着 gateway 与
    // appliance，预检与拨号读的是同一对值，见 `ConnectRequest` 上的
    // 说明。
    let params = creds.params(ctx.cfg.reverse_port);
    let preflight = ctx.deps.preflight.clone();
    let factory = ctx.deps.factory.clone();

    let (msg_tx, msg_rx) = mpsc::channel(MSG_CAPACITY);
    let (connect_tx, connect_rx) = mpsc::channel(CONNECT_EVENT_CAPACITY);
    // R61 的"每次尝试全新通道"同一个理由也适用于这里：`PendingHandle`
    // 必须跟这一次尝试一一对应，不能被上一次尝试遗留的槎位污染——见
    // `PendingHandle` 上的说明。
    let pending_handle: PendingHandle = Arc::new(std::sync::Mutex::new(None));
    let req = ConnectRequest {
        do_preflight,
        preflight,
        factory,
        params,
    };
    let task = tokio::spawn(run_connect_sequence(
        req,
        msg_tx,
        connect_tx,
        pending_handle.clone(),
    ));
    ctx.connect_task = Some(task);
    Some((msg_rx, connect_rx, pending_handle))
}

/// R71：是否"有一次开启正在建连中，或者已经建立"——用同步字段
/// （`connect_task`/`handle`）判断，不看 `ctx.state`。`ctx.state` 要
/// 等后台连接任务送回第一条 `ConnectEvent` 才会离开 `Idle`，这中间有
/// 一段异步延迟；`connect_task`/`handle` 是处理对应命令的同一步就
/// 同步写入的，不存在这段延迟。`Command::Cancel`/`Stop`（有没有东西
/// 可停）与 `Command::RetryNow`（不该在这期间发起第二次尝试）的准入
/// 判断都基于这个函数；`Command::Start` 还要另外叠加检查 `retry_at`
/// （代表 `Backoff` 状态——建连任务与隧道句柄都不存在，但仍处于自动
/// 重试等待中，不应该被一次新的手动 `Start` 打断），调用处直接写
/// `retry_at.is_some()`，不塞进这个函数（`retry_at` 是 `run()` 的
/// 局部变量，`RetryNow`/`Cancel`/`Stop` 都不需要单独关心它）。
fn connecting_or_connected(ctx: &Ctx) -> bool {
    ctx.connect_task.is_some() || ctx.handle.is_some()
}

/// `Command::Cancel` 与 `Command::Stop` 受理之后要做的事，两者完全相同
/// ——差别只在**准入判断**上（`Failed` 状态下只有 `Stop` 受理，见
/// `Command::Stop` 分支上的说明与模块顶部第 18 条），受理之后的动作
/// 一模一样。R78 把这段从原来合并的一个 match 分支里抽出来，让两个
/// 分支各自写各自的准入判断而不用复制这五行。
///
/// 顺序是有讲究的：先广播 `Stopping` 再 `teardown()`——`teardown()`
/// 里的 `shutdown()`/`JoinHandle::await` 都可能要等一会儿，界面应该在
/// 这段等待**开始之前**就看到"正在停止"，而不是等它结束才一次性跳到
/// `Idle`。
async fn stop_everything(
    ctx: &mut Ctx,
    connect_rx: &mut mpsc::Receiver<ConnectEvent>,
    pending_handle: &PendingHandle,
    probe_at: &mut Option<Instant>,
) {
    ctx.set_state(State::Stopping);
    ctx.teardown(connect_rx, pending_handle).await;
    // 方案 §3.8：口令留到会话结束才清（断线重连要复用，不是"认证后
    // 立即清除"，见该节最新的说明）——这里就是"会话结束"的一个出口。
    // `Credentials` 里的 `Zeroizing<String>` 在这一行被丢弃时会把底层
    // 缓冲区清零。
    ctx.creds = None;
    ctx.retry_at = None;
    *probe_at = None;
    ctx.set_state(State::Idle);
}

/// `Command::Start`（校验通过后）与 `Supervisor::spawn_with_validated_
/// start`（跳过校验，仅测试）初始化一次新会话共用的逻辑：记凭据、
/// 重置退避/端口占用计时、发起第一次连接尝试。R74：这段逻辑原来在两处
/// 各写一份，抽成共享函数。
///
/// 返回值签名沿用 `spawn_connect` 的 `Option`，但两个调用点都是"刚刚
/// 把 `ctx.creds` 填成 `Some`，紧接着调用"，`spawn_connect` 内部的
/// `ctx.creds.as_ref()?` 不可能在这里短路——调用处仍然用 `if let`
/// 接，不额外 `unwrap`，不假设这个内部实现细节永远不变。
fn begin(
    ctx: &mut Ctx,
    username: String,
    password: Zeroizing<String>,
    addrs: ValidatedAddresses,
) -> Option<(
    mpsc::Receiver<TunnelMsg>,
    mpsc::Receiver<ConnectEvent>,
    PendingHandle,
)> {
    // 审计：谁、连到了哪台一体机——这是"事后追责"四个问题里另外两个,
    // `set_state` 记的通用状态迁移行看不出来（`State` 不携带账号/地址）。
    // 只记账号与地址，不记口令；`username` 在这里只是被 `format!` 借用,
    // 随后仍然原样移进下面的 `Credentials`。
    ctx.audit.record(
        Level::Info,
        &format!(
            "开始连接：账号 {username}，运维服务器 {}，一体机 {}",
            addrs.gateway(),
            addrs.appliance()
        ),
    );
    ctx.creds = Some(Credentials {
        username,
        password,
        addrs,
    });
    ctx.backoff = Backoff::new((ctx.deps.jitter)());
    ctx.port_busy_since = None;
    ctx.port_busy_attempt = 0;
    spawn_connect(ctx, true)
}

async fn run(
    cfg: Config,
    deps: Deps,
    mut cmd_rx: mpsc::Receiver<Command>,
    ev: broadcast::Sender<TunnelEvent>,
    initial: Option<(String, Zeroizing<String>, ValidatedAddresses)>,
) {
    let mut sys = deps.events.subscribe();
    let jitter = deps.jitter;
    // 审计日志目录初始化失败（权限、磁盘）不是 Fatal——不能因为记不下
    // 日志就拒绝启动整个 Supervisor，那样"一次正在进行的维护会话"甚至
    // 都没机会开始。降级为 `tracing::error!`（这是真实故障，得让人
    // 看见）加一个尽力而为的 `Audit`：`record()` 每次调用都会自己重试
    // 创建目录，环境恢复后会自动开始写入，见 `Audit::record` 上的说明。
    let audit = Audit::open(cfg.log_dir.clone()).unwrap_or_else(|e| {
        tracing::error!(
            error = %e,
            dir = ?cfg.log_dir,
            "审计日志目录初始化失败，继续运行"
        );
        Audit::open_best_effort(cfg.log_dir.clone())
    });
    // 保留期清理失败（目录读不了）同理不是 Fatal，只是错过这一次清理，
    // 下次进程启动再试。
    if let Err(e) = audit.prune() {
        tracing::warn!(error = %e, "审计日志清理失败，忽略");
    }
    let mut ctx = Ctx {
        cfg,
        deps,
        ev,
        state: State::Idle,
        creds: None,
        handle: None,
        connect_task: None,
        sessions: BTreeMap::new(),
        backoff: Backoff::new(jitter()),
        port_busy_attempt: 0,
        port_busy_since: None,
        retry_at: None,
        audit,
    };

    // 初始都指向"不会有任何发送端"的哨兵通道——sender 在这条语句结束时
    // 就被丢弃，`recv()` 恒定返回 `None`。这两个分支分别用
    // `if ctx.connect_task.is_some()`（connect_rx）与
    // `if ctx.handle.is_some() || ctx.connect_task.is_some()`（msg_rx）
    // 挡住，平时根本不会被 poll 到，哨兵通道只是给局部变量一个初始值。
    let mut msg_rx: mpsc::Receiver<TunnelMsg> = mpsc::channel(1).1;
    let mut connect_rx: mpsc::Receiver<ConnectEvent> = mpsc::channel(1).1;
    // 同样只是初始占位——每次 `spawn_connect` 都会给一个跟这次尝试
    // 一一对应的全新槎位，见 `PendingHandle` 上的说明。
    let mut pending_handle: PendingHandle = Arc::new(std::sync::Mutex::new(None));

    // 下一次尝试连接的时刻现在随 `Ctx` 走（`ctx.retry_at`，R80）。
    // degraded 时下一次探测一体机的时刻。None 表示不在探测中。
    let mut probe_at: Option<Instant> = None;
    // R90：下一次审计日志保留期清理的时刻，恒定 `Some`——跟 `retry_at`/
    // `probe_at` 不同，这个定时器不依赖会话状态，进程活着就该一直转。
    let mut prune_at = Instant::now() + AUDIT_PRUNE_INTERVAL;

    // 注意这里不调用 `ctx.set_state(State::Idle)`：`ctx.state` 在上面
    // 的结构体字面量里已经初始化成 `Idle`，这里只是"进程刚起来，状态
    // 还没变过"，不是一次真正的状态转移。如果这里也广播一次，`rx` 会在
    // 测试第一次 `recv()` 之前就已经缓冲到这条 `Idle` 事件（`broadcast`
    // 的缓冲不需要接收端先调用过 `recv`），导致 `happy_path_reaches_
    // connected` 断言 `seen[0]` 是 `Preflight` 时失败——实际
    // `seen[0]` 会是这条多余的 `Idle`。只在状态真的发生变化时才广播。

    if let Some((username, password, addrs)) = initial {
        if let Some((new_msg_rx, new_connect_rx, new_pending_handle)) =
            begin(&mut ctx, username, password, addrs)
        {
            msg_rx = new_msg_rx;
            connect_rx = new_connect_rx;
            pending_handle = new_pending_handle;
        }
    }

    loop {
        let idle = Instant::now() + Duration::from_secs(3600);
        let sleep_until = ctx.retry_at.unwrap_or(idle);
        let probe_until = probe_at.unwrap_or(idle);

        // R58/R73：`biased` 把 `connect_rx` 排在最前，虽然 R73 已经把
        // "`Established` 必须先于任何 `TunnelMsg` 被处理"这件事从
        // `biased` 的调度时序保证改成了 `msg_rx` guard 本身的结构性
        // 保证（见下面 `msg_rx` 分支上的说明），这里仍然保留
        // `biased`、把 `connect_rx` 排最前——如果 `Stop`/`Cancel` 与
        // `Established` 恰好同时就绪，优先处理 `Established` 能让
        // 隧道先进入 `ctx.handle`，随后的 `Stop` 走正常的
        // `teardown()` 把它关掉,而不是让一个已经建立、但还没来得及
        // 被主循环认领的隧道被 `Cancel`/`Stop` 直接丢弃。
        //
        // 见 `connecting_or_connected` 上的说明：`Start`/`Cancel`/
        // `Stop`/`RetryNow` 四个命令的准入判断（下面几个分支各自的
        // `if` 条件）都改用同步字段（`connect_task`/`handle`/
        // `retry_at`），不使用 `ctx.state`——R71。
        tokio::select! {
            biased;

            Some(event) = connect_rx.recv(), if ctx.connect_task.is_some() => {
                handle_connect_event(&mut ctx, event, &pending_handle);
            }

            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { ctx.teardown(&mut connect_rx, &pending_handle).await; return };
                match cmd {
                    Command::Start { username, password, gateway, appliance } => {
                        // R71：不看 `ctx.state`——背靠背发 `Start` 后
                        // 立刻又发一条命令，中间没有任何 `.await`，
                        // `ctx.state` 这时可能还没来得及离开 `Idle`。
                        if connecting_or_connected(&ctx) || in_backoff(&ctx) {
                            continue;
                        }
                        match ValidatedAddresses::validate(gateway, appliance) {
                            Ok(addrs) => {
                                probe_at = None;
                                if let Some((new_msg_rx, new_connect_rx, new_pending_handle)) = begin(&mut ctx, username, password, addrs) {
                                    msg_rx = new_msg_rx;
                                    connect_rx = new_connect_rx;
                                    pending_handle = new_pending_handle;
                                }
                            }
                            Err(e) => {
                                // 地址关系本身不合法（一体机等于 Gateway、
                                // 一体机是本机回环）：这是配置错误，不是
                                // 网络问题，重试无意义，且这一步必须发生在
                                // 触达 Deps::factory 之前——见模块顶部第 7 条。
                                //
                                // R62：连同凭据一起清空——否则改错地址后点
                                // RetryNow（Failed 状态下允许）会拿旧地址
                                // 旧口令去连，界面刚报的错跟实际连的地方
                                // 对不上。
                                ctx.creds = None;
                                ctx.set_state(State::Failed { class: e.class(), message: e.to_string() });
                            }
                        }
                    }
                    Command::Cancel => {
                        // R71：同上，不看 `ctx.state`——`Start` 之后
                        // 立刻 `Cancel`，`ctx.state` 可能还是 `Idle`，
                        // 但 `ctx.connect_task` 已经被同步设置好了。
                        //
                        // R78：`Failed` 下 `Cancel` 是空操作——方案
                        // §3.5 的表格里 `Failed` 只允许"重试、查看
                        // 诊断"，而 `Cancel` 的语义是"取消正在进行的
                        // 这次开启"，`Failed` 下没有任何正在进行的
                        // 东西可取消。跟 `Stop` 的差别见下一个分支。
                        if !connecting_or_connected(&ctx) && !in_backoff(&ctx) {
                            continue;
                        }
                        stop_everything(&mut ctx, &mut connect_rx, &pending_handle, &mut probe_at).await;
                    }
                    Command::Stop => {
                        // R78：`Failed` 下 `Stop` 必须仍然有效——见
                        // 模块顶部第 18 条。上一轮（R71）的新准入条件
                        // 让 `Failed` 下 `Cancel`/`Stop` 都成了空操作，
                        // 从状态机角度更贴 §3.5 的表格，副作用却是
                        // `Zeroizing<String>` 口令会在 `Failed` 期间
                        // 一直留在内存里，直到下一次 `Start` 或进程
                        // 退出——而 §3.8 明确要求口令"仅存于进程内存，
                        // 认证后清除"。工程师遇到失败之后合上笔记本
                        // 走人，恰恰是最常见的收尾方式。两条规格冲突
                        // 时安全那条优先。
                        //
                        // 准入判断因此比 `Cancel` 多两条：
                        //  - `ctx.creds.is_some()`：内存里还留着口令，
                        //    这是安全要求的核心判据；
                        //  - `matches!(ctx.state, State::Failed { .. })`：
                        //    即使口令已经被清掉（例如地址校验失败那条
                        //    路，见 R62），"我不玩了"也应该能把界面从
                        //    `Failed` 带回 `Idle`——`Stop` 表达的是
                        //    "我不玩了"，任何状态下可用符合直觉。
                        //
                        // 这里读 `ctx.state` 不重蹈 R71 的覆辙：R71 的
                        // 危险在于"状态滞后导致误判为可以开始/没什么可
                        // 取消"，而这两条只会让准入**更宽**；状态如果
                        // 还没来得及变成 `Failed`，前面几条同步字段的
                        // 判据必然已经成立。
                        if !connecting_or_connected(&ctx)
                            && !in_backoff(&ctx)
                            && ctx.creds.is_none()
                            && !matches!(ctx.state, State::Failed { .. })
                        {
                            continue;
                        }
                        stop_everything(&mut ctx, &mut connect_rx, &pending_handle, &mut probe_at).await;
                    }
                    Command::RetryNow => {
                        // R71：只看"有没有正在建连/已经建立"，不看
                        // `ctx.state`——同样是为了不被"背靠背发命令"
                        // 绕过；`retry_at` 是否 `Some`（Backoff 中）
                        // 不需要额外判断，`Failed` 状态下 `retry_at`
                        // 是 `None` 也应该允许 `RetryNow`。
                        if !connecting_or_connected(&ctx) {
                            ctx.backoff.reset();
                            ctx.port_busy_since = None;
                            ctx.port_busy_attempt = 0;
                            ctx.retry_at = None;
                            if let Some((new_msg_rx, new_connect_rx, new_pending_handle)) = spawn_connect(&mut ctx, false) {
                                msg_rx = new_msg_rx;
                                connect_rx = new_connect_rx;
                                pending_handle = new_pending_handle;
                            }
                        }
                    }
                    Command::DisconnectRemoteSession { id } => {
                        if let Some(h) = ctx.handle.as_ref() {
                            let _ = h.close_remote_session(id).await;
                        }
                    }
                }
            }

            // R73：guard 收紧成单纯 `ctx.handle.is_some()`——不再是
            // `handle.is_some() || connect_task.is_some()`。建连期间
            // 产生的 `TunnelMsg`（哪怕是隧道刚建成那一刻就跟着来的）
            // 会先在 channel 的 256 容量缓冲区里等着，guard 只有在
            // `Established` 真的被处理、`ctx.handle` 被设置之后才会
            // 打开；`msg_rx` 里排在前面的消息这时才会按 FIFO 顺序被
            // 处理到——`Established` 必然先于任何 `TunnelMsg` 被处理，
            // 这是 channel 的顺序保证给出的结构性事实，不再依赖
            // `biased`/谁先被调度赢下一场时序竞赛。
            Some(msg) = msg_rx.recv(), if ctx.handle.is_some() => {
                handle_msg(&mut ctx, msg, &mut probe_at, &mut connect_rx, &pending_handle).await;
            }

            Ok(event) = sys.recv() => {
                // 网络变化与休眠恢复都清零退避并立刻重试。
                //
                // R75：准入判断也改看同步字段，不看 `ctx.state`——原来
                // 这里写的是 `matches!(ctx.state, State::Backoff { .. })`，
                // 那是第四轮评审抓到的第三个、也是唯一**必现**的隧道
                // 泄漏入口，见模块顶部第 16 条与
                // `two_system_events_during_backoff_do_not_leak_a_tunnel`。
                // `retry_at.is_some()` 表达"处于自动重试等待中"（就是
                // `Backoff`，但这个字段是同步维护的，没有 `ctx.state`
                // 那段异步延迟），`!connecting_or_connected(&ctx)` 排除
                // "这一次重试已经发起了、只是状态还没跟上"。
                if in_backoff(&ctx)
                    && !connecting_or_connected(&ctx)
                    && matches!(event, SystemEvent::NetworkChanged | SystemEvent::ResumedFromSleep)
                {
                    ctx.backoff.reset();
                    ctx.retry_at = None;
                    if let Some((new_msg_rx, new_connect_rx, new_pending_handle)) = spawn_connect(&mut ctx, false) {
                        msg_rx = new_msg_rx;
                        connect_rx = new_connect_rx;
                        pending_handle = new_pending_handle;
                    }
                }
            }

            // R80：第五处入口，也是四个 spawn_connect 调用点里唯一一个
            // 原来只写 `if retry_at.is_some()`、不含
            // `!connecting_or_connected(&ctx)` 的——见模块顶部第 19 条。
            // 不变量本来就成立（`retry_at`/`connect_task`+`handle` 从不
            // 同时置位），这里补的是显式检查，不是修复一个当前能复现的
            // 缺陷。R89：这条 guard 一旦被不变量打破就会变 `false`，
            // 后果是这个分支被静默禁用、`retry_at` 卡在 `Some`、重试
            // 定时器再也不触发——静默卡在 Backoff，不是报错，见模块
            // 顶部第 19 条订正后的说明。
            _ = tokio::time::sleep_until(sleep_until), if in_backoff(&ctx) && !connecting_or_connected(&ctx) => {
                ctx.retry_at = None;
                if let Some((new_msg_rx, new_connect_rx, new_pending_handle)) = spawn_connect(&mut ctx, false) {
                    msg_rx = new_msg_rx;
                    connect_rx = new_connect_rx;
                    pending_handle = new_pending_handle;
                }
            }

            _ = tokio::time::sleep_until(probe_until), if probe_at.is_some() => {
                probe_at = probe_appliance(&mut ctx).await;
            }

            // R90：审计日志保留期清理不再只在启动时跑一次——见
            // `AUDIT_PRUNE_INTERVAL` 上的说明。跟 `Audit::open` 那次
            // 一样，失败不是 Fatal，只是错过这一轮，下一轮再试。
            _ = tokio::time::sleep_until(prune_at) => {
                if let Err(e) = ctx.audit.prune() {
                    tracing::warn!(error = %e, "审计日志清理失败，忽略，下次到点再试");
                }
                prune_at = Instant::now() + AUDIT_PRUNE_INTERVAL;
            }
        }
    }
}

/// 处理后台连接任务上报的一步进度/结果。
fn handle_connect_event(ctx: &mut Ctx, event: ConnectEvent, pending_handle: &PendingHandle) {
    match event {
        ConnectEvent::EnteredPreflight => ctx.set_state(State::Preflight),
        ConnectEvent::PreflightReport(report) => {
            let _ = ctx.ev.send(TunnelEvent::Preflight(report));
        }
        ConnectEvent::PreflightFailed { class, message } => {
            ctx.connect_task = None;
            // 预检失败没有 Backoff 分支——见方案 3.5 的状态图：Preflight
            // 只有"通过"/"失败"两个出口，失败恒定直接进 Failed，不自动
            // 重试，用户需要 RetryNow 或一次新的 Start。
            ctx.set_state(State::Failed { class, message });
        }
        ConnectEvent::EnteredConnecting => ctx.set_state(State::Connecting),
        ConnectEvent::Established => {
            ctx.connect_task = None;
            // R72 深化：句柄本身不在这条消息里，从 `PendingHandle` 槎位
            // 里取——见该类型上的说明。`take()` 之后是 `None` 只可能
            // 发生在极端的实现错误下（这条消息本来就是"槎位里有东西了"
            // 的信号），正常路径下这里恒为 `Some`。
            ctx.handle = pending_handle.lock().unwrap().take();
            ctx.port_busy_since = None;
            ctx.port_busy_attempt = 0;
            ctx.backoff.reset();
            let _ = ctx.ev.send(TunnelEvent::ConnectedSince(SystemTime::now()));
            ctx.set_state(State::Connected { degraded: false });
        }
        ConnectEvent::Failed(e) => {
            ctx.connect_task = None;
            schedule_retry(ctx, e);
        }
    }
}

/// degraded 时每 [`APPLIANCE_PROBE`] 探测一次一体机，恢复即转回。返回
/// 下一次探测时刻，`None` 表示不需要再探测（已恢复，或隧道已不存在）。
async fn probe_appliance(ctx: &mut Ctx) -> Option<Instant> {
    let appliance = ctx.creds.as_ref()?.addrs.appliance().clone();
    match ctx
        .deps
        .transport
        .probe_tcp(&appliance, Duration::from_secs(5))
        .await
    {
        Ok(_) => {
            if matches!(ctx.state, State::Connected { degraded: true }) {
                ctx.set_state(State::Connected { degraded: false });
            }
            None
        }
        Err(_) => Some(Instant::now() + APPLIANCE_PROBE),
    }
}

/// 按错误分类决定是否以及何时重试。
///
/// 见模块顶部第 4 条：`ErrorClass::ApplianceUnreachable` 目前没有任何
/// 生产调用点会传到这里——`run_connect_sequence` 只会失败于 Gateway 侧
/// 的握手/认证/端口注册（`SshTunnelFactory::establish` 根本不拨号一体
/// 机），一体机不可达在已连接状态下经 `TunnelMsg::ApplianceDialFailed`
/// 单独处理（见 `handle_msg`），从不经过这个函数。但 `schedule_retry`
/// 是按 `e.class()` 泛化处理的，如果把这个分类默认并进 `Network`，
/// 一旦未来某个调用点真的传入这个类别，会把"隧道保持、转 degraded、
/// 每 30 秒探测"错误地处理成"整条隧道拆了重建、指数退避"——这里单独
/// 给一条分支，用固定的 [`APPLIANCE_PROBE`] 节奏，不套用网络类的指数
/// 退避表，也不推进 `ctx.backoff` 的计数。
/// 审计日志级别：`Fatal` 是唯一必须让人立刻警觉的一类，其余都只是
/// "正在自动处理中"的过程性事件。跟 `Ctx::set_state` 里那套按
/// `State` 形状分级的映射是两套独立的分级——`State::Idle`/
/// `State::Backoff` 都不携带 `ErrorClass`，看不出"认证被拒绝"跟
/// "网络抖动"的区别，这里直接按 `class` 分级，两条记录合在一起才
/// 是完整的信息。
fn audit_level_for(class: ErrorClass) -> Level {
    match class {
        ErrorClass::Fatal => Level::Error,
        ErrorClass::Auth
        | ErrorClass::PortBusy
        | ErrorClass::Network
        | ErrorClass::ApplianceUnreachable => Level::Warn,
    }
}

fn schedule_retry(ctx: &mut Ctx, e: Error) {
    let class = e.class();
    // 审计：错误原文本身要留痕——`State::Backoff`/`State::Idle` 都不
    // 携带这段文字，只看 `Ctx::set_state` 记的通用状态迁移行看不出
    // "为什么"（认证被拒绝？端口占用？哪一个一体机不可达？）。
    // `Error` 的 `Display` 全部由固定文案拼成，不含口令——见 `error.rs`
    // 上 `error_display_never_contains_a_password` 那条测试，可以直接
    // 记原文。
    ctx.audit.record(audit_level_for(class), &e.to_string());
    // 见模块顶部第 3 条：除端口占用外的任何结果都清空端口占用的计时，
    // 让下一次端口占用序列从一份全新的 120 秒预算开始。
    if !matches!(class, ErrorClass::PortBusy) {
        ctx.port_busy_since = None;
        ctx.port_busy_attempt = 0;
    }
    match class {
        ErrorClass::Fatal => {
            ctx.retry_at = None;
            ctx.set_state(State::Failed {
                class: ErrorClass::Fatal,
                message: e.to_string(),
            });
        }
        ErrorClass::Auth => {
            // R65：回到 Idle 让界面提示重新输入，凭据同时清掉——方案
            // §3.8（R82 订正后）把"Gateway 拒绝认证"列为三个清除
            // 触发点之一，不自动重试也就没有"留着凭据等下一次重试
            // 复用"这个理由。
            ctx.retry_at = None;
            ctx.creds = None;
            ctx.set_state(State::Idle);
        }
        ErrorClass::PortBusy => {
            let since = *ctx.port_busy_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= PORT_BUSY_BUDGET {
                ctx.retry_at = None;
                ctx.set_state(State::Failed {
                    class: ErrorClass::PortBusy,
                    message: format!("{e}，{} 秒内未能注册", PORT_BUSY_BUDGET.as_secs()),
                });
                return;
            }
            // 见模块顶部第 5 条：这条计数只在端口占用序列里递增，专门
            // 供界面显示"第几次重试"，不与下面 Network 分支的指数退避
            // 计数共用。
            ctx.port_busy_attempt = ctx.port_busy_attempt.saturating_add(1);
            ctx.set_state(State::Backoff {
                attempt: ctx.port_busy_attempt,
                delay: PORT_BUSY_RETRY,
            });
            ctx.retry_at = Some(Instant::now() + PORT_BUSY_RETRY);
        }
        ErrorClass::ApplianceUnreachable => {
            let delay = APPLIANCE_PROBE;
            ctx.set_state(State::Backoff {
                attempt: ctx.backoff.attempt(),
                delay,
            });
            ctx.retry_at = Some(Instant::now() + delay);
        }
        ErrorClass::Network => {
            let delay = ctx.backoff.next_delay();
            ctx.set_state(State::Backoff {
                attempt: ctx.backoff.attempt(),
                delay,
            });
            ctx.retry_at = Some(Instant::now() + delay);
        }
    }
}

/// 一个远程会话的收尾账目：用移除前记下的 `opened_at` 现场算一次时长，
/// 连同累计字节数一起记一行——这是"谁、连到了哪台一体机、干了多久"这
/// 四个问题里最后一个的落点。`handle_msg` 的 `TunnelMsg::
/// RemoteSessionClosed`（正常关闭）与 `Ctx::teardown`（R83：隧道非
/// 正常结束时 `ctx.sessions` 里还剩的那些，见该函数上的说明）共用
/// 这一份实现，不能各写一份——否则两处measure用时/字节数的口径迟早会
/// 长歪。
fn record_session_closed(audit: &Audit, id: u64, info: &RemoteSessionInfo) {
    let secs = SystemTime::now()
        .duration_since(info.opened_at)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    audit.record(
        Level::Info,
        &format!(
            "远程会话 {id} 已关闭，用时 {secs} 秒，工程师→一体机 {} 字节，\
             一体机→工程师 {} 字节",
            info.to_appliance, info.from_appliance
        ),
    );
}

/// `handle_msg` 的审计策略：**逐个变体手写要记的内容，不是
/// `ctx.audit.record(Info, &format!("{msg:?}"))` 一把梭**——brief 那样
/// 写有两个问题：
///
/// 1. `TunnelMsg::RemoteSessionBytes` 每 [`crate::ssh::pump::
///    BYTES_REPORT_INTERVAL`]（2 秒）上报一次，一次普通的维护会话就能
///    刷出成百上千行，把真正有价值的"谁、何时、连到了哪台一体机、干了
///    多久"淹没在流量心跳里，也直接违背"日志按天滚动、体量可控"这个
///    设计目标。这里不记它——累计字节数在会话关闭时随
///    `RemoteSessionClosed` 一次性记一遍，账目不丢，只是不逐帧记。
/// 2. 逐个匹配比"匹配一次、Debug 转存"更安全：新增 `TunnelMsg` 变体时
///    Rust 会强制在下面这个 `match` 里显式处理（没有 `_ =>` 兜底），
///    逼着下一个人想一遍"这条该不该进审计日志、要不要脱敏"，而不是
///    自动继承一条前人从没审视过的 `{:?}` 输出。
async fn handle_msg(
    ctx: &mut Ctx,
    msg: TunnelMsg,
    probe_at: &mut Option<Instant>,
    connect_rx: &mut mpsc::Receiver<ConnectEvent>,
    pending_handle: &PendingHandle,
) {
    match msg {
        TunnelMsg::Authenticated {
            host_key_fp,
            first_seen,
        } => {
            ctx.audit.record(
                Level::Info,
                &format!(
                    "运维服务器认证通过，host key {host_key_fp}{}",
                    if first_seen { "（首次记录）" } else { "" }
                ),
            );
            let _ = ctx.ev.send(TunnelEvent::HostKey {
                fingerprint: host_key_fp,
                first_seen,
            });
        }
        TunnelMsg::ForwardRegistered { port } => {
            ctx.audit
                .record(Level::Info, &format!("反向端口 {port} 已注册"));
        }
        TunnelMsg::RemoteSessionOpened { id } => {
            ctx.audit
                .record(Level::Info, &format!("远程会话 {id} 已开启"));
            ctx.sessions.insert(
                id,
                RemoteSessionInfo {
                    id,
                    opened_at: SystemTime::now(),
                    to_appliance: 0,
                    from_appliance: 0,
                },
            );
            ctx.publish_sessions();
            // 有会话成功打开说明一体机恢复了，不必再靠定时探测。
            if matches!(ctx.state, State::Connected { degraded: true }) {
                ctx.set_state(State::Connected { degraded: false });
                *probe_at = None;
            }
        }
        TunnelMsg::RemoteSessionBytes {
            id,
            to_appliance,
            from_appliance,
        } => {
            // 不进审计日志——见函数文档第 1 条。
            if let Some(s) = ctx.sessions.get_mut(&id) {
                s.to_appliance = to_appliance;
                s.from_appliance = from_appliance;
                ctx.publish_sessions();
            }
        }
        TunnelMsg::RemoteSessionClosed { id } => {
            // "干了多久"：用移除前记下的 `opened_at` 现场算一次时长，
            // 连同关闭前最后一次 `RemoteSessionBytes` 报的累计字节数
            // 一起记——这一行是"谁连到了哪台一体机、干了多久"这四个
            // 问题里最后一个的落点，`RemoteSessionOpened`/这一行合起来
            // 就是一次远程会话完整的起止记录。跟 `teardown()`（隧道
            // 非正常结束时残留会话的收尾账，见 R83）共用同一份计算。
            if let Some(s) = ctx.sessions.remove(&id) {
                record_session_closed(&ctx.audit, id, &s);
            }
            ctx.publish_sessions();
        }
        TunnelMsg::ApplianceDialFailed { id, reason } => {
            ctx.audit.record(
                Level::Warn,
                &format!("远程会话 {id} 连接一体机失败：{reason}"),
            );
            if matches!(ctx.state, State::Connected { degraded: false }) {
                ctx.set_state(State::Connected { degraded: true });
                // 进入 degraded 后开始周期探测一体机；隧道本身保持不动，
                // 不经过 schedule_retry，不拆隧道。
                *probe_at = Some(Instant::now() + APPLIANCE_PROBE);
            }
        }
        TunnelMsg::Disconnected { reason } => {
            ctx.teardown(connect_rx, pending_handle).await;
            *probe_at = None;
            if ctx.creds.is_some() {
                // R91（复审发现）：这里原来先记一行"SSH 隧道断开：
                // {reason}"，`schedule_retry` 紧接着又记一行"SSH 链路
                // 中断：{reason}"（`Error::SshTransport` 的 `Display`）
                // ——同一次断线连续两行几乎同义的记录，实测相邻，读的
                // 人分不清这是两件事还是同一件事被记了两遍。不在这里
                // 重复记，交给 `schedule_retry` 记一次就够。
                schedule_retry(ctx, Error::SshTransport(reason));
            } else {
                // 目前没有已知的生产路径会走到这里（`ctx.creds` 在
                // `ctx.handle.is_some()` 期间——也就是 `msg_rx` 会被
                // 轮到的这段时间——理应恒为 `Some`），纯粹是防御：
                // `schedule_retry` 不会被调用，这里补一行，不让这次
                // 断线完全没有痕迹。
                ctx.audit
                    .record(Level::Warn, &format!("SSH 隧道断开：{reason}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! 状态机的行为规约。全部用假隧道与 tokio 的时间控制，不碰真实网络
    //! ——唯一的例外是文件末尾"第十条"那条端到端测量，它需要真的经过
    //! `ssh::establish_over`，因为要测的正是 russh 客户端的 keepalive
    //! 定时器，脚本化的假隧道压根不会触发它。

    use super::*;
    // R96：主体代码已经不再直接提 `HostPort`（地址一律经
    // `ValidatedAddresses` 与 `TunnelParams` 传递），只有测试里的假
    // `Preflight` 签名和地址字面量还要用它，所以导入收进测试模块。
    use crate::addr::HostPort;
    use crate::backoff::FixedJitter;
    use crate::platform::{NoProxy, NoProxyAuth, NoSystemEvents, SystemEvent, SystemEvents};
    use crate::transport::tls::TlsRoots;
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// 给整条测试套一层超时：真正卡死时给出"判定为死锁"的清晰失败，而
    /// 不是让 `cargo test` 无限期挂起。即使在 `#[tokio::test(start_paused
    /// = true)]` 下，这层超时本身也是一个待处理的定时器——虚拟时钟在
    /// "没有别的活干"时会自动跳到下一个定时器，所以对"卡在等一个永远
    /// 不会送出的事件"这类死锁依然有效；测不到的只有"陷入真正的忙等
    /// 死循环"，那种情况会让 `cargo test` 占满 CPU、一眼可辨，不是这层
    /// 超时要防的那一类。这个项目已经被夹具死锁拖垮过一次，见
    /// `ssh::test_support` 模块文档"第一版死锁及其修复"。
    async fn guard<F: std::future::Future>(fut: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(300), fut)
            .await
            .expect("测试超过 300（虚拟或真实）秒仍未完成，判定为死锁")
    }

    /// establish 的一次结果。
    enum Outcome {
        /// 成功，随后按脚本向 tx 推送这些消息。
        Ok(Vec<TunnelMsg>),
        Err(Error),
    }

    /// 按队列逐次给出 establish 结果的假隧道工厂。
    struct Scripted {
        outcomes: Mutex<VecDeque<Outcome>>,
        calls: Arc<Mutex<Vec<TunnelParams>>>,
        /// R68：每次 `establish()` 被调用的时刻，供测试断言"真的经过了
        /// 这么久的虚拟时间"，不只是"上报的数值对不对"。
        call_times: Mutex<Vec<Instant>>,
    }

    impl Scripted {
        fn new(outcomes: Vec<Outcome>) -> (Arc<Self>, Arc<Mutex<Vec<TunnelParams>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let me = Arc::new(Self {
                outcomes: Mutex::new(outcomes.into()),
                calls: calls.clone(),
                call_times: Mutex::new(Vec::new()),
            });
            (me, calls)
        }

        fn call_times(&self) -> Vec<Instant> {
            self.call_times.lock().unwrap().clone()
        }
    }

    struct FakeHandle;

    #[async_trait::async_trait]
    impl TunnelHandle for FakeHandle {
        // R——brief 原文这里写的是 `-> rmc_core::Result<()>`，跟
        // `tunnel::TunnelHandle::close_remote_session` 的真实签名
        // （`std::result::Result<(), UnknownSessionId>`，Task 7 交付）
        // 对不上，照抄编译不过。`UnknownSessionId` 不走 `ErrorClass`
        // 那套分类体系——见 tunnel.rs 上它的文档。
        async fn close_remote_session(
            &self,
            _id: u64,
        ) -> std::result::Result<(), crate::tunnel::UnknownSessionId> {
            Ok(())
        }
        async fn shutdown(self: Box<Self>) {}
    }

    #[async_trait::async_trait]
    impl TunnelFactory for Scripted {
        async fn establish(
            &self,
            params: TunnelParams,
            tx: mpsc::Sender<TunnelMsg>,
        ) -> crate::error::Result<Box<dyn TunnelHandle>> {
            self.calls.lock().unwrap().push(params);
            self.call_times.lock().unwrap().push(Instant::now());
            let outcome = self
                .outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Outcome::Err(Error::SshTransport("脚本用尽".into())));
            match outcome {
                Outcome::Err(e) => Err(e),
                Outcome::Ok(msgs) => {
                    tokio::spawn(async move {
                        for m in msgs {
                            if tx.send(m).await.is_err() {
                                return;
                            }
                        }
                    });
                    Ok(Box::new(FakeHandle))
                }
            }
        }
    }

    /// 立即返回全 Pass 的假预检——见模块顶部第 6 条。不碰网络、不等待，
    /// `Scripted` 假隧道工厂因此才有机会被真正调用到，而不是每条测试都
    /// 先卡死在对一个不存在的地址做真实 DNS/TCP 探测上。
    struct AlwaysPassPreflight;

    #[async_trait::async_trait]
    impl Preflight for AlwaysPassPreflight {
        async fn run(
            &self,
            _gateway: &HostPort,
            _appliance: &HostPort,
        ) -> preflight::PreflightReport {
            let pass = |name: &'static str| preflight::PreflightStep {
                name,
                outcome: preflight::StepOutcome::Pass {
                    detail: "ok".into(),
                },
            };
            preflight::PreflightReport {
                steps: vec![
                    pass(preflight::STEP_APPLIANCE_TCP),
                    pass(preflight::STEP_APPLIANCE_HOSTKEY),
                    pass(preflight::STEP_GATEWAY_DNS),
                    pass(preflight::STEP_GATEWAY_TLS),
                ],
            }
        }
    }

    /// R66：恒定失败的假预检，用来证明预检失败这条出口真的走的是
    /// `State::Failed`，不是被误改成 `State::Backoff`——`AlwaysPassPreflight`
    /// 永远不会让这条出口被执行到。
    struct FailingPreflight;

    #[async_trait::async_trait]
    impl Preflight for FailingPreflight {
        async fn run(
            &self,
            _gateway: &HostPort,
            _appliance: &HostPort,
        ) -> preflight::PreflightReport {
            preflight::PreflightReport {
                steps: vec![preflight::PreflightStep {
                    name: preflight::STEP_APPLIANCE_TCP,
                    outcome: preflight::StepOutcome::Fail {
                        detail: "一体机连接被拒绝".into(),
                        class: ErrorClass::ApplianceUnreachable,
                    },
                }],
            }
        }
    }

    fn config() -> Config {
        Config {
            gateway: "gateway.company.com:443".parse().unwrap(),
            appliance: "192.168.100.10:22".parse().unwrap(),
            reverse_port: 22001,
            known_hosts_path: PathBuf::from("/tmp/rmc-test/known_hosts"),
            log_dir: test_log_dir(),
        }
    }

    /// Task 11 接上 `Ctx.audit` 之后，几乎每条既有测试都会真的写审计
    /// 日志——如果继续用原来那个写死的 `/tmp/rmc-test/logs`，这个目录
    /// 会随每一次 `cargo test` 无限增长，从不清空（这个 crate 里已经
    /// 建立的惯例是"临时目录不主动清理，靠系统温度清理"，见
    /// `tests/audit.rs` 风格的 `tmpdir()`，但那些至少是按纳秒生成的
    /// 一次性路径）。这里换成本进程这一次运行专用的一次性目录（进程号
    /// 与纳秒拼出来的），整个测试二进制共用同一个目录（用 `OnceLock`
    /// 缓存，不是每条测试各生成一个——没必要为审计日志的落点单独隔离
    /// 每一条测试）。
    fn test_log_dir() -> PathBuf {
        static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        DIR.get_or_init(|| {
            let n = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            std::env::temp_dir().join(format!("rmc-core-test-{}-{n}", std::process::id()))
        })
        .clone()
    }

    struct ManualEvents(broadcast::Sender<SystemEvent>);

    impl SystemEvents for ManualEvents {
        fn subscribe(&self) -> broadcast::Receiver<SystemEvent> {
            self.0.subscribe()
        }
    }

    fn deps(factory: Arc<dyn TunnelFactory>, events: Arc<dyn SystemEvents>) -> Deps {
        Deps {
            factory,
            transport: Arc::new(Transport::new(
                Arc::new(NoProxy),
                Arc::new(NoProxyAuth),
                TlsRoots::webpki(),
            )),
            preflight: Arc::new(AlwaysPassPreflight),
            events,
            jitter: || Box::new(FixedJitter(1.0)),
        }
    }

    fn start() -> Command {
        Command::Start {
            username: "tunnel-zhang".into(),
            password: Zeroizing::new("pw".into()),
            gateway: "gateway.company.com:443".parse().unwrap(),
            appliance: "192.168.100.10:22".parse().unwrap(),
        }
    }

    /// 收集状态变迁，直到匹配 pred 或超时。
    async fn states_until(
        rx: &mut broadcast::Receiver<TunnelEvent>,
        pred: impl Fn(&State) -> bool,
    ) -> Vec<State> {
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(300);
        while Instant::now() < deadline {
            match rx.recv().await {
                Ok(TunnelEvent::State(s)) => {
                    let hit = pred(&s);
                    seen.push(s);
                    if hit {
                        return seen;
                    }
                }
                Ok(_) => {}
                Err(e) => panic!("事件通道异常：{e}"),
            }
        }
        panic!("等待状态超时，已见：{seen:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn happy_path_reaches_connected() {
        guard(async {
            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: true,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
            ])]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            let seen = states_until(&mut rx, |s| {
                matches!(s, State::Connected { degraded: false })
            })
            .await;
            assert!(matches!(seen[0], State::Preflight));
            assert!(seen.iter().any(|s| matches!(s, State::Connecting)));
        })
        .await;
    }

    // R84（复审发现）：`schedule_retry` 顶部那行 `ctx.audit.record
    // (audit_level_for(class), &e.to_string())` 是"为什么退避/回到
    // Idle"这件事在审计日志里唯一的落点（`Ctx::set_state` 记的通用
    // 状态迁移行看不出原因，`State::Idle` 不带任何字段）；原来 183 个
    // 测试没有一条检查过它的内容，删掉这一行也能全绿。这里额外读回
    // 审计日志，确认认证失败的错误原文真的留了痕。
    //
    // 会让这条测试变红的实现改法：删掉 `schedule_retry` 顶部那行
    // `ctx.audit.record(...)`。
    #[tokio::test(start_paused = true)]
    async fn auth_failure_returns_to_idle_and_does_not_retry() {
        guard(async {
            let dir = std::env::temp_dir().join(format!(
                "rmc-audit-auth-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let mut cfg = config();
            cfg.log_dir = dir.clone();

            let (factory, calls) = Scripted::new(vec![Outcome::Err(Error::AuthRejected)]);
            let (tx, mut rx) = Supervisor::spawn(
                cfg,
                deps(factory.clone(), Arc::new(NoSystemEvents::default())),
            );
            tx.send(start()).await.unwrap();

            let seen = states_until(&mut rx, |s| matches!(s, State::Idle)).await;
            assert!(
                !seen.iter().any(|s| matches!(s, State::Backoff { .. })),
                "{seen:?}"
            );
            tokio::time::sleep(Duration::from_secs(120)).await;
            assert_eq!(calls.lock().unwrap().len(), 1, "认证失败后不得自动重试");

            let a = Audit::open(dir).unwrap();
            let text = std::fs::read_to_string(a.current_path()).unwrap_or_default();
            assert!(
                text.contains("账号或口令不正确"),
                "认证失败的原因没有留痕：{text}"
            );
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn host_key_mismatch_goes_to_failed_and_does_not_retry() {
        guard(async {
            let (factory, calls) = Scripted::new(vec![Outcome::Err(Error::HostKeyMismatch {
                expected: "SHA256:aaa".into(),
                actual: "SHA256:bbb".into(),
            })]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            let seen = states_until(&mut rx, |s| matches!(s, State::Failed { .. })).await;
            match seen.last().unwrap() {
                State::Failed { class, message } => {
                    assert_eq!(*class, ErrorClass::Fatal);
                    assert!(message.contains("host key"), "{message}");
                }
                other => panic!("{other:?}"),
            }
            tokio::time::sleep(Duration::from_secs(120)).await;
            assert_eq!(calls.lock().unwrap().len(), 1);
        })
        .await;
    }

    // R68：不仅报告的 delay 数值要对，重试之间真实经过的虚拟时间也要
    // 对——否则把 `schedule_retry` 的返回值换成
    // `Some(tokio::time::Instant::now())`（照样按序上报 1/2/5/10 秒，
    // 但下一次尝试立刻发生，不真的等）这条测试原来只看 `delays`
    // 列表，会照样绿。加上 `Scripted::call_times()` 之后，
    // 用相邻两次 `establish()` 调用之间真实经过的虚拟秒数二次验证同一
    // 件事，任何"上报了正确数字但没真的等那么久"的实现都会在
    // `gaps` 断言上落网。
    #[tokio::test(start_paused = true)]
    async fn network_failure_backs_off_along_the_documented_sequence() {
        guard(async {
            let outcomes = (0..4)
                .map(|_| Outcome::Err(Error::Tcp("refused".into())))
                .chain(std::iter::once(Outcome::Ok(vec![
                    TunnelMsg::Authenticated {
                        host_key_fp: "SHA256:aaa".into(),
                        first_seen: false,
                    },
                    TunnelMsg::ForwardRegistered { port: 22001 },
                ])))
                .collect();
            let (factory, _calls) = Scripted::new(outcomes);
            let timing = factory.clone();
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            let seen = states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;
            let delays: Vec<u64> = seen
                .iter()
                .filter_map(|s| match s {
                    State::Backoff { delay, .. } => Some(delay.as_secs()),
                    _ => None,
                })
                .collect();
            assert_eq!(delays, vec![1, 2, 5, 10]);

            let times = timing.call_times();
            assert_eq!(
                times.len(),
                5,
                "应有 5 次 establish 调用（4 次失败 + 1 次成功）"
            );
            let gaps: Vec<u64> = times
                .windows(2)
                .map(|w| w[1].duration_since(w[0]).as_secs())
                .collect();
            assert_eq!(
                gaps,
                vec![1, 2, 5, 10],
                "重试之间真实经过的虚拟时间应该等于上报的 delay，而不只是\
                 上报的数字碰巧对"
            );
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn port_busy_retries_every_five_seconds_then_fails_after_budget() {
        guard(async {
            let outcomes = (0..40)
                .map(|_| Outcome::Err(Error::ForwardPortBusy(22001)))
                .collect();
            let (factory, calls) = Scripted::new(outcomes);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            let seen = states_until(&mut rx, |s| matches!(s, State::Failed { .. })).await;
            match seen.last().unwrap() {
                State::Failed { class, .. } => assert_eq!(*class, ErrorClass::PortBusy),
                other => panic!("{other:?}"),
            }
            let n = calls.lock().unwrap().len();
            let expected = (PORT_BUSY_BUDGET.as_secs() / PORT_BUSY_RETRY.as_secs()) as usize;
            assert!(
                (expected..=expected + 2).contains(&n),
                "预算内应重试约 {expected} 次，实际 {n}"
            );
            // R——见模块顶部第 5 条：界面显示的"第几次重连"不该在整段
            // 120 秒预算里恒为 0。会让这条断言变红的实现改法：
            // `schedule_retry` 的 `PortBusy` 分支不推进 `port_busy_attempt`，
            // 直接用 `ctx.backoff.attempt()`（从不因为 PortBusy 调用
            // `next_delay`，恒为 0）去填 `State::Backoff { attempt, .. }`。
            let attempts: Vec<u32> = seen
                .iter()
                .filter_map(|s| match s {
                    State::Backoff { attempt, .. } => Some(*attempt),
                    _ => None,
                })
                .collect();
            assert!(
                attempts.iter().any(|a| *a > 0),
                "端口占用重试期间界面不该一直显示第 0 次：{attempts:?}"
            );
            assert!(
                attempts.windows(2).all(|w| w[1] > w[0]),
                "端口占用重试计数应该严格递增：{attempts:?}"
            );
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn appliance_dial_failure_turns_degraded_and_recovers() {
        guard(async {
            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: false,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
                TunnelMsg::ApplianceDialFailed {
                    id: 1,
                    reason: "refused".into(),
                },
                TunnelMsg::RemoteSessionOpened { id: 2 },
            ])]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            states_until(&mut rx, |s| {
                matches!(s, State::Connected { degraded: true })
            })
            .await;
            // 一条会话成功打开即视为恢复。
            states_until(&mut rx, |s| {
                matches!(s, State::Connected { degraded: false })
            })
            .await;
        })
        .await;
    }

    // R58/R61：`connect_rx`/`msg_rx` 的处理顺序必须是 `connect_rx` 优先
    // ——见 `run()` 主循环里 `biased` 声明上方的说明。这条 race 只有在
    // 真正多线程（`flavor = "multi_thread"`）下才会被逼出来，本文件
    // 其余测试全部用默认的单线程 `current_thread` 运行时，观察不到它
    // ——单独钉在这里，用真正的多核并行反复跑同一个"建隧道成功 + 隧道
    // 建成后一体机立刻拨号失败"场景，断言 `degraded` 转移每一次都真的
    // 发生。
    //
    // 会让这条测试变红的实现改法：删掉 `run()` 里 `tokio::select!` 的
    // `biased;` 声明，或者把 `msg_rx` 分支排到 `connect_rx` 分支前面
    // ——本地验证过：两种改法叠加后，这条测试在几百次迭代内几乎必现
    // "从未见过 degraded=true"的 panic（`ApplianceDialFailed` 在
    // `ctx.state` 还是 `Connecting` 时被处理，guard 没通过，degraded
    // 转移被悄悄漏掉）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn connect_event_ordering_is_race_free_under_true_parallelism() {
        for _ in 0..300 {
            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: false,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
                TunnelMsg::ApplianceDialFailed {
                    id: 1,
                    reason: "refused".into(),
                },
                TunnelMsg::RemoteSessionOpened { id: 2 },
            ])]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            // 这条测试不能用 `start_paused`（`multi_thread` 下时间控制
            // 语义复杂，也没必要——不涉及任何退避/延时），所以这里的
            // 5 秒预算是真实挂钟时间，跟 `guard`（虚拟时钟）的 300 秒
            // 预算是两回事：单次迭代应该在毫秒级完成，5 秒对 300 次
            // 迭代来说仍然是很宽的单次上限。
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut saw_degraded = false;
            let mut saw_recovered = false;
            while std::time::Instant::now() < deadline && !saw_recovered {
                match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
                    Ok(Ok(TunnelEvent::State(State::Connected { degraded: true }))) => {
                        saw_degraded = true;
                    }
                    Ok(Ok(TunnelEvent::State(State::Connected { degraded: false })))
                        if saw_degraded =>
                    {
                        saw_recovered = true;
                    }
                    Ok(Ok(_)) => {}
                    _ => break,
                }
            }
            assert!(
                saw_degraded && saw_recovered,
                "connect_rx/msg_rx 处理顺序出现竞态：degraded={saw_degraded}，\
                 recovered={saw_recovered}"
            );
        }
    }

    // --- R71：三处命令准入判断改看同步字段，不再看 ctx.state ---
    //
    // 复现条件：调用方背靠背发两条命令，中间没有任何 `.await`——这不是
    // 人手点击能碰到的时序，是"两次 `tx.send(...).await` 之间没有别的
    // await 点"这种程序化调用方式，未来的 CLI、自动开启、集成测试都
    // 属于这一类。用 `flavor = "multi_thread"`：这条 bug 本身其实不
    // 依赖多线程才能复现（是"命令处理跟不上状态广播"的逻辑问题，不是
    // 线程竞态），但复审用这个配置验证过，这里保持一致，也顺便确认
    // 修复在多线程下同样成立。
    //
    // 会让这条测试变红的实现改法：把 `Command::Cancel | Command::Stop`
    // 分支的准入判断改回 `matches!(ctx.state, State::Idle)`——`Start`
    // 之后立刻 `Cancel`，`ctx.state` 这时可能还没离开 `Idle`，`Cancel`
    // 会被 `continue` 吞掉，状态机继续跑到 `Connected`，从不出现
    // `Idle`。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancel_right_after_start_is_not_swallowed_by_a_lagging_state() {
        for i in 0..200 {
            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: false,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
            ])]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));

            tx.send(start()).await.unwrap();
            // 中间没有任何 await——这正是 R71 的复现条件。
            tx.send(Command::Cancel).await.unwrap();

            let mut saw_idle = false;
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                match tokio::time::timeout(Duration::from_millis(300), rx.recv()).await {
                    Ok(Ok(TunnelEvent::State(State::Idle))) => {
                        saw_idle = true;
                        break;
                    }
                    Ok(Ok(_)) => {}
                    _ => break,
                }
            }
            assert!(
                saw_idle,
                "第 {i} 次迭代：Start 后立刻 Cancel（中间无 await）应该能回到 Idle，\
                 不该被吞掉"
            );
        }
    }

    // 会让这条测试变红的实现改法：把 `Command::Start` 分支的准入判断
    // 改回 `!matches!(ctx.state, State::Idle | State::Failed { .. })`
    // ——第一条 `Start` 之后 `ctx.state` 可能还没离开 `Idle`，第二条
    // `Start` 会被误判为"可以开始"，覆盖 `ctx.connect_task` 而不
    // `abort()` 旧的那个，`establish` 会被调用 2 次。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_second_start_right_after_the_first_does_not_spawn_a_second_connect_attempt() {
        struct CountingHandle;
        #[async_trait::async_trait]
        impl TunnelHandle for CountingHandle {
            async fn close_remote_session(
                &self,
                _id: u64,
            ) -> std::result::Result<(), crate::tunnel::UnknownSessionId> {
                Ok(())
            }
            async fn shutdown(self: Box<Self>) {}
        }
        struct CountingFactory(Arc<std::sync::atomic::AtomicUsize>);
        #[async_trait::async_trait]
        impl TunnelFactory for CountingFactory {
            async fn establish(
                &self,
                _params: TunnelParams,
                tx: mpsc::Sender<TunnelMsg>,
            ) -> crate::error::Result<Box<dyn TunnelHandle>> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    let _ = tx
                        .send(TunnelMsg::Authenticated {
                            host_key_fp: "SHA256:aaa".into(),
                            first_seen: false,
                        })
                        .await;
                    let _ = tx.send(TunnelMsg::ForwardRegistered { port: 22001 }).await;
                });
                Ok(Box::new(CountingHandle))
            }
        }

        for i in 0..200 {
            let established = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let factory = Arc::new(CountingFactory(established.clone()));
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));

            tx.send(start()).await.unwrap();
            // 中间没有任何 await——第二条 Start 应该被准入判断直接拒绝，
            // 不该覆盖第一条正在跑的连接任务。
            tx.send(start()).await.unwrap();

            // 只等到 Connected 为止——不需要等到彻底"安静下来"，这条
            // 场景里 Connected 之后不会再有别的事件，等安静反而白白
            // 多花一整个超时窗口的时间，200 次迭代乘起来会让这条测试
            // 慢得不成比例（第一版这么写过，200 次跑了 60 秒）。
            let mut saw_connected = false;
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while std::time::Instant::now() < deadline && !saw_connected {
                match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
                    Ok(Ok(TunnelEvent::State(State::Connected { .. }))) => saw_connected = true,
                    Ok(Ok(_)) => {}
                    _ => break,
                }
            }
            assert!(saw_connected, "第 {i} 次迭代：应该能连上");
            assert_eq!(
                established.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "第 {i} 次迭代：背靠背发两次 Start，establish 应该只被调用一次，\
                 多出来的那次对应一条从未被 abort、无人认领的隧道"
            );
        }
    }

    // --- R72：Cancel/Stop 与"建连刚好成功"撞车时，隧道不能永远漏
    // shutdown ---
    //
    // 第一版直接"发 Start 紧接发 Cancel、不插入任何等待"：本地实测
    // （3000 次迭代）`established` 恒为 0——`Cancel` 被处理得太快，
    // 后台连接任务在被 `abort()` 时压根还没被调度起来跑过
    // `establish()`，`established_n == shutdowns_n == 0` 每次都成立，
    // 但这只是在证明"从没建立过"，不是在验证"建立过的都被关掉"。第二版
    // 用 `Notify` 让工厂在真正进入 `establish()`（`fetch_add` 之后）就
    // 通知测试，测试收到通知才发 `Cancel`，本地验证过 `established`
    // 确实变成恒为 1（真的对准了 `establish()` 已经在跑的窗口），但当时
    // 的实现是"`abort()` 之后立刻排空 `connect_rx`，句柄就装在
    // `ConnectEvent::Established` 里"——即使这样对准了窗口，
    // `shutdowns_n` 依然恒等于 `established_n`（0/400 次落空），说明
    // "跨线程调度延迟"这条路径上要真正撞见泄漏比预期更难复现。
    //
    // 于是改成现在这个更强的设计：`establish()` 成功之后，句柄先同步
    // 写进 [`PendingHandle`] 槎位（这一步不跨越任何 `.await`，物理上不
    // 可能被 `abort()` 打断），`ConnectEvent::Established` 降级成一个
    // 不带负载的信号。这样"句柄会不会丢"就不再取决于"`abort()` 与
    // 那条消息的 `send()` 谁先谁后"这种时序竞赛，`teardown()` 排空
    // `connect_rx` 之后额外去槎位里再确认一次，二者之一必然接得住。
    // 断言"建立过多少次隧道就必须关掉多少次"这条不变量，不要求真的
    // 撞上任何窄窗口——反复跑、把 `Cancel` 对准 `establish` 入口，是在
    // 最大化覆盖不同时序的机会，不是这条测试成立的必要条件。
    //
    // 会让这条测试变红的实现改法：把 `Ctx::teardown` 里检查
    // `pending_handle` 槎位、`shutdown()` 里面剩下句柄的那几行删掉。
    //
    // R77（第四轮评审）订正：上一轮在这里写的是"删掉之后这条测试在
    // 第 0 次迭代就会失败，不需要真的撞上任何窄窗口"——这句话被证伪
    // 了，会让下一个人误以为不必在负载下验证这条变异。本地实测（同一
    // 台机器，tokio 1.53.1）：删掉槎位兜底之后**单跑 0/20 次失败**，
    // 只有整套测试并行时才抓得到——`cargo test -p rmc-core --lib --
    // --test-threads=32` 跑 13 次，1 次失败，而且是在第 178 次迭代才
    // 失败（`established=1, shutdowns=0`）。
    //
    // 也就是说：400 次迭代 + 真正的调度压力是这条变异能被抓到的必要
    // 条件，验证这条测试的有效性时必须在负载下跑、而且要跑够次数。
    // 槎位这个设计仍然比"靠时序取胜"更可靠——它让泄漏在**实现层面**
    // 不可能发生；但"这条测试能多快抓到回退"是另一回事，别把两者
    // 混为一谈。单纯删掉 `let _ =
    // task.await;`（保留槎位检查）本地验证过**不会**让这条测试变红：
    // 现在这一行只是为了不留一个已经判定"不再需要"的任务在后台裸跑，
    // 不是这条不泄漏保证的决定性环节——见 `Ctx::teardown` 上的说明。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancel_racing_a_successful_establish_never_leaks_the_tunnel_handle() {
        struct TrackedHandle(Arc<std::sync::atomic::AtomicUsize>);
        #[async_trait::async_trait]
        impl TunnelHandle for TrackedHandle {
            async fn close_remote_session(
                &self,
                _id: u64,
            ) -> std::result::Result<(), crate::tunnel::UnknownSessionId> {
                Ok(())
            }
            async fn shutdown(self: Box<Self>) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        struct RacyFactory {
            established: Arc<std::sync::atomic::AtomicUsize>,
            shutdowns: Arc<std::sync::atomic::AtomicUsize>,
            entered: Arc<tokio::sync::Notify>,
        }
        #[async_trait::async_trait]
        impl TunnelFactory for RacyFactory {
            async fn establish(
                &self,
                _params: TunnelParams,
                tx: mpsc::Sender<TunnelMsg>,
            ) -> crate::error::Result<Box<dyn TunnelHandle>> {
                self.established
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // 通知测试："已经真的进入 establish()"——测试收到这条
                // 通知才会发 Cancel，把 abort() 对准这里到
                // 下面 `Ok(handle)` 返回、`run_connect_sequence` 送出
                // `Established` 之间这段窗口。
                self.entered.notify_one();
                tokio::spawn(async move {
                    let _ = tx
                        .send(TunnelMsg::Authenticated {
                            host_key_fp: "SHA256:aaa".into(),
                            first_seen: false,
                        })
                        .await;
                    let _ = tx.send(TunnelMsg::ForwardRegistered { port: 22001 }).await;
                });
                Ok(Box::new(TrackedHandle(self.shutdowns.clone())))
            }
        }

        for i in 0..400 {
            let established = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let shutdowns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let entered = Arc::new(tokio::sync::Notify::new());
            let factory = Arc::new(RacyFactory {
                established: established.clone(),
                shutdowns: shutdowns.clone(),
                entered: entered.clone(),
            });
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));

            tx.send(start()).await.unwrap();
            // 等真的进入 establish() 再发 Cancel——见上面的说明，这是
            // 把 abort() 对准窄窗口的关键，不是可省略的细节。
            entered.notified().await;
            tx.send(Command::Cancel).await.unwrap();

            // 等到 Idle 为止——`Cancel` 无论有没有撞上那个窄窗口，最终
            // 都会走到 `Idle`；这是比"等到安静下来"更快、更明确的完成
            // 信号（`teardown()` 在设置 `Idle` 之前已经把该 shutdown 的
            // 都 shutdown 完了，观察到 `Idle` 时读计数器是安全的）。
            let mut saw_idle = false;
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while std::time::Instant::now() < deadline && !saw_idle {
                match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
                    Ok(Ok(TunnelEvent::State(State::Idle))) => saw_idle = true,
                    Ok(Ok(_)) => {}
                    _ => break,
                }
            }
            assert!(saw_idle, "第 {i} 次迭代：Cancel 应该已经完成、回到 Idle");

            let established_n = established.load(std::sync::atomic::Ordering::SeqCst);
            let shutdowns_n = shutdowns.load(std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                established_n, shutdowns_n,
                "第 {i} 次迭代：establish 被调用 {established_n} 次，只有 \
                 {shutdowns_n} 次被 shutdown——泄漏了一条隧道（Gateway 上会\
                 留下一条活着的会话和一个占着的反向端口，界面却已经显示\
                 已停止）"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn degraded_probe_recovers_when_the_appliance_comes_back() {
        guard(async {
            // 探测走真实 TCP。开一个本地监听充当恢复后的一体机。
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    if listener.accept().await.is_err() {
                        return;
                    }
                }
            });

            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: false,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
                TunnelMsg::ApplianceDialFailed {
                    id: 1,
                    reason: "refused".into(),
                },
            ])]);
            // 一体机地址指向那个监听端口，探测应当成功。这是本任务
            // R33/R10 的 for_test 旁路——公开的 `Command::Start` 会拒绝
            // loopback 一体机，见模块顶部第 7 条与
            // `Supervisor::spawn_with_validated_start` 上的文档。
            let gateway: HostPort = "gateway.company.com:443".parse().unwrap();
            let appliance: HostPort = format!("127.0.0.1:{port}").parse().unwrap();
            let (_tx, mut rx) = Supervisor::spawn_with_validated_start(
                config(),
                deps(factory, Arc::new(NoSystemEvents::default())),
                "tunnel-zhang".into(),
                Zeroizing::new("pw".into()),
                ValidatedAddresses::for_test(gateway, appliance),
            );

            states_until(&mut rx, |s| {
                matches!(s, State::Connected { degraded: true })
            })
            .await;
            // 无需任何远程会话，仅靠 30 秒探测就应转回。
            states_until(&mut rx, |s| {
                matches!(s, State::Connected { degraded: false })
            })
            .await;
        })
        .await;
    }

    // R63：重写。旧版有两层问题：
    // 1. `match ... { Ok(Ok(TunnelEvent::State(s))) => {...}, _ => break }`
    //    把"收到一条非 State 事件"（例如 `Preflight`/`RemoteSessions`）
    //    也当成"结束观察，退出循环"——一次探测周期里只要混进一条不相干
    //    的事件就会提前收工，根本没验证到后面的周期。
    // 2. `probe_appliance` 打的是真实 TCP（`Transport::probe_tcp`），
    //    探测失败时（`Err` 分支）完全不广播任何事件——120 秒窗口内一次
    //    "探测失败也清 degraded"的变异如果发生在某次探测的 `Ok` 分支
    //    上才会被看见，如果窗口内探测本身没有再失败/成功产生新事件，
    //    这条测试会在第一次 35 秒超时后就 `break`，什么都没验证到就
    //    "通过"了。评审实测过：这个变异并行跑 6/6 全绿、单独跑 3/4 红，
    //    典型的检测力不稳。
    //
    // 改法：不再用"等事件或超时"的消极观察，而是主动推进虚拟时钟越过
    // 三个完整的探测周期（`APPLIANCE_PROBE` = 30 秒 一个周期），每个
    // 周期结束后用 `try_recv()` 排空这段时间里产生的所有事件——任何一条
    // `State` 事件都必须仍是 `degraded: true`，非 `State` 事件直接忽略
    // 而不是当成"观察结束"的信号。
    #[tokio::test(start_paused = true)]
    async fn degraded_stays_degraded_while_the_appliance_is_still_down() {
        guard(async {
            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: false,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
                TunnelMsg::ApplianceDialFailed {
                    id: 1,
                    reason: "refused".into(),
                },
            ])]);
            // 绑一个端口立刻释放：这个地址在探测时必然被拒绝（比裸写
            // 127.0.0.1:1 更明确地表达"这个端口现在没有人监听"）。
            //
            // R74 提出过一个理论风险："bind 到 drop 之间存在一个极窄
            // 窗口，可能被同一台机器上另一个并发测试的 bind(0) 抢先
            // 复用"（32 线程并行跑过 26 次没有撞到，但不等于不存在）。
            // 当时试过加一次"绑完立刻回连确认真的被拒绝、不行就换一个"
            // 的自检，结果这条测试**必现地**跑不完，于是回退了，并在
            // 这里写下"成因不明的 tokio 交互问题"。
            //
            // R77（第四轮评审）：那条记录的成因写反了，现已订正——
            // **不是挂死，是虚拟时钟一步跳掉了 262 秒。**
            //
            // `start_paused` 的自动前进发生在运行时 park 且没有可跑
            // 任务的时候，前进量取自 `wheel.next_expiration_time()`
            // ——而这个值是**时间轮层级槽的边界**，不是定时器的真实
            // 到期时刻（tokio `time/wheel/level.rs`：
            // `slot_range(level) = 64^level` 毫秒，level 3 = 262144 ms）。
            // 这条测试跑起来时唯一挂在时间轮上的定时器是 `guard` 的
            // 300000 ms，落在 level 3 的 1 号槽，槽边界正是 262144 ms。
            // 于是**一次真实 I/O 的 `.await`——这恰好是"让运行时 park
            // 而时间轮里没有近处定时器"最常见的方式——就让虚拟钟一步
            // 跳到 262.144 秒**，`guard` 的 300 秒预算只剩 38 秒，
            // 测试跑到 cycle 1 就超时了。整个测试二进制真实时间只花了
            // 0.01 秒就返回，压根没有"挂住"。
            //
            // 两个反证（本地对 tokio 1.53.1 实测）：
            //  - 在测试里额外挂一个 1 秒心跳任务（时间轮里始终有近处
            //    定时器，每次只跳 1 秒），同一次真实 I/O 之后虚拟时钟
            //    只前进 1 秒，测试通过；
            //  - 把 `guard` 从 300 秒改成 1000 秒（下一个 level 3 边界
            //    是 786432 ms，跳完仍有 214 秒余量），同样通过。
            //
            // 所以这个自检可以零风险地加回来，只要**不让运行时 park**：
            // 用阻塞的 `std::net::TcpStream::connect_timeout` 而不是
            // `tokio::net::TcpStream::connect().await`——前者完全不经过
            // tokio 的 I/O driver，对着 127.0.0.1 上一个没人监听的端口
            // 是一次立刻返回 ECONNREFUSED 的系统调用，既不会让运行时
            // park，也不会真的等满那个超时。
            let dead_port = {
                let mut chosen = None;
                for _ in 0..16 {
                    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let addr = dead.local_addr().unwrap();
                    drop(dead);
                    // 回连确认这个端口真的没人接——万一在 drop 到这一
                    // 步之间被另一个并发测试的 bind(0) 抢先复用，就换
                    // 一个重来。
                    if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200))
                        .is_err()
                    {
                        chosen = Some(addr.port());
                        break;
                    }
                }
                chosen.expect("连续 16 次都没能拿到一个确认无人监听的本地端口")
            };

            let gateway: HostPort = "gateway.company.com:443".parse().unwrap();
            let appliance: HostPort = format!("127.0.0.1:{dead_port}").parse().unwrap();
            let (_tx, mut rx) = Supervisor::spawn_with_validated_start(
                config(),
                deps(factory, Arc::new(NoSystemEvents::default())),
                "tunnel-zhang".into(),
                Zeroizing::new("pw".into()),
                ValidatedAddresses::for_test(gateway, appliance),
            );

            states_until(&mut rx, |s| {
                matches!(s, State::Connected { degraded: true })
            })
            .await;

            for cycle in 0..3 {
                tokio::time::sleep(APPLIANCE_PROBE + Duration::from_secs(2)).await;
                while let Ok(ev) = rx.try_recv() {
                    if let TunnelEvent::State(s) = ev {
                        assert!(
                            matches!(s, State::Connected { degraded: true }),
                            "第 {cycle} 个探测周期内状态不该变成 {s:?}"
                        );
                    }
                }
            }
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn disconnect_reconnects_and_reuses_credentials_without_a_new_start() {
        guard(async {
            let (factory, calls) = Scripted::new(vec![
                Outcome::Ok(vec![
                    TunnelMsg::Authenticated {
                        host_key_fp: "SHA256:aaa".into(),
                        first_seen: false,
                    },
                    TunnelMsg::ForwardRegistered { port: 22001 },
                    TunnelMsg::Disconnected {
                        reason: "reset".into(),
                    },
                ]),
                Outcome::Ok(vec![
                    TunnelMsg::Authenticated {
                        host_key_fp: "SHA256:aaa".into(),
                        first_seen: false,
                    },
                    TunnelMsg::ForwardRegistered { port: 22001 },
                ]),
            ]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            states_until(&mut rx, |s| matches!(s, State::Backoff { .. })).await;
            states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;

            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].username, calls[1].username);
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn network_event_clears_backoff_and_retries_at_once() {
        guard(async {
            let outcomes = vec![
                Outcome::Err(Error::Tcp("refused".into())),
                Outcome::Err(Error::Tcp("refused".into())),
                Outcome::Err(Error::Tcp("refused".into())),
                Outcome::Ok(vec![
                    TunnelMsg::Authenticated {
                        host_key_fp: "SHA256:aaa".into(),
                        first_seen: false,
                    },
                    TunnelMsg::ForwardRegistered { port: 22001 },
                ]),
            ];
            let (factory, _calls) = Scripted::new(outcomes);
            let (ev_tx, _) = broadcast::channel(8);
            let events = Arc::new(ManualEvents(ev_tx.clone()));
            let (tx, mut rx) = Supervisor::spawn(config(), deps(factory, events));
            tx.send(start()).await.unwrap();

            states_until(&mut rx, |s| matches!(s, State::Backoff { attempt: 2, .. })).await;
            ev_tx.send(SystemEvent::NetworkChanged).unwrap();

            let seen = states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;
            // 事件触发后下一次退避必须回到序列起点。
            let delays: Vec<u64> = seen
                .iter()
                .filter_map(|s| match s {
                    State::Backoff { delay, .. } => Some(delay.as_secs()),
                    _ => None,
                })
                .collect();
            assert_eq!(delays.last(), Some(&1), "退避未清零：{delays:?}");
        })
        .await;
    }

    // --- R75（第四轮评审）：`Backoff` 期间连发两条系统事件会必现地泄漏
    // 一条隧道 ---
    //
    // 现场最普通的一条路径：笔记本从睡眠恢复时，`platform` 会同时产生
    // `ResumedFromSleep` 与 `NetworkChanged`（方案 §3.9 明确要求两者都
    // 接），而"恢复那一刻"状态机几乎必然正在 `Backoff`（睡眠期间网络
    // 早就断了）。两条事件之间没有任何 `.await`，主循环连着处理两次：
    // 第一次 `spawn_connect` 已经**同步**写好了 `ctx.connect_task`，但
    // `ctx.state` 要等后台任务回 `EnteredConnecting` 才离开 `Backoff`
    // ——用 `ctx.state` 做准入判断的话，第二条事件会被误判为"还在退避、
    // 可以立刻重试"，`spawn_connect` 覆盖 `ctx.connect_task`（旧
    // `JoinHandle` 被丢弃、从不 `abort()`）**并且覆盖 `pending_handle`
    // 槎位**：第一个任务建成的隧道写进的是已经没人持有的那个槎位，
    // `Arc` 归零后句柄被 drop——Gateway 上留下一条活着的 SSH 会话和一个
    // 已注册的反向端口，界面全程无感。
    //
    // 这不是竞态，是必现：单线程运行时下 `spawn_connect` 起的任务在主
    // 循环下一次真正 park 之前根本没机会被调度（`sys.recv()` 有缓冲
    // 事件时直接返回 `Ready`，不让出执行权），第二条事件必然撞在
    // "`connect_task` 已设置、`ctx.state` 还没变"这个窗口里。
    //
    // 会让这条测试变红的实现改法：把系统事件分支的准入判断
    // `retry_at.is_some() && !connecting_or_connected(&ctx)` 改回
    // `matches!(ctx.state, State::Backoff { .. })`——本地实测连续 20 次
    // 单跑全部失败（20/20），失败信息恒为 `handles=2, shutdowns=1`。
    // 这条测试用 `start_paused = true`，只能跑在 `current_thread` 上
    // （tokio 不允许 `start_paused` 配 `multi_thread`），但这条缺陷本来
    // 就不需要多线程才能现形。
    #[tokio::test(start_paused = true)]
    async fn two_system_events_during_backoff_do_not_leak_a_tunnel() {
        guard(async {
            struct CountingHandle(Arc<std::sync::atomic::AtomicUsize>);
            #[async_trait::async_trait]
            impl TunnelHandle for CountingHandle {
                async fn close_remote_session(
                    &self,
                    _id: u64,
                ) -> std::result::Result<(), crate::tunnel::UnknownSessionId> {
                    Ok(())
                }
                async fn shutdown(self: Box<Self>) {
                    self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
            /// 第一次 `establish()` 失败（把状态机送进 `Backoff`），之后
            /// 每次都成功——`handles` 只统计真的造出过句柄的那些次。
            struct CountingFactory {
                attempts: Arc<std::sync::atomic::AtomicUsize>,
                handles: Arc<std::sync::atomic::AtomicUsize>,
                shutdowns: Arc<std::sync::atomic::AtomicUsize>,
            }
            #[async_trait::async_trait]
            impl TunnelFactory for CountingFactory {
                async fn establish(
                    &self,
                    _params: TunnelParams,
                    tx: mpsc::Sender<TunnelMsg>,
                ) -> crate::error::Result<Box<dyn TunnelHandle>> {
                    if self
                        .attempts
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                        == 0
                    {
                        return Err(Error::Tcp("refused".into()));
                    }
                    self.handles
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    tokio::spawn(async move {
                        let _ = tx
                            .send(TunnelMsg::Authenticated {
                                host_key_fp: "SHA256:aaa".into(),
                                first_seen: false,
                            })
                            .await;
                        let _ = tx.send(TunnelMsg::ForwardRegistered { port: 22001 }).await;
                    });
                    Ok(Box::new(CountingHandle(self.shutdowns.clone())))
                }
            }

            let handles = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let shutdowns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let factory = Arc::new(CountingFactory {
                attempts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                handles: handles.clone(),
                shutdowns: shutdowns.clone(),
            });
            let (ev_tx, _) = broadcast::channel(8);
            let events = Arc::new(ManualEvents(ev_tx.clone()));
            let (tx, mut rx) = Supervisor::spawn(config(), deps(factory, events));
            tx.send(start()).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Backoff { .. })).await;

            // 两条事件之间不插入任何 await——这正是"笔记本醒来"那一刻
            // 真实发生的事。
            ev_tx.send(SystemEvent::ResumedFromSleep).unwrap();
            ev_tx.send(SystemEvent::NetworkChanged).unwrap();

            states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;
            tx.send(Command::Stop).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Idle)).await;
            // 给那个（可能存在的）被覆盖、无人认领的连接任务足够的机会
            // 跑完 `establish()`——泄漏要等它真的造出句柄才看得见。
            tokio::time::sleep(Duration::from_secs(1)).await;

            let handles_n = handles.load(std::sync::atomic::Ordering::SeqCst);
            let shutdowns_n = shutdowns.load(std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                handles_n, shutdowns_n,
                "建成 {handles_n} 条隧道却只关掉 {shutdowns_n} 条：多出来的那条\
                 在 Gateway 上仍然活着、反向端口仍然被占用，界面上完全看不到"
            );
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn stop_from_connected_returns_to_idle() {
        guard(async {
            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: false,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
            ])]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;

            tx.send(Command::Stop).await.unwrap();
            let seen = states_until(&mut rx, |s| matches!(s, State::Idle)).await;
            assert!(seen.iter().any(|s| matches!(s, State::Stopping)));
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn stop_during_backoff_returns_to_idle_and_stops_retrying() {
        guard(async {
            let outcomes = (0..20)
                .map(|_| Outcome::Err(Error::Tcp("refused".into())))
                .collect();
            let (factory, calls) = Scripted::new(outcomes);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Backoff { .. })).await;

            tx.send(Command::Stop).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Idle)).await;
            let before = calls.lock().unwrap().len();
            tokio::time::sleep(Duration::from_secs(120)).await;
            assert_eq!(calls.lock().unwrap().len(), before, "停止后仍在重试");
        })
        .await;
    }

    // --- R78（第四轮评审，安全）：`Failed` 下 `Stop` 必须仍然有效 ---
    //
    // 上一轮（R71）的新准入条件让 `Failed` 下 `Cancel`/`Stop` 都变成了
    // 空操作（三项判据皆假）。按方案 §3.5 的表格，`Failed` 只允许
    // "重试、查看诊断"，所以从状态机角度这更贴规格——但副作用是
    // `Failed` 期间那份 `Zeroizing<String>` 口令会一直留在进程内存里，
    // 直到下一次 `Start` 或进程退出。而 §3.8 明确要求口令"仅存于进程
    // 内存，认证后清除"。工程师遇到失败之后合上笔记本走人，恰恰是最
    // 常见的收尾方式。
    //
    // 裁定：两条规格冲突时安全那条优先，`Failed` 下 `Stop` 有效
    // （走 `teardown`、清 `creds`、回 `Idle`），`Cancel` 保持空操作
    // （见下一条测试）。
    //
    // "口令真的被清掉了"这件事没有直接的观测点（`Credentials` 不
    // 外泄、也不进任何事件），这里用它唯一的可观测后果代替：`Stop`
    // 之后再发一条 `RetryNow`，`spawn_connect` 会因为 `ctx.creds` 是
    // `None` 而什么都不做，`establish` 的调用次数不会增加。
    //
    // 会让这条测试变红的实现改法：把 `Command::Stop` 的准入判断改回
    // 跟 `Command::Cancel` 一样（即去掉 `ctx.creds.is_some()` 与
    // `matches!(ctx.state, State::Failed { .. })` 这两条）——`Stop`
    // 在 `Failed` 下被直接吞掉，等不到 `Idle`，`states_until` 会在
    // 300 秒虚拟超时后 panic。
    #[tokio::test(start_paused = true)]
    async fn stop_from_failed_clears_the_password_and_returns_to_idle() {
        guard(async {
            // host key 不匹配 → Fatal → `Failed`，而且这条路径**不会**
            // 顺手清掉凭据（只有 `Auth` 类和地址校验失败会清），正是
            // "口令留在内存里"那个场景。
            let (factory, calls) = Scripted::new(vec![Outcome::Err(Error::HostKeyMismatch {
                expected: "SHA256:aaa".into(),
                actual: "SHA256:bbb".into(),
            })]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Failed { .. })).await;
            assert_eq!(calls.lock().unwrap().len(), 1);

            tx.send(Command::Stop).await.unwrap();
            let seen = states_until(&mut rx, |s| matches!(s, State::Idle)).await;
            assert!(
                seen.iter().any(|s| matches!(s, State::Stopping)),
                "Stop 应该先广播 Stopping 再回 Idle，实际：{seen:?}"
            );

            // 凭据真的被清掉了：`RetryNow` 拿不到凭据，不会再发起一次
            // 连接尝试。
            tx.send(Command::RetryNow).await.unwrap();
            tokio::time::sleep(Duration::from_secs(120)).await;
            assert_eq!(
                calls.lock().unwrap().len(),
                1,
                "Stop 之后凭据仍在内存里：RetryNow 又拿旧口令去连了一次"
            );
        })
        .await;
    }

    // --- Task 11：口令不会经由 Supervisor 落到审计日志 ---
    //
    // brief 原文把这条测试写进外部集成测试文件
    // `crates/rmc-core/tests/supervisor.rs`——那个文件不存在，而且就算
    // 建一个也用不了：`Scripted`/`Outcome`/`deps`/`config`/
    // `states_until`/`NoSystemEvents` 全部是本模块（`#[cfg(test)] mod
    // tests`）内部的私有测试基础设施，外部集成测试是独立 crate，看
    // 不到任何私有/`#[cfg(test)]` 项——跟 `config.rs` 里
    // `ValidatedAddresses::for_test` 上说明的道理一样。放在这里才编
    // 得过，也符合本 crate 一贯把测试放在同文件 `#[cfg(test)]` 里的
    // 做法。
    //
    // 双向证据：`!text.contains(...)` 这类"不包含"断言，在日志压根
    // 没被写出来的时候也会通过（`ssh/pump.rs` 的哨兵测试真的这样栽过
    // 一次，见该文件顶部 R59/R74 的说明）。`assert!(!text.is_empty())`
    // 排掉了"文件是空的"这一种；真正的双向证据是本任务提交前手动做
    // 过的变异测试：临时在 `begin()` 里把审计记录改成
    // `format!("... 口令 {}", **password)`（把 `Zeroizing<String>`
    // 解引用出来拼进消息），跑这条测试——变红（`assert!(!text.
    // contains("PLAINTEXT-SECRET-9f2a"), ...)` 失败，报出口令原文出现
    // 在了日志文本里），改回来之后再跑——变绿。这一步之后被撤销，不
    // 留在最终代码里；PR/commit 历史里的这条记录本身就是证据。
    #[tokio::test(start_paused = true)]
    async fn password_never_reaches_the_audit_log() {
        guard(async {
            let dir = std::env::temp_dir().join(format!(
                "rmc-audit-sup-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();

            let mut cfg = config();
            cfg.log_dir = dir.clone();

            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: true,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
            ])]);
            let (tx, mut rx) =
                Supervisor::spawn(cfg, deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(Command::Start {
                username: "tunnel-zhang".into(),
                password: Zeroizing::new("PLAINTEXT-SECRET-9f2a".into()),
                gateway: "gateway.company.com:443".parse().unwrap(),
                appliance: "192.168.100.10:22".parse().unwrap(),
            })
            .await
            .unwrap();
            states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;

            let a = Audit::open(dir.clone()).unwrap();
            let text = std::fs::read_to_string(a.current_path()).unwrap_or_default();
            assert!(!text.is_empty(), "Supervisor 应当写入审计日志");
            assert!(
                !text.contains("PLAINTEXT-SECRET-9f2a"),
                "口令进了日志：{text}"
            );
            assert!(text.contains("tunnel-zhang"), "账号应当留痕：{text}");
            assert!(text.contains("已连接"), "状态变迁未入日志：{text}");
        })
        .await;
    }

    // --- Task 11：审计日志目录坏掉不该掐断一次正在进行的维护会话 ---
    //
    // 这是"写不进去不是 Fatal"这条裁定在 Supervisor 接线层面唯一能在
    // 单元测试里直接摆出来的证据：把 `log_dir` 指向一个已经存在的
    // 普通文件（不是目录），`Audit::open` 内部的 `create_dir_all` 会
    // 因此失败（要创建目录的路径上已经有一个同名文件）——这是
    // `Error::LocalIo` 真实会发生的场景之一,不是伪造的错误分支。
    //
    // 会让这条测试变红的实现改法：把 `run()` 里
    // `Audit::open(cfg.log_dir.clone()).unwrap_or_else(...)` 改回
    // brief 原文那种 `Audit::open(cfg.log_dir.clone()).unwrap()`——
    // 本地实测：审计目录坏掉会让 `unwrap()` 在 `run()`（`tokio::spawn`
    // 出来的任务）里直接 panic，任务连同它持有的 `cmd_rx`/`ev_tx` 一起
    // 被立刻丢弃；`states_until` 读事件通道时会先撞上
    // `Err(RecvError::Closed)`，落进它自己 `Err(e) => panic!("事件
    // 通道异常：{e}")` 那一支，报"channel closed"而不是等到 300 秒
    // 虚拟超时——失败得又快又清楚，不需要等超时才能看出问题。
    #[tokio::test(start_paused = true)]
    async fn audit_directory_failure_does_not_block_a_live_session() {
        guard(async {
            let dir = std::env::temp_dir().join(format!(
                "rmc-audit-blocked-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            // 造一个同名的普通文件，占住这个路径，让 `create_dir_all`
            // 必定失败。
            std::fs::write(&dir, b"i-am-a-file-not-a-directory").unwrap();

            let mut cfg = config();
            cfg.log_dir = dir;

            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: true,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
            ])]);
            let (tx, mut rx) =
                Supervisor::spawn(cfg, deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            // 审计目录坏掉，会话本身照样要能连到 Connected。
            states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;
        })
        .await;
    }

    // --- R90（复审发现）：`prune()` 不能只在启动时跑一次。---
    //
    // 现场笔记本经常连续开机运行数周不重启，`RETENTION_DAYS` 因此
    // 事实上失效——保留期清理逻辑本身没坏，只是没有第二次被叫到的
    // 机会。造一个"启动之后才出现"的陈旧文件（启动那一次清理不可能
    // 删过它），推进虚拟时钟一整个清理周期，确认它被周期性清理删掉。
    //
    // 会让这条测试变红的实现改法：把 `run()` 主循环里 R90 新加的
    // `_ = tokio::time::sleep_until(prune_at) => { ... }` 分支删掉，
    // 改回只在 `run()` 开头调一次 `audit.prune()`。
    //
    // 不用共享的 `guard()`：它固定 300 秒的死锁预算比这条测试本身
    // 需要的 24 小时虚拟等待还短，会被自己的死锁哨兵误伤（`start_
    // paused` 下这 24 小时是虚拟时间，近乎不花真实时间，但仍然长于
    // 300 秒虚拟预算）。换一个更宽的预算，仍然是"卡死会报错，不是
    // 挂住"，只是上限跟着这条测试自己的周期走。
    #[tokio::test(start_paused = true)]
    async fn prune_runs_periodically_not_only_at_startup() {
        let fut = async {
            let dir = std::env::temp_dir().join(format!(
                "rmc-audit-periodic-prune-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let mut cfg = config();
            cfg.log_dir = dir.clone();

            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: true,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
            ])]);
            let (tx, mut rx) =
                Supervisor::spawn(cfg, deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;

            // 启动时那次 prune 已经跑完（`Supervisor::spawn` 里同步
            // 执行，早于主循环第一次 `select!`）。这个陈旧文件是启动
            // 之后才写进去的，启动那一次清理不可能删过它。
            let stale = dir.join("rmc-2000-01-01.log");
            std::fs::write(&stale, "老日志\n").unwrap();
            let long_ago =
                std::time::SystemTime::now() - std::time::Duration::from_secs(40 * 86_400);
            filetime::set_file_mtime(&stale, filetime::FileTime::from_system_time(long_ago))
                .unwrap();
            assert!(stale.exists());

            // 虚拟时钟推进一整个清理周期——如果 `prune()` 只在启动时
            // 跑过一次，这个文件会一直留着。
            tokio::time::sleep(AUDIT_PRUNE_INTERVAL + Duration::from_secs(1)).await;

            assert!(!stale.exists(), "24 小时后陈旧日志应该被周期性清理删掉");
        };
        tokio::time::timeout(Duration::from_secs(25 * 3600), fut)
            .await
            .expect("测试超过 25 小时（虚拟）仍未完成，判定为死锁");
    }

    // R78 的另一半：`Cancel` 在 `Failed` 下**保持**空操作，这个不对称
    // 是有意的。`Cancel` 的语义是"取消正在进行的这次开启"，`Failed`
    // 下没有任何正在进行的东西可取消；`Stop` 的语义是"我不玩了"，
    // 任何状态下可用符合直觉，而且它还兼着清口令的安全职责。
    //
    // 会让这条测试变红的实现改法：把 `Command::Cancel` 的准入判断也
    // 加上 `Failed` 那两条（或者干脆把两个分支合并回一个）——`Cancel`
    // 会把状态机带回 `Idle`，下面那次"1 秒内不应该有任何状态事件"的
    // 断言立刻落空。
    #[tokio::test(start_paused = true)]
    async fn cancel_from_failed_is_a_no_op_by_design() {
        guard(async {
            let (factory, _calls) = Scripted::new(vec![Outcome::Err(Error::HostKeyMismatch {
                expected: "SHA256:aaa".into(),
                actual: "SHA256:bbb".into(),
            })]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Failed { .. })).await;

            tx.send(Command::Cancel).await.unwrap();
            // `start_paused` 下这 1 秒是虚拟时间，不花真实时间；同时
            // 它也是这条断言的超时上限，不会挂住。
            let next = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await;
            assert!(
                next.is_err(),
                "Failed 下的 Cancel 应该是空操作，实际又广播了状态：{next:?}"
            );
        })
        .await;
    }

    // R84（复审发现，中等严重）：审计内容原来除了口令测试那四条粗
    // 断言之外零覆盖——评审把 `begin()` 的"Gateway，一体机"整段、
    // `RemoteSessionOpened`/`RemoteSessionClosed`/`ForwardRegistered`
    // 四处审计行全删，183 个测试全绿。"连到了哪台一体机"这个 Task 11
    // 自己定义的核心追责要素，一次重构就能悄悄消失，没有任何测试会
    // 报警。这条测试现在额外读回审计日志文件、逐一断言这几处内容都
    // 真的写进去了；`schedule_retry` 那一行错误原文的覆盖见
    // `auth_failure_returns_to_idle_and_does_not_retry`（这条测试走的
    // 是没有错误的正常路径，覆盖不到那一行）。
    //
    // 会让这条测试变红的实现改法：删掉 `begin()`/`handle_msg` 里
    // `ForwardRegistered`/`RemoteSessionOpened`/`RemoteSessionClosed`
    // 对应的任意一行 `ctx.audit.record(...)`。
    //
    // R92（Task 12 复审追加）：这条测试本身当时也漏了 host key 指纹行
    // ——最后一条 `assert!` 是本次追加的，见该处注释。「干了多久」
    // （`record_session_closed` 的时长）与「远程会话 N 连接一体机
    // 失败」两处缺口分别在
    // `record_session_closed_writes_the_real_elapsed_seconds`（本文件
    // 后面）与 `appliance_dial_failure_is_recorded_with_its_reason`
    // 里补上——前者必须绕开 `start_paused`（它只虚拟化 tokio 的时钟，
    // 管不到 `record_session_closed` 用的 `std::time::SystemTime`），
    // 所以直接对私有函数写单元测试，不走这条集成测试。
    #[tokio::test(start_paused = true)]
    async fn remote_sessions_are_reported_with_traffic_and_removed_on_close() {
        guard(async {
            let dir = std::env::temp_dir().join(format!(
                "rmc-audit-sessions-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let mut cfg = config();
            cfg.log_dir = dir.clone();

            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: false,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
                TunnelMsg::RemoteSessionOpened { id: 7 },
                TunnelMsg::RemoteSessionBytes {
                    id: 7,
                    to_appliance: 100,
                    from_appliance: 200,
                },
                TunnelMsg::RemoteSessionClosed { id: 7 },
            ])]);
            let (tx, mut rx) =
                Supervisor::spawn(cfg, deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            let mut with_traffic = false;
            let mut emptied = false;
            let deadline = Instant::now() + Duration::from_secs(60);
            while Instant::now() < deadline && !(with_traffic && emptied) {
                if let Ok(TunnelEvent::RemoteSessions(list)) = rx.recv().await {
                    if list.iter().any(|s| s.id == 7 && s.from_appliance == 200) {
                        with_traffic = true;
                    }
                    if with_traffic && list.is_empty() {
                        emptied = true;
                    }
                }
            }
            assert!(with_traffic, "没有收到带流量的会话列表");
            assert!(emptied, "会话关闭后列表未清空");

            let a = Audit::open(dir).unwrap();
            let text = std::fs::read_to_string(a.current_path()).unwrap_or_default();
            assert!(
                text.contains("192.168.100.10:22"),
                "「连到了哪台一体机」这条账目丢了：{text}"
            );
            assert!(text.contains("22001 已注册"), "{text}");
            assert!(text.contains("远程会话 7 已开启"), "{text}");
            assert!(text.contains("远程会话 7 已关闭"), "{text}");
            assert!(
                text.contains("100 字节") && text.contains("200 字节"),
                "字节数没记全：{text}"
            );
            // R92（Task 12 复审发现）：host key 指纹行（`§3.8` 明确要求
            // 留痕的安全要素）此前没有任何测试断言过内容，删掉整行也
            // 全绿——补上。会让这条断言变红的实现改法：把 `handle_msg`
            // 里 `TunnelMsg::Authenticated` 分支对应的
            // `ctx.audit.record(...)` 那一行删掉。
            assert!(
                text.contains("host key SHA256:aaa"),
                "「host key 指纹」这条账目丢了：{text}"
            );
        })
        .await;
    }

    // R92（Task 12 复审发现，HIGH）：`record_session_closed` 里的时长
    // 此前零覆盖——评审把 `secs` 改成恒定的 `0`，整套 `cargo test`
    // （197 个用例）全绿。「干了多久」是 Task 11 自己定义的四个追责
    // 要素之一（模块文档第一段），一次重构就能悄悄变成常数 0 而无人
    // 报警。
    //
    // 直接给这个私有函数写单元测试，不走 `Supervisor` 那一整套异步
    // 状态机：`#[tokio::test(start_paused = true)]` 的虚拟时钟只加速
    // `tokio::time`，管不到 `record_session_closed` 用的
    // `std::time::SystemTime`——把这条断言塞进一条 `start_paused` 的
    // 集成测试，量出来的真实耗时永远接近 0 秒，测不出"时长是不是真的
    // 按 `opened_at` 算出来的"这件事。这里用一个纯同步的 `#[test]`
    // （不需要 tokio），把 `opened_at` 直接写成 90 秒前。
    //
    // 会让这条测试变红的实现改法：把 `record_session_closed` 里
    // `SystemTime::now().duration_since(info.opened_at).map(|d|
    // d.as_secs())` 换成恒定的 `0`（或任何跟 `opened_at` 无关的固定
    // 值）。**已做过变异验证**：临时改成 `let secs = 0u64;` 本地跑过，
    // 确认这条测试会在 `assert!` 上失败（日志里看到的是"用时 0 秒"，
    // 不含"用时 90 秒"）；改完已还原。
    #[test]
    fn record_session_closed_writes_the_real_elapsed_seconds() {
        let dir = std::env::temp_dir().join(format!(
            "rmc-audit-duration-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let audit = Audit::open(dir.clone()).unwrap();
        let info = RemoteSessionInfo {
            id: 42,
            opened_at: SystemTime::now() - Duration::from_secs(90),
            to_appliance: 1,
            from_appliance: 2,
        };

        record_session_closed(&audit, 42, &info);

        let text = std::fs::read_to_string(audit.current_path()).unwrap();
        assert!(text.contains("用时 90 秒"), "{text}");
    }

    // R92（Task 12 复审发现）：`TunnelMsg::ApplianceDialFailed` 对应的
    // "远程会话 N 连接一体机失败：{原因}"这一行此前也没有任何测试断言
    // 过内容，删掉整行同样全绿。
    //
    // 会让这条测试变红的实现改法：把 `handle_msg` 里
    // `TunnelMsg::ApplianceDialFailed` 分支对应的
    // `ctx.audit.record(...)` 那一行删掉。
    #[tokio::test(start_paused = true)]
    async fn appliance_dial_failure_is_recorded_with_its_reason() {
        guard(async {
            let dir = std::env::temp_dir().join(format!(
                "rmc-audit-dialfail-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let mut cfg = config();
            cfg.log_dir = dir.clone();

            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: false,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
                TunnelMsg::ApplianceDialFailed {
                    id: 9,
                    reason: "TEMP-MUTATION-CHECK-拒绝连接".into(),
                },
            ])]);
            let (tx, mut rx) =
                Supervisor::spawn(cfg, deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            states_until(&mut rx, |s| {
                matches!(s, State::Connected { degraded: true })
            })
            .await;

            let a = Audit::open(dir).unwrap();
            let text = std::fs::read_to_string(a.current_path()).unwrap();
            assert!(
                text.contains("远程会话 9 连接一体机失败")
                    && text.contains("TEMP-MUTATION-CHECK-拒绝连接"),
                "{text}"
            );
        })
        .await;
    }

    // --- R83（复审发现，最要紧）：隧道非正常结束时残留的远程会话不能
    // 被静默丢弃。---
    //
    // 评审用探针实证：`RemoteSessionOpened{7}` → `RemoteSessionBytes
    // {111,222}` → `Disconnected`（没有显式的 `RemoteSessionClosed`），
    // 日志原来到"远程会话 7 已开启"为止，没有任何关闭记录——而这正是
    // 最常见的收尾路径：远程工程师正连着客户一体机，现场笔记本断网，
    // 或者现场人员点"停止"。事后追责问"他连了多久、传了多少"，答案
    // 原来止步于"开启过"。这不是时序运气：`msg_rx` 的 guard 是
    // `ctx.handle.is_some()`（见 `run()` 主循环），`teardown()` 已经把
    // `self.handle` 取走，即使 pump 补发了 `RemoteSessionClosed` 也
    // 永远不会被 `handle_msg` 处理到，是结构性的必然（见 `Ctx::
    // teardown` 上的说明）。
    //
    // 会让这条测试变红的实现改法：把 `Ctx::teardown` 里 R83 新加的那段
    // （对 `self.sessions` 逐个调 `record_session_closed`）删掉，改回
    // 原来那句单纯的 `self.sessions.clear()`。
    #[tokio::test(start_paused = true)]
    async fn residual_remote_sessions_are_recorded_as_closed_when_the_tunnel_ends_abnormally() {
        guard(async {
            let dir = std::env::temp_dir().join(format!(
                "rmc-audit-residual-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let mut cfg = config();
            cfg.log_dir = dir.clone();

            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: true,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
                TunnelMsg::RemoteSessionOpened { id: 7 },
                TunnelMsg::RemoteSessionBytes {
                    id: 7,
                    to_appliance: 111,
                    from_appliance: 222,
                },
                TunnelMsg::Disconnected {
                    reason: "SSH 会话已断开".into(),
                },
            ])]);
            let (tx, mut rx) =
                Supervisor::spawn(cfg, deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            // 断线是网络类错误，会转 Backoff 等待重连；到这一步
            // `teardown()` 已经跑完，正是我们要验证的时机。
            states_until(&mut rx, |s| matches!(s, State::Backoff { .. })).await;

            let a = Audit::open(dir).unwrap();
            let text = std::fs::read_to_string(a.current_path()).unwrap_or_default();
            assert!(text.contains("远程会话 7 已开启"), "{text}");
            assert!(
                text.contains("远程会话 7 已关闭"),
                "隧道非正常结束时残留的会话被静默丢弃了，日志到「已\
                 开启」为止：{text}"
            );
            assert!(
                text.contains("111 字节") && text.contains("222 字节"),
                "残留会话的字节数没记全：{text}"
            );
        })
        .await;
    }

    // --- 第七条：公开的 Command::Start 必须做地址校验，且必须有测试
    // 钉住它做了。---

    /// 一旦被调用就 panic 的工厂——跟 Task 9 那条 Pass 测试证明"预检
    // 失败时 establish 一次都不会被调用"用的是同一个手法：如果
    /// `Command::Start` 的处理跳过了 `ValidatedAddresses::validate`、
    /// 直接拿裸 `HostPort` 拼 `Credentials` 去建连，这个工厂会被调用
    /// 到，测试当场 panic（红）。
    struct PanicsIfEstablishIsCalled;

    #[async_trait::async_trait]
    impl TunnelFactory for PanicsIfEstablishIsCalled {
        async fn establish(
            &self,
            _params: TunnelParams,
            _tx: mpsc::Sender<TunnelMsg>,
        ) -> crate::error::Result<Box<dyn TunnelHandle>> {
            panic!("地址校验应该在建立隧道之前就已经拒绝，establish 不该被调用");
        }
    }

    // 会让这条测试变红的实现改法：把 `Command::Start` 处理里的
    // `ValidatedAddresses::validate(gateway, appliance)` 删掉，直接用
    // 命令携带的裸 `gateway`/`appliance` 构造 `Credentials`——那样
    // 预检会照常通过（`AlwaysPassPreflight` 不检查地址），后台连接任务
    // 会调用 `PanicsIfEstablishIsCalled::establish`，测试 panic。
    #[tokio::test(start_paused = true)]
    async fn start_rejects_appliance_equal_to_gateway_before_touching_the_factory() {
        guard(async {
            let (tx, mut rx) = Supervisor::spawn(
                config(),
                deps(
                    Arc::new(PanicsIfEstablishIsCalled),
                    Arc::new(NoSystemEvents::default()),
                ),
            );
            let gw: HostPort = "gateway.company.com:443".parse().unwrap();
            tx.send(Command::Start {
                username: "tunnel-zhang".into(),
                password: Zeroizing::new("pw".into()),
                gateway: gw.clone(),
                appliance: gw,
            })
            .await
            .unwrap();

            let seen = states_until(&mut rx, |s| matches!(s, State::Failed { .. })).await;
            match seen.last().unwrap() {
                State::Failed { class, message } => {
                    assert_eq!(*class, ErrorClass::Fatal);
                    assert!(message.contains("一体机"), "{message}");
                }
                other => panic!("{other:?}"),
            }
            assert!(
                !seen
                    .iter()
                    .any(|s| matches!(s, State::Preflight | State::Connecting)),
                "校验失败不该走到预检或建连：{seen:?}"
            );
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn start_rejects_loopback_appliance_before_touching_the_factory() {
        guard(async {
            let (tx, mut rx) = Supervisor::spawn(
                config(),
                deps(
                    Arc::new(PanicsIfEstablishIsCalled),
                    Arc::new(NoSystemEvents::default()),
                ),
            );
            tx.send(Command::Start {
                username: "tunnel-zhang".into(),
                password: Zeroizing::new("pw".into()),
                gateway: "gateway.company.com:443".parse().unwrap(),
                appliance: "127.0.0.1:22".parse().unwrap(),
            })
            .await
            .unwrap();

            let seen = states_until(&mut rx, |s| matches!(s, State::Failed { .. })).await;
            match seen.last().unwrap() {
                State::Failed { class, .. } => assert_eq!(*class, ErrorClass::Fatal),
                other => panic!("{other:?}"),
            }
        })
        .await;
    }

    // --- R96（最终复审）：`Command::Start` 携带的 Gateway 地址必须
    // 真的参与拨号，不能只参与"校验 + 预检 + 审计日志"。---

    /// 记下每次 `run()` 被问到的 (gateway, appliance)，然后一律放行。
    ///
    /// 存在的理由：光断言"工厂收到的 gateway 等于 Start 传的那个"，
    /// 还漏掉这条问题的另一半——诊断页显示的是**预检**探到的结果。
    /// 必须同时钉住"预检探的那台"与"隧道实际连的那台"是同一台，
    /// 否则日后谁把 `run_connect_sequence` 里预检的入参换回一份独立
    /// 拷贝，诊断页又会开始稳定地描述一台不是实际连上的机器，而两条
    /// 各管一头的断言都照样绿。
    #[derive(Default)]
    struct RecordingPreflight(Mutex<Vec<(HostPort, HostPort)>>);

    #[async_trait::async_trait]
    impl Preflight for RecordingPreflight {
        async fn run(
            &self,
            gateway: &HostPort,
            appliance: &HostPort,
        ) -> preflight::PreflightReport {
            self.0
                .lock()
                .unwrap()
                .push((gateway.clone(), appliance.clone()));
            AlwaysPassPreflight.run(gateway, appliance).await
        }
    }

    // 方案 §3.8/§3.10：现场工程师可以把界面上的运维服务器地址改成客户
    // 现场那一台再点「开启」。这条测试就演这个场景——`Start` 携带的
    // Gateway 故意跟 `config()` 里那个（也就是 R96 之前
    // `SshTunnelFactory` 构造时会被固定下来的那一个）不一样。
    //
    // R96 之前这件事完全没人盯：把 `Credentials::params` 里取 gateway
    // 那一行（当时在 `spawn_connect` 里，写作
    // `let gateway = creds.addrs.gateway().clone();`）换成任何一个写死
    // 的错误地址，237 条测试 0 失败——`TunnelParams` 里根本没有这个
    // 字段，假工厂 `Scripted` 看不到它，`AlwaysPassPreflight` 忽略参数。
    //
    // 会让这条测试变红的实现改法（三处，各自单独试过）：
    //
    // 1. 把 `Credentials::params` 里的
    //    `gateway: self.addrs.gateway().clone()` 换成别的地址
    //    （比如 `ctx.cfg.gateway`）——第一条断言红。
    // 2. 把 `run_connect_sequence` 里的
    //    `preflight.run(&params.gateway, &params.appliance)` 换成探测
    //    另一个地址——第二条断言红。
    // 3. 给 `SshTunnelFactory` 加回构造期固定的 `gateway` 字段、让
    //    `establish()` 拨那一个——这条测试用的是假工厂，抓不到；那一
    //    层现在靠"字段整个不存在"在结构上保证，见 `ssh/mod.rs` 上
    //    `SshTunnelFactory` 的 R96 说明。
    #[tokio::test(start_paused = true)]
    async fn start_passes_the_commanded_gateway_all_the_way_to_the_factory() {
        guard(async {
            // 跟 `config().gateway`（gateway.company.com:443）不同的
            // 一台——"现场工程师把地址改成客户现场那一台"。
            let onsite: HostPort = "onsite-gw.customer.example:8443".parse().unwrap();
            let appliance: HostPort = "192.168.100.10:22".parse().unwrap();

            let (factory, calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: false,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
            ])]);
            let preflight = Arc::new(RecordingPreflight::default());
            let mut deps = deps(factory, Arc::new(NoSystemEvents::default()));
            deps.preflight = preflight.clone();

            let (tx, mut rx) = Supervisor::spawn(config(), deps);
            tx.send(Command::Start {
                username: "tunnel-zhang".into(),
                password: Zeroizing::new("pw".into()),
                gateway: onsite.clone(),
                appliance: appliance.clone(),
            })
            .await
            .unwrap();
            states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;

            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(
                calls[0].gateway, onsite,
                "隧道必须建到 Start 命令携带的那台 Gateway，而不是别处\
                 固定下来的某一台——host key 也是对着它比对的"
            );
            assert_eq!(calls[0].appliance, appliance);

            let probed = preflight.0.lock().unwrap();
            assert_eq!(probed.len(), 1);
            assert_eq!(
                probed[0].0, calls[0].gateway,
                "预检探测的 Gateway 必须就是隧道实际连上的那一台，否则\
                 诊断页会稳定地描述一台不是实际连上的机器"
            );
            assert_eq!(probed[0].1, calls[0].appliance);
        })
        .await;
    }

    // R62：地址校验失败必须清空凭据——不然改错地址之后点 RetryNow
    // （Failed 状态下允许）会拿旧地址旧口令重新连接。这里直接钉住
    // "校验失败之后凭据确实是 None"这件事本身，不通过端到端的
    // RetryNow 行为间接验证（间接验证还得再造一个不会 panic 的工厂，
    // 且没有直接指向"到底是不是 creds 的问题"）。
    //
    // 会让这条测试变红的实现改法：删掉 `Command::Start` 校验失败分支里
    // 新加的 `ctx.creds = None;`。
    #[tokio::test(start_paused = true)]
    async fn start_validation_failure_clears_stale_credentials() {
        guard(async {
            // 第一版这条测试有缺陷：只发过一次会校验失败的 `Start`，
            // `ctx.creds` 从一开始就是 `None`（唯一会把它设成 `Some`
            // 的分支是校验*通过*那条路），不管 R62 的
            // `ctx.creds = None;` 那一行在不在，这条测试都会通过——
            // 根本没有"陈旧凭据"可清。改正：先用一组合法地址真的把
            // `ctx.creds` 填上（借道一次会被判 Fatal 的握手失败，
            // Fatal 分支本来就不清凭据，为的是让 RetryNow 能用原地址
            // 重试——这不是 bug，是 R62 之外的另一条既有行为），状态
            // 停在 `Failed` 但凭据仍是"第一次"那一份；再发一条地址
            // 非法的 `Start`（校验失败），断言这一步把那份"陈旧"的
            // 凭据也清掉了——不然随后的 `RetryNow` 会悄悄拿着已经被
            // 界面否决的旧地址重新建连。
            let (factory, calls) = Scripted::new(vec![Outcome::Err(Error::HostKeyMismatch {
                expected: "SHA256:aaa".into(),
                actual: "SHA256:bbb".into(),
            })]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));

            tx.send(start()).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Failed { .. })).await;
            assert_eq!(calls.lock().unwrap().len(), 1);

            // 换一组非法地址（一体机等于 Gateway）——校验会失败，
            // `ctx.state` 停在 Failed 允许再发 Start，这条命令能被
            // 处理到。
            let gw: HostPort = "gateway.company.com:443".parse().unwrap();
            tx.send(Command::Start {
                username: "tunnel-zhang".into(),
                password: Zeroizing::new("pw".into()),
                gateway: gw.clone(),
                appliance: gw,
            })
            .await
            .unwrap();
            // 校验失败不产生新的 establish 调用，也不经过 Preflight/
            // Connecting，直接停在（新的）Failed。
            states_until(&mut rx, |s| matches!(s, State::Failed { .. })).await;
            assert_eq!(
                calls.lock().unwrap().len(),
                1,
                "校验失败不该触发任何建连尝试"
            );

            tx.send(Command::RetryNow).await.unwrap();
            // 给状态机一点虚拟时间处理这条命令。
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert_eq!(
                calls.lock().unwrap().len(),
                1,
                "地址校验失败之后 RetryNow 不该拿第一次的陈旧凭据去重新建连"
            );
        })
        .await;
    }

    // --- 第三条：port_busy_since 必须在非 PortBusy 错误时清零 ---

    fn test_ctx() -> Ctx {
        let (ev, _rx) = broadcast::channel(16);
        let cfg = config();
        let audit = Audit::open(cfg.log_dir.clone()).unwrap();
        Ctx {
            cfg,
            deps: deps(
                Arc::new(PanicsIfEstablishIsCalled),
                Arc::new(NoSystemEvents::default()),
            ),
            ev,
            state: State::Connected { degraded: false },
            creds: Some(Credentials {
                username: "tunnel-zhang".into(),
                password: Zeroizing::new("pw".into()),
                addrs: ValidatedAddresses::validate(
                    "gateway.company.com:443".parse().unwrap(),
                    "192.168.100.10:22".parse().unwrap(),
                )
                .unwrap(),
            }),
            handle: None,
            connect_task: None,
            sessions: BTreeMap::new(),
            backoff: Backoff::new(Box::new(FixedJitter(1.0))),
            port_busy_attempt: 0,
            port_busy_since: None,
            retry_at: None,
            audit,
        }
    }

    // 会让这条测试变红的实现改法：删掉 `schedule_retry` 顶部"非
    // PortBusy 就清空 port_busy_since/port_busy_attempt"这几行——那样
    // 第二次 `ForwardPortBusy` 会沿用第一次记下的 `since`，快进 5 分钟
    // 之后 `since.elapsed() >= PORT_BUSY_BUDGET` 立刻成立，状态变成
    // `Failed` 而不是 `Backoff`，`ctx.retry_at.is_some()` 断言失败。
    #[tokio::test(start_paused = true)]
    async fn port_busy_since_resets_when_a_different_error_class_intervenes() {
        guard(async {
            let mut ctx = test_ctx();

            // 第一次端口占用：记下 since，重试计数从 1 开始。
            schedule_retry(&mut ctx, Error::ForwardPortBusy(22001));
            assert!(ctx.port_busy_since.is_some());
            assert_eq!(ctx.port_busy_attempt, 1);

            // 换成网络错误：应清空端口占用的计时与计数。
            schedule_retry(&mut ctx, Error::Tcp("refused".into()));
            assert!(
                ctx.port_busy_since.is_none(),
                "非端口占用错误应清空 port_busy_since"
            );
            assert_eq!(ctx.port_busy_attempt, 0);

            // 时间快进 5 分钟——如果 since 没被清零、且用的是会被虚拟时钟
            // 骗过的 std::time::Instant，这里会直接判定预算耗尽、转 Failed。
            tokio::time::advance(Duration::from_secs(300)).await;

            // 全新的端口占用：预算应该从 0 重新计时，不应立刻 Failed。
            schedule_retry(&mut ctx, Error::ForwardPortBusy(22001));
            assert!(
                matches!(ctx.state, State::Backoff { .. }),
                "{:?}",
                ctx.state
            );
            assert!(ctx.retry_at.is_some(), "预算应该重新计时，不应该判定用完");
        })
        .await;
    }

    // --- 第四条：ApplianceUnreachable 不走网络类的指数退避 ---

    // 会让这条测试变红的实现改法：把 `schedule_retry` 里
    // `ErrorClass::ApplianceUnreachable` 的分支跟 `ErrorClass::Network`
    // 合并（`ErrorClass::Network | ErrorClass::ApplianceUnreachable =>
    // {...}`，brief 原文的写法）——`delay` 会变成
    // `ctx.backoff.next_delay()` 算出来的指数退避值（第一次是 1 秒，
    // 不等于 `APPLIANCE_PROBE` 的 30 秒），且 `ctx.backoff.attempt()`
    // 会被推进到 1，两条断言都会失败。
    #[tokio::test(start_paused = true)]
    async fn schedule_retry_routes_appliance_unreachable_to_a_fixed_probe_not_exponential_backoff()
    {
        guard(async {
            let mut ctx = test_ctx();
            schedule_retry(&mut ctx, Error::ApplianceUnreachable("refused".into()));
            assert!(ctx.retry_at.is_some());
            match &ctx.state {
                State::Backoff { delay, .. } => assert_eq!(*delay, APPLIANCE_PROBE),
                other => panic!("{other:?}"),
            }
            assert_eq!(ctx.backoff.attempt(), 0, "不该推进网络类的指数退避计数");
        })
        .await;
    }

    // --- 第五条：PortBusy 路径上 Backoff{attempt} 不该恒为 0 ---
    //
    // `port_busy_retries_every_five_seconds_then_fails_after_budget` 里已经
    // 有一条端到端的断言覆盖这一点；这条单独用 schedule_retry 直接调用，
    // 把"逐次递增"钉得更精确（1, 2, 3...），不依赖端到端时序。

    // 会让这条测试变红的实现改法：`schedule_retry` 的 `PortBusy` 分支不
    // 推进 `ctx.port_busy_attempt`，直接用 0 或 `ctx.backoff.attempt()`
    // （从不因为 PortBusy 调用 `next_delay`，恒为 0）填 `State::Backoff
    // { attempt, .. }`——第二次断言 `assert_eq!(*attempt, 2)` 会失败,
    // 实际会看到 1（或者一直是 0）。
    #[tokio::test(start_paused = true)]
    async fn port_busy_backoff_attempt_increments_across_retries() {
        guard(async {
            let mut ctx = test_ctx();
            for expected in 1..=3u32 {
                schedule_retry(&mut ctx, Error::ForwardPortBusy(22001));
                match &ctx.state {
                    State::Backoff { attempt, delay } => {
                        assert_eq!(
                            *attempt, expected,
                            "第 {expected} 次端口占用重试，界面不该一直显示同一个数"
                        );
                        assert_eq!(*delay, PORT_BUSY_RETRY);
                    }
                    other => panic!("{other:?}"),
                }
            }
        })
        .await;
    }

    // --- R65：认证失败必须清空凭据 ---
    //
    // 方案 §3.8 要求口令认证之后即清除；认证失败同样不该继续攥着这份
    // 口令。之前只有端到端的
    // `auth_failure_returns_to_idle_and_does_not_retry` 覆盖这条路径，
    // 但它只断言"不自动重试"，不重试的真正原因是 `schedule_retry` 的
    // `Auth` 分支把 `ctx.retry_at` 置为 `None`（压根不安排下一次尝试），
    // 跟 `ctx.creds` 是否被清空无关——就算 `ctx.creds = None;` 这一行
    // 被删掉，那条端到端测试也照样绿。这里直接检查字段本身。
    //
    // 会让这条测试变红的实现改法：删掉 `schedule_retry` 的 `Auth`
    // 分支里 `ctx.creds = None;` 这一行。
    #[tokio::test(start_paused = true)]
    async fn auth_rejected_clears_credentials_so_a_stale_password_cannot_be_reused() {
        guard(async {
            let mut ctx = test_ctx();
            assert!(ctx.creds.is_some());
            schedule_retry(&mut ctx, Error::AuthRejected);
            assert!(
                ctx.creds.is_none(),
                "认证失败后必须清空凭据，方案 §3.8 要求口令认证后即清除"
            );
        })
        .await;
    }

    // --- R66：预检失败必须直接进 Failed，不是 Backoff ---
    //
    // `AlwaysPassPreflight` 恒定 Pass，这条出口在其余所有测试里一次都
    // 没被走到过——如果 `run_connect_sequence`/`handle_connect_event`
    // 把 `ConnectEvent::PreflightFailed` 的处理错误地改成走
    // `schedule_retry`（安排一次 Backoff 重试），没有任何现有测试会
    // 变红。
    //
    // 会让这条测试变红的实现改法：把 `handle_connect_event` 里
    // `ConnectEvent::PreflightFailed { class, message } => { ...
    // ctx.set_state(State::Failed { class, message }); }` 改成调用
    // `schedule_retry(ctx, ...)` 或者直接 `ctx.set_state(State::Backoff
    // { .. })`。
    #[tokio::test(start_paused = true)]
    async fn preflight_failure_goes_straight_to_failed_not_backoff() {
        guard(async {
            let mut d = deps(
                Arc::new(PanicsIfEstablishIsCalled),
                Arc::new(NoSystemEvents::default()),
            );
            d.preflight = Arc::new(FailingPreflight);
            let (tx, mut rx) = Supervisor::spawn(config(), d);
            tx.send(start()).await.unwrap();

            let seen = states_until(&mut rx, |s| {
                matches!(s, State::Failed { .. } | State::Backoff { .. })
            })
            .await;
            match seen.last().unwrap() {
                State::Failed { class, .. } => assert_eq!(*class, ErrorClass::ApplianceUnreachable),
                other => panic!("预检失败应该直接进 Failed，不是 {other:?}"),
            }
        })
        .await;
    }

    // --- R74 第一条：连接任务 panic 之后状态机不会永久卡住 ---
    //
    // 在这条测试之前，`Preflight`/`TunnelFactory` 实现里的 bug 一旦
    // panic，`connect_task` 对应的 `JoinHandle` 从没被任何人观察过
    // （既不在 `connect_rx` 上，也不在别处），`ctx.connect_task` 会
    // 永远是 `Some`，状态机永久停在 panic 发生前的最后一步
    // （`Preflight` 或 `Connecting`），既不会自动重试，也不会报出
    // `Failed`，界面只能一直转圈。
    //
    // 会让这条测试变红的实现改法：把 `run_connect_sequence` 顶部的
    // `FailOnPanic` guard 删掉（或者把 `armed` 恒定初始化成
    // `false`）——panic 时不会再有任何 `ConnectEvent` 被送出，
    // `states_until` 等不到 `Failed`，300 秒的 `guard` 超时会先触发，
    // 测试失败但不是因为下面这条断言。
    #[tokio::test(start_paused = true)]
    async fn a_panicking_preflight_does_not_hang_the_state_machine_forever() {
        guard(async {
            struct PanickingPreflight;
            #[async_trait::async_trait]
            impl Preflight for PanickingPreflight {
                async fn run(
                    &self,
                    _gateway: &HostPort,
                    _appliance: &HostPort,
                ) -> preflight::PreflightReport {
                    panic!("PanickingPreflight：模拟 Preflight 实现里的 bug");
                }
            }
            let mut d = deps(
                Arc::new(PanicsIfEstablishIsCalled),
                Arc::new(NoSystemEvents::default()),
            );
            d.preflight = Arc::new(PanickingPreflight);
            let (tx, mut rx) = Supervisor::spawn(config(), d);
            tx.send(start()).await.unwrap();

            // panic 发生在一个独立的 tokio 任务里，会被 tokio 自己的
            // panic 捕获机制接住（不会打掉整个测试进程），但会往 stderr
            // 打一条 panic 消息——这是预期之内的噪音，不代表测试本身
            // 出了问题。
            //
            // `FailOnPanic` 兜底送出的是 `Error::SshTransport(..)`，
            // 分类是 `Network`——一次内部错误默认按"可能是偶发的、值得
            // 重试"处理，跟这个 crate 别处"不确定就归 Network，安全
            // 默认是退避重连"的一贯取舍一致（见 `error.rs` 上
            // `Error::Io` 的说明）；不是 `Failed`，是 `Backoff`。这里
            // 只关心"状态机真的往前走了、没有卡死在 Preflight"，不深究
            // 具体分类是否是产品最优选择——如果 `PanickingPreflight`
            // 每次都 panic，状态机会按退避序列不断重试、不断再 panic、
            // 再退避，这是预期内的行为，不是这条测试要钉住的点。
            let seen = states_until(&mut rx, |s| matches!(s, State::Backoff { .. })).await;
            assert!(
                seen.iter().any(|s| matches!(s, State::Preflight)),
                "应该先进过 Preflight 才 panic：{seen:?}"
            );
        })
        .await;
    }

    // --- R67：ConnectedSince / HostKey 事件确实会被广播 ---
    //
    // 生产代码里这两处 `ctx.ev.send(...)` 调用此前没有任何测试直接
    // 断言过——之前的测试都只订阅 `TunnelEvent::State`，`HostKey`/
    // `ConnectedSince` 两种事件即使被送出，也从来没人检查过内容或者
    // "有没有被送出"这件事本身。
    //
    // 会让这条测试变红的实现改法：删掉 `handle_connect_event` 里
    // `Established` 分支的 `ctx.ev.send(TunnelEvent::ConnectedSince(...))`
    // 那一行，或者删掉 `handle_msg` 里 `Authenticated` 分支的
    // `ctx.ev.send(TunnelEvent::HostKey { .. })` 那一行。
    #[tokio::test(start_paused = true)]
    async fn established_session_reports_connected_since_and_host_key_events() {
        guard(async {
            let (factory, _calls) = Scripted::new(vec![Outcome::Ok(vec![
                TunnelMsg::Authenticated {
                    host_key_fp: "SHA256:aaa".into(),
                    first_seen: true,
                },
                TunnelMsg::ForwardRegistered { port: 22001 },
            ])]);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();

            let mut saw_host_key = false;
            let mut saw_connected_since = false;
            let deadline = Instant::now() + Duration::from_secs(60);
            while Instant::now() < deadline && !(saw_host_key && saw_connected_since) {
                match rx.recv().await {
                    Ok(TunnelEvent::HostKey {
                        fingerprint,
                        first_seen,
                    }) => {
                        assert_eq!(fingerprint, "SHA256:aaa");
                        assert!(first_seen);
                        saw_host_key = true;
                    }
                    Ok(TunnelEvent::ConnectedSince(_)) => saw_connected_since = true,
                    Ok(_) => {}
                    Err(e) => panic!("事件通道异常：{e}"),
                }
            }
            assert!(
                saw_host_key,
                "Authenticated 消息应该转成 HostKey 事件广播出去"
            );
            assert!(saw_connected_since, "连接成功应该广播 ConnectedSince");
        })
        .await;
    }

    // --- R64：Stop 必须真的关掉 SSH 会话，不能只是"忘掉"它 ---
    //
    // `teardown()` 目前确实调用了 `h.shutdown().await`，但在这条测试
    // 之前没有任何测试验证过这一点——把 `teardown()` 改成只
    // `self.handle.take()`、不调用 `.shutdown()`，之前的 19 条测试会
    // 继续全绿（它们都只观察状态变迁，不关心 `TunnelHandle` 有没有被
    // 真的关掉）。不真的关掉会话，Gateway 侧的反向端口监听不会被回收，
    // 正是方案 §3.6"端口占用"那条故障的成因。
    //
    // 会让这条测试变红的实现改法：把 `Ctx::teardown` 里
    // `h.shutdown().await;` 删掉，只留 `self.handle.take();`。
    #[tokio::test(start_paused = true)]
    async fn stop_actually_shuts_down_the_ssh_session_not_just_forgets_it() {
        guard(async {
            struct TrackedHandle(Arc<std::sync::atomic::AtomicBool>);
            #[async_trait::async_trait]
            impl TunnelHandle for TrackedHandle {
                async fn close_remote_session(
                    &self,
                    _id: u64,
                ) -> std::result::Result<(), crate::tunnel::UnknownSessionId> {
                    Ok(())
                }
                async fn shutdown(self: Box<Self>) {
                    self.0.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
            struct TracksShutdown(Arc<std::sync::atomic::AtomicBool>);
            #[async_trait::async_trait]
            impl TunnelFactory for TracksShutdown {
                async fn establish(
                    &self,
                    _params: TunnelParams,
                    tx: mpsc::Sender<TunnelMsg>,
                ) -> crate::error::Result<Box<dyn TunnelHandle>> {
                    tokio::spawn(async move {
                        let _ = tx
                            .send(TunnelMsg::Authenticated {
                                host_key_fp: "SHA256:aaa".into(),
                                first_seen: false,
                            })
                            .await;
                        let _ = tx.send(TunnelMsg::ForwardRegistered { port: 22001 }).await;
                    });
                    Ok(Box::new(TrackedHandle(self.0.clone())))
                }
            }

            let shutdown_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let factory = Arc::new(TracksShutdown(shutdown_called.clone()));
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;
            assert!(
                !shutdown_called.load(std::sync::atomic::Ordering::SeqCst),
                "隧道还没停止就已经 shutdown"
            );

            tx.send(Command::Stop).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Idle)).await;
            assert!(
                shutdown_called.load(std::sync::atomic::Ordering::SeqCst),
                "Stop 之后必须真的关掉 SSH 会话，不能只是 take() 忘掉它——\
                 否则 Gateway 侧会留下僵尸监听"
            );
        })
        .await;
    }

    // --- R61：迟到的 Disconnected 不能污染一次更新的尝试 ---
    //
    // 场景：Stop 之后，旧隧道的 watcher（真实实现里是
    // `ssh::spawn_disconnect_watcher`，200ms 轮询一次）还没来得及发现
    // 会话已经关闭；用户几乎立刻又发起一次新的 Start，新隧道建立成功；
    // 这时旧 watcher 才终于发现旧会话已经死了，往它手里那份旧的
    // `msg_tx` 送一条 `Disconnected`。这条消息不该有机会拆掉刚建好的
    // 新隧道。
    //
    // 直接验证机制本身：`spawn_connect` 每次都建一对全新的
    // `msg_tx`/`msg_rx`，所以"旧" `tx` 对应的接收端在 Stop 之后、新的
    // `Start` 触发 `spawn_connect` 时就已经被换掉、丢弃——旧 `tx` 再
    // `.send()` 必然返回 `Err`（对应的接收端不存在了），这条消息物理
    // 上不可能被新会话的主循环看到，不需要会话代号/世代号这类额外
    // 状态去分辨"这条消息是不是当前这一次尝试的"。
    //
    // 会让这条测试变红的实现改法：把 `spawn_connect` 改成复用调用方
    // 传入的旧 `msg_tx`/`msg_rx`（而不是每次新建一对）——那样
    // `stale_tx.send(...)` 会成功投递到新会话正在用的同一个
    // `msg_rx`，`handle_msg` 的 `Disconnected` 分支会把刚建好的新隧道
    // 也拆掉。
    #[tokio::test(start_paused = true)]
    async fn stale_disconnected_from_a_torn_down_session_cannot_affect_a_newer_one() {
        guard(async {
            // 工厂只返回句柄，把 establish() 收到的 tx 存起来，供测试
            // 稍后手动模拟"迟到的 Disconnected"。
            struct CapturesTx(Mutex<Vec<mpsc::Sender<TunnelMsg>>>);
            #[async_trait::async_trait]
            impl TunnelFactory for CapturesTx {
                async fn establish(
                    &self,
                    _params: TunnelParams,
                    tx: mpsc::Sender<TunnelMsg>,
                ) -> crate::error::Result<Box<dyn TunnelHandle>> {
                    self.0.lock().unwrap().push(tx.clone());
                    tokio::spawn(async move {
                        let _ = tx
                            .send(TunnelMsg::Authenticated {
                                host_key_fp: "SHA256:aaa".into(),
                                first_seen: false,
                            })
                            .await;
                        let _ = tx.send(TunnelMsg::ForwardRegistered { port: 22001 }).await;
                    });
                    Ok(Box::new(FakeHandle))
                }
            }

            let captured = Arc::new(CapturesTx(Mutex::new(Vec::new())));
            let (tx, mut rx) = Supervisor::spawn(
                config(),
                deps(captured.clone(), Arc::new(NoSystemEvents::default())),
            );
            tx.send(start()).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;

            // 拿到第一条隧道用过的 tx——模拟它的 watcher 稍后才发现断线。
            let stale_tx = captured.0.lock().unwrap()[0].clone();

            tx.send(Command::Stop).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Idle)).await;

            tx.send(start()).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;

            // 迟到的 Disconnected：这条 send 必须失败——旧隧道的接收端
            // 已经在新一次 Start 触发的 spawn_connect 里被换掉、丢弃。
            let send_result = stale_tx
                .send(TunnelMsg::Disconnected {
                    reason: "迟到的断线".into(),
                })
                .await;
            assert!(
                send_result.is_err(),
                "旧隧道的 msg_tx 应该已经失效（接收端已被换成新隧道的）"
            );

            // 双重保险：就算侥幸没失败，也确认新隧道没有被牵连——排空
            // 一段虚拟时间内的所有事件，不该出现 Backoff/Idle。
            tokio::time::sleep(Duration::from_secs(1)).await;
            while let Ok(TunnelEvent::State(s)) = rx.try_recv() {
                assert!(
                    !matches!(s, State::Backoff { .. } | State::Idle),
                    "迟到的 Disconnected 不该影响新隧道：{s:?}"
                );
            }
        })
        .await;
    }

    // --- R60：Cancel/RetryNow/DisconnectRemoteSession 各自的专属测试 ---

    /// 见 R58：Preflight 现在跑在可以被 abort 的后台任务里，`Cancel`
    /// 应该几乎立刻生效，不用等预检跑完。用一个故意卡 60 秒的假预检
    /// 证明这一点——旧实现会让这条测试的 `elapsed` 断言失败（需要等满
    /// 60 秒），新实现应该在几毫秒内看到 `Idle`。
    ///
    /// 会让这条测试变红的实现改法：回到"预检 + 建隧道整段内联 `.await`
    /// 在处理 `Command::Start` 的分支里"的旧写法——`Cancel` 会被排在
    /// `cmd_rx.recv()` 的下一次调用上，只有等 60 秒的假预检跑完才能被
    /// 看到。
    #[tokio::test(start_paused = true)]
    async fn cancel_during_preflight_takes_effect_immediately_not_after_the_whole_sequence() {
        guard(async {
            // `reached_end` 用来区分"真的被 abort 掉"和"只是被主循环
            // 忘掉、后台任务其实还在裸跑"——如果只是 `Ctx::teardown`
            // 把 `JoinHandle` 丢掉但不调用 `.abort()`，主循环一样能立刻
            // 转回 `Idle`（它不等待这个任务完成），下面前两条断言会
            // 照样通过，测不出区别；只有真的把这段 60 秒 sleep 之后的
            // 代码跑到、把 `reached_end` 置位，才说明任务没有被真正
            // 取消。
            let reached_end = Arc::new(std::sync::atomic::AtomicBool::new(false));

            struct SlowPreflight(Arc<std::sync::atomic::AtomicBool>);
            #[async_trait::async_trait]
            impl Preflight for SlowPreflight {
                async fn run(
                    &self,
                    _gateway: &HostPort,
                    _appliance: &HostPort,
                ) -> preflight::PreflightReport {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    self.0.store(true, std::sync::atomic::Ordering::SeqCst);
                    preflight::PreflightReport { steps: vec![] }
                }
            }
            let mut d = deps(
                Arc::new(PanicsIfEstablishIsCalled),
                Arc::new(NoSystemEvents::default()),
            );
            d.preflight = Arc::new(SlowPreflight(reached_end.clone()));
            let (tx, mut rx) = Supervisor::spawn(config(), d);
            tx.send(start()).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Preflight)).await;

            let t0 = Instant::now();
            tx.send(Command::Cancel).await.unwrap();
            let seen = states_until(&mut rx, |s| matches!(s, State::Idle)).await;
            let elapsed = Instant::now().duration_since(t0);
            assert!(
                elapsed < Duration::from_secs(5),
                "Cancel 应该几乎立刻生效，不该等预检跑完（60 秒），实际 {elapsed:?}"
            );
            assert!(
                !seen
                    .iter()
                    .any(|s| matches!(s, State::Connecting | State::Connected { .. })),
                "取消预检不该走到建连：{seen:?}"
            );

            // 再放虚拟时钟走 65 秒——如果后台任务只是被"忘掉"而不是真的
            // `abort()`，这段 sleep 会在这段时间内跑完，`reached_end`
            // 会被置位。
            tokio::time::sleep(Duration::from_secs(65)).await;
            assert!(
                !reached_end.load(std::sync::atomic::Ordering::SeqCst),
                "Cancel 必须真的 abort 掉后台的预检任务，不能只是让主循环\
                 不再等它——否则一个取消了的预检仍会在后台裸跑到底"
            );
        })
        .await;
    }

    // 会让这条测试变红的实现改法：`Command::RetryNow` 处理里不清
    // `retry_at`、继续沿用旧的 `sleep_until` 定时器（那样即使发起了新
    // 的连接尝试，旧定时器到期时还会再发一次多余的尝试）；或者
    // `RetryNow` 压根不发起新的连接尝试，只是被动等旧定时器到期。
    #[tokio::test(start_paused = true)]
    async fn retry_now_skips_the_remaining_backoff_wait() {
        guard(async {
            let outcomes = vec![
                Outcome::Err(Error::Tcp("refused".into())),
                Outcome::Ok(vec![
                    TunnelMsg::Authenticated {
                        host_key_fp: "SHA256:aaa".into(),
                        first_seen: false,
                    },
                    TunnelMsg::ForwardRegistered { port: 22001 },
                ]),
            ];
            let (factory, calls) = Scripted::new(outcomes);
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Backoff { .. })).await;
            assert_eq!(calls.lock().unwrap().len(), 1);

            let t0 = Instant::now();
            tx.send(Command::RetryNow).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;
            let elapsed = Instant::now().duration_since(t0);
            assert!(
                elapsed < Duration::from_secs(1),
                "RetryNow 应该立刻重试，不用等满 1 秒的退避，实际 {elapsed:?}"
            );
            assert_eq!(calls.lock().unwrap().len(), 2);
        })
        .await;
    }

    // 会让这条测试变红的实现改法：`Command::DisconnectRemoteSession`
    // 处理里不调用 `ctx.handle.close_remote_session(id)`，或者把 `id`
    // 传错。
    #[tokio::test(start_paused = true)]
    async fn disconnect_remote_session_calls_close_remote_session_on_the_handle() {
        guard(async {
            struct TrackingHandle(mpsc::Sender<u64>);
            #[async_trait::async_trait]
            impl TunnelHandle for TrackingHandle {
                async fn close_remote_session(
                    &self,
                    id: u64,
                ) -> std::result::Result<(), crate::tunnel::UnknownSessionId> {
                    let _ = self.0.send(id).await;
                    Ok(())
                }
                async fn shutdown(self: Box<Self>) {}
            }
            struct ReturnsTrackingHandle(mpsc::Sender<u64>);
            #[async_trait::async_trait]
            impl TunnelFactory for ReturnsTrackingHandle {
                async fn establish(
                    &self,
                    _params: TunnelParams,
                    tx: mpsc::Sender<TunnelMsg>,
                ) -> crate::error::Result<Box<dyn TunnelHandle>> {
                    tokio::spawn(async move {
                        let _ = tx
                            .send(TunnelMsg::Authenticated {
                                host_key_fp: "SHA256:aaa".into(),
                                first_seen: false,
                            })
                            .await;
                        let _ = tx.send(TunnelMsg::ForwardRegistered { port: 22001 }).await;
                    });
                    Ok(Box::new(TrackingHandle(self.0.clone())))
                }
            }

            let (closed_tx, mut closed_rx) = mpsc::channel(4);
            let factory = Arc::new(ReturnsTrackingHandle(closed_tx));
            let (tx, mut rx) =
                Supervisor::spawn(config(), deps(factory, Arc::new(NoSystemEvents::default())));
            tx.send(start()).await.unwrap();
            states_until(&mut rx, |s| matches!(s, State::Connected { .. })).await;

            tx.send(Command::DisconnectRemoteSession { id: 42 })
                .await
                .unwrap();
            let closed = closed_rx
                .recv()
                .await
                .expect("应该调用了 close_remote_session");
            assert_eq!(closed, 42);
        })
        .await;
    }

    // --- 第十条：keepalive 断线判定耗时的端到端实测 ---
    //
    // 不使用 Scripted 假隧道——这里要测的是"真实的 ssh::establish_over
    // 建立的隧道，在服务端不再应答之后，状态机需要多久才能感知并转入
    // State::Backoff"，脚本化假隧道压根不会经过 russh 的 keepalive
    // 定时器，测不出这个数。用 Task 7 的进程内 russh 服务端夹具
    // （`ssh::test_support::spawn_freezable_gateway`）造"服务端不再
    // 应答"的场景——冻结后连接既不报错也不产生任何字节，模拟网络黑洞，
    // 不需要 docker，也不需要真实网络。
    //
    // 实测结果与测量条件见 task-10-report.md 与 docs/方案设计.md §3.4。

    struct FreezeAfterEstablish {
        state: Mutex<
            Option<(
                crate::ssh::test_support::FreezeSwitch,
                crate::ssh::test_support::ReadTimestamps,
            )>,
        >,
    }

    #[async_trait::async_trait]
    impl TunnelFactory for FreezeAfterEstablish {
        async fn establish(
            &self,
            params: TunnelParams,
            tx: mpsc::Sender<TunnelMsg>,
        ) -> crate::error::Result<Box<dyn TunnelHandle>> {
            use crate::ssh::test_support::{
                spawn_freezable_gateway, tmp_known_hosts, GatewayConfig,
            };
            let (reads, switch, pending, conn) = spawn_freezable_gateway(GatewayConfig {
                permitted_port: params.reverse_port as u32,
                accept_password: true,
            });
            let known_hosts = Arc::new(tmp_known_hosts());
            let handle = crate::ssh::establish_over(conn, &known_hosts, params, tx).await?;
            *self.state.lock().unwrap() = Some((switch, reads));
            // 不需要驱动服务端 handle 做任何事，这条测试只关心客户端一侧
            // 的行为；丢弃它不影响后台的 `run_stream` 任务继续运行。
            drop(pending);
            Ok(handle)
        }
    }

    // 会让这条断言变红的实现改法：删掉 `ssh::mod::spawn_disconnect_watcher`
    // 对 `establish_over` 的接线（那样连接冻结之后永远不会有
    // `TunnelMsg::Disconnected` 送出，`states_until` 等不到
    // `State::Backoff`，300 秒的 `guard` 超时会先触发，测试失败但不是
    // 因为这条时间断言）；或者把 `ssh::client_config()` 里的
    // `keepalive_interval`/`keepalive_max` 改掉——耗时会明显偏离
    // 39～41 秒这个窗口。
    #[tokio::test(start_paused = true)]
    async fn keepalive_disconnect_is_measured_end_to_end_from_a_real_ssh_session() {
        guard(async {
            use crate::ssh::test_support::{TEST_PASSWORD, TEST_USER};

            let factory = Arc::new(FreezeAfterEstablish {
                state: Mutex::new(None),
            });
            let (tx, mut rx) = Supervisor::spawn(
                config(),
                deps(factory.clone(), Arc::new(NoSystemEvents::default())),
            );
            tx.send(Command::Start {
                username: TEST_USER.into(),
                password: Zeroizing::new(TEST_PASSWORD.into()),
                gateway: "gateway.company.com:443".parse().unwrap(),
                appliance: "192.168.100.10:61001".parse().unwrap(),
            })
            .await
            .unwrap();

            states_until(&mut rx, |s| {
                matches!(s, State::Connected { degraded: false })
            })
            .await;

            let (switch, reads) = factory
                .state
                .lock()
                .unwrap()
                .take()
                .expect("establish 应该已经记录冻结开关");
            // 掐表：从这一刻起，服务端不再应答任何字节（既不报错也不
            // 回复，模拟网络黑洞），直到状态机真的判定断线。
            switch.freeze();
            let t0 = reads
                .snapshot()
                .into_iter()
                .max()
                .expect("握手/认证/端口注册期间服务端应至少读到过字节");

            let seen = states_until(&mut rx, |s| matches!(s, State::Backoff { .. })).await;
            let elapsed = Instant::now().duration_since(t0);

            eprintln!(
                "[Task 10 实测] keepalive 断线判定（连接冻结到 State::Backoff）\
                 耗时：{elapsed:?}（{}ms）",
                elapsed.as_millis()
            );

            // 10 秒一次 keepalive、keepalive_max = 3：russh 客户端在
            // `alive_timeouts > keepalive_max` 时判定超时，也就是第 4 次
            // 未获应答的 keepalive（t = 4×10 = 40 秒），不是
            // 10×3 = 30 秒这个未经实测的乘法——这正是方案设计.md §3.4
            // 明确要求必须实测、不能直接推定的地方。窗口留了 ±1 秒，
            // 覆盖 watcher 200ms 轮询与调度带来的极小滞后。
            assert!(
                elapsed >= Duration::from_secs(39) && elapsed <= Duration::from_secs(41),
                "keepalive 断线判定耗时应接近实测的 40 秒，实际 {elapsed:?}；\
                 状态序列：{seen:?}"
            );
        })
        .await;
    }

    // --- R91：审计日志里的状态描述是人话，不是 Rust 结构体 Debug
    // 语法。---
    //
    // 会让这条测试变红的实现改法：把 `describe_state` 里任何一个分支
    // 换回 `format!("{s:?}")`——`Backoff`/`Failed` 两个带字段的变体会
    // 立刻在输出里带上 `{`。
    #[test]
    fn describe_state_produces_prose_not_rust_debug_syntax() {
        assert_eq!(
            describe_state(&State::Connected { degraded: false }),
            "已连接"
        );
        assert!(!describe_state(&State::Connected { degraded: false }).contains('{'));
        assert!(!describe_state(&State::Backoff {
            attempt: 1,
            delay: Duration::from_secs(5)
        })
        .contains('{'));
        assert!(!describe_state(&State::Failed {
            class: ErrorClass::Auth,
            message: "账号或口令不正确".into()
        })
        .contains('{'));
    }
}
