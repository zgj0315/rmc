//! 诊断页的数据整理与**诊断包导出**。
//!
//! 本文件里没有一个 `iced::Element`：跟 `theme`/`model` 一样，它是诊断页
//! 的全部判断，视图只负责把结果摆进控件（见 crate 根的模块文档）。
//!
//! # 这个文件里最要紧的一件事：诊断包是唯一会离开这台机器的产物
//!
//! 维护页上敲进去的口令、DPAPI 里存着的口令、协商出来的 token，它们全都
//! 只在这台笔记本上打转。**只有诊断包会被工程师复制出去、发给远程同事、
//! 走邮件与聊天工具。** 所以[`bundle`] 是这个产品的安全面上最薄的一层，
//! 而「包里不含凭据」这件事**没有任何编译器或闸门会帮忙**——只有
//! [`tests::no_entry_in_the_bundle_carries_the_canary_password_or_account`]
//! 那一条测试守着。
//!
//! W36 当初把 `next_token` 的返回改成 `Zeroizing<String>`，给出的全部
//! 理由就是「真正让它值得堵的是 Task 9 要做诊断包导出」。那个任务就是
//! 这一个。
//!
//! # W160（落实 W43）：这一页不许自己去查代理
//!
//! [`rows`] 收的是一个**已经取好的** [`ProxyStatus`]，不是一个能去查的
//! 句柄。诊断页**不得调用 `Transport::effective_proxy`**：那个方法会在
//! 协商途中改写 `ProxyEndpointRecorder`，而**没有任何测试会因此变红**。
//! 界面每重画一帧就查一次的话，正在进行的代理认证会被悄悄搅乱。
//!
//! 这条不只是文档：`tests` 里的
//! `this_crate_never_polls_the_transport_for_the_current_proxy` 扫 rmc-app
//! 的整份源码守它，Task 10 接线时踩上去会当场红。

use rmc_core::preflight::{
    PreflightReport, StepOutcome, ALL_STEPS, STEP_APPLIANCE_HOSTKEY, STEP_APPLIANCE_TCP,
    STEP_GATEWAY_REACH, STEP_GATEWAY_TLS,
};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub use rmc_core::diagnostic::{ConnectOutcome, ProxyAuthSummary, Verdict, PROXY_AUTH_ROW};

/// 诊断页上「系统代理」那一行的行首文字。
pub const PROXY_ENDPOINT_ROW: &str = "系统代理";

/// 诊断页上「代理 CONNECT」那一行的行首文字。
pub const PROXY_CONNECT_ROW: &str = "代理 CONNECT";

/// 诊断页上运维服务器 host key 那一行的行首文字。
///
/// **不要用 `name.contains("host key")` 去找它**：预检的第二步叫
/// 「一体机 host key 指纹」，也含这三个字，而且排在前面。写测试时踩过
/// 一次，留这个常量就是为了别再踩第二次。
pub const HOST_KEY_ROW: &str = "运维服务器 host key";

/// 诊断页上的一行。
///
/// **没有 `highlight: bool` 字段**（brief 原稿有）：那个字段跟 `verdict`
/// 说的是同一件事，而构造它的地方少写一个取反就会让两者不一致，没有任何
/// 东西看得出来。标红与否由 [`Verdict::highlight`] 算出来，只有一个真相
/// 来源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagRow {
    /// 行首文字。预检那几行直接是 [`ALL_STEPS`] 里的名字。
    pub name: String,
    pub verdict: Verdict,
    /// 行尾的说明。
    pub detail: String,
}

impl DiagRow {
    /// 这一行要不要标红。
    pub fn highlight(&self) -> bool {
        self.verdict.highlight()
    }
}

/// 现场**已经查到**的系统代理情况。
///
/// # W159：为什么不是 `proxy: Option<&str>` + 一个元组
///
/// brief 原稿收的是 `proxy: Option<&str>` 与
/// `host_key: Option<&(String, bool)>`。后者是元组套 `Option`，读的人无从
/// 知道那个 `bool` 是什么意思——这是本项目同一个缺陷类的第五次
/// （`resolve()`、`next_token()`、`load()`、`validate()` 是前四次，四次
/// 的解法都是**带类型的出口**）。
///
/// 而前者只带一个地址，说不出「CONNECT 成没成」与「代理认证谈成什么样」，
/// 那恰好是 W38 要求的那张表的两根轴。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyStatus {
    /// 代理地址，形如 `proxy.company.com:8080`。
    ///
    /// **由调用方取好之后交进来**，见模块文档 W160 一节。
    pub endpoint: String,
    /// 经这个代理的那次 HTTP CONNECT 成没成。
    pub connect: ConnectOutcome,
    /// 代理认证协商的结局（平台中立，见 `rmc_core::diagnostic`）。
    pub auth: ProxyAuthSummary,
}

impl ProxyStatus {
    /// 从 rmc-core 送上来的那份观察结果转过来。
    ///
    /// `None` 表示**这次是直连**，诊断页于是一行代理信息都不画——这正是
    /// [`ProxyObservation`](rmc_core::diagnostic::ProxyObservation) 分成
    /// 两个变体的理由：直连时根本没有「CONNECT 成没成」这回事，压成一对
    /// 字段就得给它编一个值，而界面会照样把编出来的值画上屏。
    pub fn observed(o: &rmc_core::diagnostic::ProxyObservation) -> Option<Self> {
        use rmc_core::diagnostic::ProxyObservation;
        match o {
            ProxyObservation::Direct => None,
            ProxyObservation::Via {
                endpoint,
                connect,
                auth,
            } => Some(Self {
                endpoint: endpoint.to_string(),
                connect: *connect,
                auth: auth.clone(),
            }),
        }
    }
}

/// 运维服务器 host key 的比对结果。
///
/// W159：这是 brief 那个 `(String, bool)` 的带类型版本。`bool` 是
/// 「是不是第一次见到」——写成两个变体之后，读的人不必再去别处查。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyRecord {
    /// 本机第一次见到这个指纹，已经记下来了。
    FirstSeen { fingerprint: String },
    /// 与本机已有记录一致。
    Matches { fingerprint: String },
}

impl HostKeyRecord {
    /// 从 [`crate::model::Model::host_key`] 那个 `(指纹, 是否首次)` 转过来。
    ///
    /// 这个适配器存在的唯一理由是 `Model` 的字段形状是 Task 7 定的、
    /// 由 `TunnelEvent::HostKey` 直接喂进去；换掉它要动 rmc-core 的事件
    /// 定义，不在本任务范围内。**判断（那个 `bool` 是什么意思）关在这里，
    /// 视图里只剩一次 `map`。**
    pub fn from_model(v: &(String, bool)) -> Self {
        let (fingerprint, first_seen) = v;
        if *first_seen {
            Self::FirstSeen {
                fingerprint: fingerprint.clone(),
            }
        } else {
            Self::Matches {
                fingerprint: fingerprint.clone(),
            }
        }
    }

    pub fn fingerprint(&self) -> &str {
        match self {
            Self::FirstSeen { fingerprint } | Self::Matches { fingerprint } => fingerprint,
        }
    }
}

/// 处置建议卡上的字。
///
/// W159：brief 原稿是 `(String, String)`，**两个裸 String 的元组说不出
/// 哪个是标题、哪个是建议**——写反了界面照样画得出来，只是标题栏上写着
/// 一整段处置步骤。具名字段之后写反就编译不过。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdviceCard {
    /// 卡片的标题：**是哪一步失败了**。
    pub failed_step: String,
    /// 卡片的正文：现场该怎么办。
    pub body: String,
}

/// 处置建议。
///
/// W159：brief 原稿是 `Option<(String, String)>`，而那个 `Option` 把
/// **两件完全不同的事**压成了同一个 `None`：
///
/// - 预检里根本没有失败项（一切正常，不该画这张卡）；
/// - 有失败项，但我们不认得它是哪一类（该画卡，而且内容就是「把诊断包
///   带走给远程工程师」——这恰恰是诊断包存在的理由）。
///
/// 压平的后果是「认不出的失败」会被当成「没有失败」，整张卡不画，现场
/// 工程师对着一屏红字得不到任何下一步。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advice {
    /// 预检里没有失败项（或者还没跑过预检）。不画这张卡。
    NoFailure,
    /// 认得出是哪一类失败，给出针对性的处置建议。
    Known(AdviceCard),
    /// 有失败项，但不认得是哪一类。仍然要画卡，内容是把包带走。
    Unrecognized(AdviceCard),
}

impl Advice {
    /// 要画的卡片内容；[`Advice::NoFailure`] 时没有卡。
    ///
    /// 视图调这一个方法就够了，三个变体的区别由本模块的测试守着——不是
    /// 把 `Option` 又还回去：`Unrecognized` 在这里是 `Some`，而在 brief
    /// 的 `Option<(String, String)>` 里它跟 `NoFailure` 一样是 `None`。
    pub fn card(&self) -> Option<&AdviceCard> {
        match self {
            Self::NoFailure => None,
            Self::Known(c) | Self::Unrecognized(c) => Some(c),
        }
    }
}

/// 诊断页要画的全部行。
///
/// # 没跑过预检时按 [`ALL_STEPS`] 排版（W161，落实 W137）
///
/// `report` 是 `None` 时这里照 [`ALL_STEPS`] 的**声明顺序**列出四行
/// 「还没有检查过」；跑过之后画的是 `report.steps` 的顺序。`preflight.rs`
/// 的 `steps!` 宏文档承诺这两个顺序相同，而在 Task 9 之前**没有任何东西
/// 守这条承诺**——打乱声明顺序，六道闸门全绿。现在它有了真实后果（四行
/// 会在重新检查前后自己跳位置），也有了两条测试：本模块的
/// [`tests::the_unchecked_page_lists_every_step_in_declaration_order`]，
/// 以及 rmc-core 里 `run()` 那一端的
/// `appliance_tcp_and_hostkey_steps_pass_over_a_real_tcp_socket`。
///
/// # W160（落实 W43）：`proxy` 是收进来的，不是查出来的
///
/// 见模块文档。这一页**不得**调用 `Transport::effective_proxy`。
pub fn rows(
    report: Option<&PreflightReport>,
    proxy: Option<&ProxyStatus>,
    host_key: Option<&HostKeyRecord>,
) -> Vec<DiagRow> {
    let mut out: Vec<DiagRow> = match report {
        Some(r) => r
            .steps
            .iter()
            .map(|s| {
                let (verdict, detail) = match &s.outcome {
                    StepOutcome::Pass { detail } => (Verdict::Pass, detail.clone()),
                    StepOutcome::Fail { detail, .. } => (Verdict::Fail, detail.clone()),
                    StepOutcome::Skipped { detail } => (Verdict::Undecided, detail.clone()),
                };
                DiagRow {
                    name: s.name.to_string(),
                    verdict,
                    detail,
                }
            })
            .collect(),
        None => ALL_STEPS
            .iter()
            .map(|name| DiagRow {
                name: (*name).to_string(),
                verdict: Verdict::Undecided,
                detail: "还没有检查过".to_string(),
            })
            .collect(),
    };

    if let Some(p) = proxy {
        out.push(DiagRow {
            name: PROXY_ENDPOINT_ROW.to_string(),
            verdict: Verdict::Pass,
            detail: p.endpoint.clone(),
        });
        let (verdict, detail) = match p.connect {
            ConnectOutcome::Established => (Verdict::Pass, "已建立"),
            ConnectOutcome::Failed => (Verdict::Fail, "没有建立"),
        };
        out.push(DiagRow {
            name: PROXY_CONNECT_ROW.to_string(),
            verdict,
            detail: detail.to_string(),
        });

        // ★ W38 的那张表在这里落地。判断与文案都不在本 crate——见
        // `rmc_core::diagnostic`，以及 rmc-win 的 `AuthOutcome::summary`
        // 上关于 W158 的说明。
        let line = p.auth.line(p.connect);
        out.push(DiagRow {
            name: PROXY_AUTH_ROW.to_string(),
            verdict: line.verdict,
            detail: line.detail,
        });
    }

    if let Some(hk) = host_key {
        let detail = match hk {
            HostKeyRecord::FirstSeen { fingerprint } => format!("{fingerprint}（首次记录）"),
            HostKeyRecord::Matches { fingerprint } => format!("{fingerprint}（与记录一致）"),
        };
        out.push(DiagRow {
            name: HOST_KEY_ROW.to_string(),
            verdict: Verdict::Pass,
            detail,
        });
    }

    out
}

/// 第一条失败的预检步骤对应的处置建议。
///
/// # 按**步骤名**分派，不按错误文案分派
///
/// brief 原稿写的是 `detail.contains("证书")` 这一串。那等于把界面的
/// 处置建议钉在 rmc-core 错误文案的字面上——W125 那一轮刚把八处
/// 「Gateway」改成「运维服务器」，同样一次改名就会让这里整片失效，
/// 而**没有任何东西会红**（它只会静静地落到兜底那一支）。
///
/// 这里先按 [`ALL_STEPS`] 里的步骤名分派（那是 `PreflightStep::name`，
/// 一个 `&'static str`，改名会牵动 rmc-core 自己的常量），只有运维服务器
/// TLS 那一步内部有三种不同的根因，才退回看 `detail`。认不出的落到
/// [`Advice::Unrecognized`]，**不是** `NoFailure`。
pub fn advice_for(report: Option<&PreflightReport>) -> Advice {
    let Some(failure) = report.and_then(|r| r.first_failure()) else {
        return Advice::NoFailure;
    };
    let StepOutcome::Fail { detail, .. } = &failure.outcome else {
        // `first_failure` 按定义只返回 `Fail`，走不到这里。写成 `NoFailure`
        // 而不是 `unreachable!()`：一次误判不该让现场的客户端直接崩掉。
        return Advice::NoFailure;
    };
    let card = |body: &str| AdviceCard {
        failed_step: failure.name.to_string(),
        body: body.to_string(),
    };

    let body = match failure.name {
        STEP_APPLIANCE_TCP => {
            "一体机不可达。请确认设备已开机、sshd 在运行，以及这台笔记本仍在一体机所在的网段。"
        }
        STEP_APPLIANCE_HOSTKEY => {
            "一体机端口开着，但 SSH 握手没完成。请确认那个端口后面确实是一体机的 sshd，\
             而不是被别的服务占用了。"
        }
        STEP_GATEWAY_REACH => {
            "连不上运维服务器的这个端口。请确认这台笔记本能出网；客户网络只放行 443 时，\
             请客户网管放行这个 IP 的端口，或由运维把公网 443 映射到运维服务器后重发连接码。"
        }
        STEP_GATEWAY_TLS if detail.contains("指纹") => {
            "运维服务器的身份与连接码里的指纹对不上，连接已经拒绝。两种可能：路径上有做\
             中间人的 TLS 审计设备（请客户网管对这个 IP 与端口免做审计），或者连接码已经\
             过期（运维服务器换过密钥，请向运维重新索取连接码）。"
        }
        STEP_GATEWAY_TLS if detail.contains("代理要求认证") => {
            "代理要求认证，而这次协商没有通过。具体是哪一步没过，看上面「代理认证」那一行：\
             它分得清「代理要的是本机不做的认证方式」「这台笔记本建不出安全上下文」\
             「协商走完了而代理不接受当前用户」。前两种找 IT 把笔记本加域或换认证方式，\
             最后一种要网络管理员给当前用户开出网权限。"
        }
        STEP_GATEWAY_TLS if detail.contains("host key") => {
            "运维服务器的 host key 与本机记录的不一致，连接已经拒绝。\
             若运维服务器确实换过主机密钥，请联系运维核对指纹之后再删掉本机的记录；\
             否则这次连接可能被引到了一台冒充的服务器上。"
        }
        _ => {
            return Advice::Unrecognized(card(
                "这一步的失败不在已知的几类里。请点下面的「导出诊断包」，\
                 把包交给远程工程师。",
            ))
        }
    };
    Advice::Known(card(body))
}

/// 诊断页底部那一行环境信息，也是诊断包里 `environment.txt` 的内容。
///
/// Task 10 会把它换成真实的系统版本与网卡地址（画板上写的是
/// `客户端 0.4.2 · Windows 11 23H2 22631.4317 · 以太网 10.20.8.41`）。
/// 现在只有编译期就知道的那几样，见 task-9-report.md 的「后续完善」。
pub fn environment_line() -> String {
    format!(
        "客户端 {} · {} {}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

// =====================================================================
// 诊断包
// =====================================================================

/// 被抹掉的东西在包里留下的记号。
pub const REDACTED: &str = "[已脱敏]";

/// 日志目录读不出来时，包里那条说明的条目名（W180）。
///
/// **静默少一个 `logs/` 才是最糟的**：收到包的人会以为这台机器真的
/// 一条日志都没写过，而真相是它读不出来。
pub const LOGS_UNAVAILABLE: &str = "logs-unavailable.txt";

/// 有日志被截断、被略过、或者根本读不出来时，包里那条说明的条目名
/// （W196/W197）。
///
/// 跟 [`LOGS_UNAVAILABLE`] 分开：那一条说的是「整个目录列不出来」，
/// 这一条说的是「目录列出来了，但里面某几个文件没有完整进包」。合成
/// 一条的话，收到包的人分不出「一条日志都没有」与「少了最老的那两天」。
pub const LOGS_INCOMPLETE: &str = "logs-incomplete.txt";

/// 单个日志文件最多收进包里多少字节。超出的部分**从头部丢**，保留尾部
/// ——出事的记录在最后。
///
/// # W197（W167 到期）：为什么必须有这个上限
///
/// 在这一轮之前 `bundle` 对日志大小**没有任何限制**：`std::fs::read`
/// 整个读进内存 → [`Redaction::apply`] 产出第二份 → `write_all` 之前还
/// 有一份压缩缓冲，**三份同时在堆上**。一份 500MB 的日志（审计日志按天
/// 滚动，一台连续跑的机器上完全做得到）会让这个 520×720 的小工具在
/// 导出诊断包时吃掉 1.5GB 并且很可能当场 OOM ——而用户点的是「出问题了，
/// 导个包给工程师」。
///
/// 当初记下的理由是「轮转策略要 Task 11 才定」。这一轮就是 Task 11。
pub const LOG_ENTRY_LIMIT: u64 = 4 * 1024 * 1024;

/// 一次导出里**全部**日志加起来的上限。
///
/// 只限单个文件不够：`log_dir` 下有多少天的日志是不封顶的。预算按
/// **从新到旧**分配（[`plan_logs`]），所以吃紧时先保住今天那一份。
pub const LOG_TOTAL_BUDGET: u64 = 16 * 1024 * 1024;

/// 一个日志文件这次收多少。
///
/// 带类型，不是一个裸 `u64`（0 到底是「空文件」还是「一个字节都不收」
/// 说不清）——同 W193 那一串。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogTake {
    /// 整个文件都收。
    Whole,
    /// 只收**尾部** `bytes` 个字节，头部 `dropped` 个字节被丢掉。
    Tail { bytes: u64, dropped: u64 },
    /// 一个字节都不收：预算已经被更新的日志用完了。
    Skipped,
}

/// 一个日志文件的收取计划。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedLog {
    pub name: String,
    pub size: u64,
    pub take: LogTake,
}

/// 给一批日志文件分配预算。**纯函数**：收的是「文件名 + 大小」，不碰
/// 文件系统，于是「500MB 的日志会怎么办」这件事在这台机器上是可测的
/// （真造一个 500MB 的夹具既慢又会把开发机的盘填满）。
///
/// `files` 按文件名升序传入（日志名是 `rmc-YYYY-MM-DD.log`，升序即从旧
/// 到新）。预算**从新到旧**分配：盘上日志太多时，保住的是最近那几天。
/// 输出顺序跟输入一致，让同一份输入产出同一份包。
pub fn plan_logs(files: &[(String, u64)]) -> Vec<PlannedLog> {
    let mut takes = vec![LogTake::Skipped; files.len()];
    let mut left = LOG_TOTAL_BUDGET;
    for (i, (_, size)) in files.iter().enumerate().rev() {
        let want = (*size).min(LOG_ENTRY_LIMIT).min(left);
        takes[i] = if want >= *size {
            LogTake::Whole
        } else if want == 0 {
            // 预算用完了。**不写成 `Tail { bytes: 0 }`**：那会在包里放
            // 一个空条目，收到包的人以为这一天真的一条日志都没有。
            LogTake::Skipped
        } else {
            LogTake::Tail {
                bytes: want,
                dropped: size - want,
            }
        };
        left -= want;
    }
    files
        .iter()
        .zip(takes)
        .map(|((name, size), take)| PlannedLog {
            name: name.clone(),
            size: *size,
            take,
        })
        .collect()
}

/// 进诊断包之前要抹掉的东西。
///
/// # 为什么脱敏要**登记**，而不是靠猜
///
/// 一个通用的扫描器认不出「哪一串是口令」——口令可以是任何字符串。
/// 真正知道口令是什么的是界面自己（[`crate::form::Form::password`]）。
/// 所以这里收的是一份**明确登记的**要抹掉的字串清单，由调用方在导出时
/// 填进来。
///
/// 口令用 [`Zeroizing`] 承载，跟它在 `Form` / `Message` 里一样；
/// [`std::fmt::Debug`] 手写，不印内容也不印长度。
#[derive(Default, Clone)]
pub struct Redaction {
    secrets: Vec<Zeroizing<String>>,
}

impl std::fmt::Debug for Redaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 连条数都不印：条数会泄露「用户到底填没填口令」。
        f.write_str("Redaction { .. }")
    }
}

impl Redaction {
    pub fn new() -> Self {
        Self::default()
    }

    /// 登记一个不许出现在诊断包里的字串。
    ///
    /// 空串直接忽略——`"".replace` 会在每两个字符之间插一个记号，把整份
    /// 日志搅烂，而现场没填口令恰恰是最常见的情形。
    pub fn hide(&mut self, secret: &str) -> &mut Self {
        if !secret.is_empty() {
            self.secrets.push(Zeroizing::new(secret.to_string()));
        }
        self
    }

    /// 抹掉之后的文本。
    ///
    /// 两件事：
    ///
    /// 1. 登记过的字串整个换成 [`REDACTED`]；
    /// 2. 任何一行里出现 `Authorization`（含 `Proxy-Authorization`）时，
    ///    冒号之后的值整段换掉。那是代理协商 token 的落点，它没有被
    ///    登记过的机会——它由 SSPI 现场生成，界面从来看不见它。
    ///
    /// **说清楚它做不到什么**：这不是一个能认出任意凭据的扫描器。日志里
    /// 一段谁也没登记、也不带 `Authorization` 字样的密文会原样进包。
    /// rmc-core 与 rmc-win 的纪律是那种东西压根不进日志（`Zeroizing`、
    /// 手写 `Debug`、`AuthOutcome` 按设计不带 token），这里是第二道。
    pub fn apply(&self, text: &str) -> String {
        // `split_inclusive` 把换行符留在每一段的末尾，所以拼回去不需要
        // 自己补 `\n`——用 `lines()` 会把「文件末尾有没有换行」这件事悄悄
        // 改掉，而日志文件的结尾正好是最常被接着追加的地方。
        let mut out = String::with_capacity(text.len());
        for line in text.split_inclusive('\n') {
            out.push_str(&self.apply_line(line));
        }
        out
    }

    fn apply_line(&self, line: &str) -> String {
        let mut s = line.to_string();
        for secret in &self.secrets {
            if s.contains(secret.as_str()) {
                s = s.replace(secret.as_str(), REDACTED);
            }
        }
        if let Some(pos) = find_ignore_ascii_case(&s, "authorization") {
            if let Some(colon) = s[pos..].find(':') {
                let cut = pos + colon + 1;
                let tail_newline = if s.ends_with('\n') { "\n" } else { "" };
                s = format!("{}{REDACTED}{tail_newline}", &s[..cut]);
            }
        }
        s
    }
}

/// `haystack` 里第一次出现 `needle`（ASCII 大小写不敏感）的位置。
///
/// 只用于找 `Authorization` 这种 ASCII 头名，所以按字节比就够；中文不会
/// 被切坏，因为 UTF-8 多字节序列的每个字节都 ≥ 0x80，跟 ASCII 字母永远
/// 不相等。
fn find_ignore_ascii_case(haystack: &str, needle: &str) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    (0..=h.len() - n.len()).find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

/// 一次导出要打进包里的东西。
pub struct BundleInput<'a> {
    /// 环境信息，通常是 [`environment_line`] 的结果。
    pub environment: &'a str,
    /// 预检结果，没跑过就是 `None`。
    pub report: Option<&'a PreflightReport>,
    /// 日志目录。只有 `rmc-*.log` 会被收进去。
    pub log_dir: &'a Path,
    /// 抹掉这些之后才准进包。
    pub redaction: &'a Redaction,
}

/// 写出一个诊断包，返回它的路径。
///
/// 包里有三样东西，**每一样都先过一遍 [`Redaction::apply`]**：
///
/// - `environment.txt`：环境信息；
/// - `preflight.txt`：预检结果逐行（没跑过预检就没有这个条目）；
/// - `logs/<文件名>`：`log_dir` 下的 `rmc-*.log`，别的文件一律不收。
///
/// # 不许绕过脱敏
///
/// 三个写入点各自调一次 `apply`。把任何一处换成原文，
/// [`tests::no_entry_in_the_bundle_carries_the_canary_password_or_account`]
/// 立刻红——那条测试往**三个来源各灌了一个金丝雀**，正是为了让三处漏掉
/// 任何一处都被逮住。条目名也过一遍：文件名本身也会被打开包的人看见。
pub fn bundle(out_dir: &Path, input: &BundleInput<'_>) -> std::io::Result<PathBuf> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let out_path = out_dir.join(format!("rmc-diagnostics-{stamp}.zip"));

    // 失败就把半成品删掉（W180）。
    //
    // 不这么做的话，任何一步出错都会在盘上留下一个**打得开、却悄悄缺料**的包
    // ——`File::create` 已经建出文件，而 `ZipWriter::finish()` 还没跑。
    // ——`ZipWriter` 的 `Drop` 会把中央目录补完（复审实测：131 字节、
    // 打得开、条目只有 `environment.txt`）。危害不是「远程那头解不开」，
    // 而是**界面报了失败、盘上却躺着一个看上去完整的包**：发的人和收的人
    // 都不会知道少了日志。
    write_or_clean(&out_path, |p| write_bundle(p, input))
}

/// 写一个文件，**写失败就把半成品删掉**，成功时交出它的路径。
///
/// # W196：为什么这一层被单独抽出来
///
/// 这一轮把「单个日志文件读不出来」改成了优雅降级（见
/// [`write_bundle`]），于是 `write_bundle` 再也**没有任何一条现实输入
/// 能让它失败**——它现在只会因为输出文件本身出事（盘满、写到一半掉电、
/// 杀软掐掉句柄）而失败，而那些在 macOS 上没有确定性的夹具。
///
/// 原来守这件事的
/// [`tests::a_failed_export_leaves_no_half_filled_bundle_behind`] 的夹具
/// 正是「用一个目录冒充日志文件」，也正是这一轮要改成降级的那一档——
/// 改完那条守卫会因为**自己的反向自证**（`assert!(err.is_err())`）而变
/// 红。两条出路：换一个能让 `File::create` 之后失败的夹具，或者如实
/// 承认这条守卫此后无法覆盖。
///
/// 选的是第一条，做法是把清理这一层抽成这个函数：测试喂一个「先建出
/// 文件、再返回 `Err`」的闭包，正是「盘满」那一路在磁盘上留下的形状。
/// 代价写清楚：**它不再证明 `write_bundle` 真的会失败**（现在它几乎
/// 不会），只证明「一旦失败，盘上不留半成品」。
fn write_or_clean(
    out_path: &Path,
    write: impl FnOnce(&Path) -> std::io::Result<()>,
) -> std::io::Result<PathBuf> {
    match write(out_path) {
        Ok(()) => Ok(out_path.to_path_buf()),
        Err(e) => {
            let _ = std::fs::remove_file(out_path);
            Err(e)
        }
    }
}

/// [`bundle`] 的正体。分出来只为让"失败就删掉半成品"那一层写得下。
fn write_bundle(out_path: &Path, input: &BundleInput<'_>) -> std::io::Result<()> {
    let file = std::fs::File::create(out_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let opts: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    zip.start_file("environment.txt", opts)?;
    zip.write_all(input.redaction.apply(input.environment).as_bytes())?;

    if let Some(r) = input.report {
        let mut body = String::new();
        for s in &r.steps {
            let line = match &s.outcome {
                StepOutcome::Pass { detail } => format!("[通过] {} — {detail}\n", s.name),
                StepOutcome::Fail { detail, class } => {
                    format!("[失败/{class:?}] {} — {detail}\n", s.name)
                }
                StepOutcome::Skipped { detail } => format!("[未执行] {} — {detail}\n", s.name),
            };
            body.push_str(&line);
        }
        zip.start_file("preflight.txt", opts)?;
        zip.write_all(input.redaction.apply(&body).as_bytes())?;
    }

    // 日志目录读不了**不能让整次导出失败**（W180）。
    //
    // 实测过的那条路：干净机器上**第一次**导出时 `log_dir` 还不存在
    // （今天还没写过任何一条审计日志），`read_dir` 返回 `NotFound`，
    // 原来那个 `?` 把整次导出判成失败——而 zip 文件已经建出来了。
    // 也就是说「第一次导出」必然失败，而且留下一个打得开、却只有
    // `environment.txt` 的包。
    //
    // 现在分两种：
    //
    // - `NotFound`：**正常**，今天还没有日志，包里就没有 `logs/`；
    // - 别的（权限、路径被占）：**照样出包**，但包里留一条
    //   [`LOGS_UNAVAILABLE`] 说明为什么没有日志——静默少一个目录才是
    //   最糟的，收到包的人会以为这台机器真的一条日志都没写过。
    let mut logs: Vec<(String, u64)> = Vec::new();
    // 这一路上出的岔子都记在这儿，最后写成一条 `LOGS_INCOMPLETE` 说明。
    let mut notes: Vec<String> = Vec::new();
    match std::fs::read_dir(input.log_dir) {
        Ok(entries) => {
            for entry in entries {
                // W196：**列目录时某一项读不出来也不能让整包失败**。
                // 原来这里是一个 `?`。
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        notes.push(format!("日志目录里有一项列不出来：{e}"));
                        continue;
                    }
                };
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if !(name.starts_with("rmc-") && name.ends_with(".log")) {
                    continue;
                }
                // 大小取自 metadata。取不到就当它读不出来——**不去猜一个
                // 大小**，猜错的后果是预算失效。
                //
                // **刻意不在这里筛 `is_file()`**：那会让「名字像日志的
                // 目录」在这一步就被挡掉，下面 `read_log_range` 的降级
                // 分支于是一条夹具都够不着（变异 M11 实测：把那一支换回
                // `?`，全套测试照样全绿）。让它走完整条路，读不出来时
                // 由同一条降级分支记一句，用户看到的结果一模一样，而
                // 那条分支有了真实覆盖。
                match std::fs::metadata(&path) {
                    Ok(m) => logs.push((name.to_string(), m.len())),
                    Err(e) => notes.push(format!("{name}：读不出来（{e}），没有收进包里")),
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            zip.start_file(LOGS_UNAVAILABLE, opts)?;
            zip.write_all(
                input
                    .redaction
                    .apply(&format!("日志目录读不出来：{e}"))
                    .as_bytes(),
            )?;
        }
    }
    // 目录项的顺序由文件系统决定，排一遍序好让同一份输入产出同一份包
    // ——也让 `plan_logs` 的「从新到旧分配预算」有意义。
    logs.sort();

    for planned in plan_logs(&logs) {
        let path = input.log_dir.join(&planned.name);
        let (offset, note) = match planned.take {
            LogTake::Whole => (0, None),
            LogTake::Tail { bytes, dropped } => (
                dropped,
                Some(format!(
                    "{}：共 {} 字节，只收了最后 {bytes} 字节（诊断包有大小上限）",
                    planned.name, planned.size
                )),
            ),
            LogTake::Skipped => {
                notes.push(format!(
                    "{}：共 {} 字节，整个没有收进包里（诊断包的日志预算已经被更新的日志用完）",
                    planned.name, planned.size
                ));
                continue;
            }
        };
        // W196：**单个日志文件读不出来不能让整包失败、更不能让整包被
        // 删掉**。Windows 上「被别的进程占住」「正在轮转」「杀软挡住」
        // 都是现场常见形态，而这一轮之前这里是一个 `?`——一个读不出来
        // 的文件会让 `bundle` 返回 `Err`，`write_or_clean` 随即把已经
        // 写好的环境信息与预检结果连同整个包一起删掉。
        //
        // 那跟紧挨着的「整个目录列不出来反而宽容」自相矛盾，也跟那段
        // 注释自己立的原则（「静默少一个 `logs/` 才是最糟的」）相反。
        let raw = match read_log_range(&path, offset) {
            Ok(bytes) => bytes,
            Err(e) => {
                notes.push(format!("{}：读不出来（{e}），没有收进包里", planned.name));
                continue;
            }
        };
        if let Some(n) = note {
            notes.push(n);
        }
        // 日志是我们自己用 tracing 写的，永远是 UTF-8；`lossy` 是为了
        // 「写到一半断电」这种半条字符的情形（截尾读也会从一个字符中间
        // 开始），宁可画一个替换符也不要整个导出失败——现场要诊断包的
        // 时候多半正是出了乱子的时候。
        let text = String::from_utf8_lossy(&raw);
        zip.start_file(
            format!("logs/{}", input.redaction.apply(&planned.name)),
            opts,
        )?;
        zip.write_all(input.redaction.apply(&text).as_bytes())?;
    }

    if !notes.is_empty() {
        notes.sort();
        zip.start_file(LOGS_INCOMPLETE, opts)?;
        zip.write_all(input.redaction.apply(&notes.join("\n")).as_bytes())?;
    }

    zip.finish()?;
    Ok(())
}

/// 从 `offset` 开始把一个文件读到底。
///
/// `seek` 而不是「整个读进来再切」：W197 的全部意义就是**不要**把
/// 500MB 读进堆里。
fn read_log_range(path: &Path, offset: u64) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Seek};
    let mut f = std::fs::File::open(path)?;
    if offset > 0 {
        f.seek(std::io::SeekFrom::Start(offset))?;
    }
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

/// 这一次导出要抹掉哪些东西，**从表单上取**。
///
/// # W172：这是 [`Redaction`] 唯一的生产调用方
///
/// 在这一轮之前，`Redaction` 一个生产调用点都没有——诊断包照常导得
/// 出来，只是里面带着明文口令，而**没有任何闸门会因为忘了登记而变红**。
///
/// 把"登记什么"关进这个函数（而不是散在 `App::update` 里），是为了让
/// 「忘了登记」这件事结构上发生不了：[`export`] 是界面唯一的导出入口，
/// 它自己调这一个函数，调用方连一个能传错的参数都没有。
///
/// **两样都登记**：口令是显然的；账号也登记，因为诊断包会离开这台
/// 机器（见本模块顶部），而账号名加上日志里的时间线足以拼出"谁在什么
/// 时候连了哪台客户设备"。代价写在这里：账号名要是短到一两个字符，
/// 日志里凡是出现那个字符的地方都会被打成 [`REDACTED`]。宁可日志花掉，
/// 不可把凭据送出去。
pub fn redaction_for(form: &crate::form::Form) -> Redaction {
    let mut r = Redaction::new();
    r.hide(&form.password);
    // 账号名从连接码里解析——Task 8 把 `username` 单独一个框合并进了
    // `code`（见 `form::Form` 上「Task 8」一节）。连接码解析不出来就
    // 没有账号可登记，不是这个函数该处理的事（`validate()` 会在别处
    // 挡住无效表单）。
    if let Some(c) = form.parsed_code() {
        r.hide(c.account().as_str());
    }
    r
}

/// 导出一个诊断包，返回它的路径。**界面唯一的导出入口。**
///
/// 脱敏在这里就地做完（[`redaction_for`]），调用方没有机会绕过它。
pub fn export(
    form: &crate::form::Form,
    report: Option<&PreflightReport>,
    environment: &str,
    log_dir: &Path,
    out_dir: &Path,
) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(out_dir)?;
    let redaction = redaction_for(form);
    bundle(
        out_dir,
        &BundleInput {
            environment,
            report,
            log_dir,
            redaction: &redaction,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmc_core::error::ErrorClass;
    use rmc_core::preflight::PreflightStep;
    use std::io::Read;

    fn step(name: &'static str, outcome: StepOutcome) -> PreflightStep {
        PreflightStep { name, outcome }
    }

    fn pass(detail: &str) -> StepOutcome {
        StepOutcome::Pass {
            detail: detail.into(),
        }
    }

    fn failed(detail: &str) -> StepOutcome {
        StepOutcome::Fail {
            detail: detail.into(),
            class: ErrorClass::Fatal,
        }
    }

    /// 一份四步的报告，最后一步（运维服务器 TLS）由参数决定。
    fn report(tls: StepOutcome) -> PreflightReport {
        PreflightReport {
            steps: vec![
                step(STEP_APPLIANCE_TCP, pass("192.168.100.10:61001 可达 · 6 ms")),
                step(STEP_APPLIANCE_HOSTKEY, pass("SHA256:kM9v7bQe")),
                step(STEP_GATEWAY_REACH, pass("203.0.113.20:443 可达 · 直连")),
                step(STEP_GATEWAY_TLS, tls),
            ],
        }
    }

    // ================= 行 =================

    #[test]
    fn passing_steps_render_as_pass_and_are_not_highlighted() {
        let rows = rows(Some(&report(pass("握手成功 · 直连"))), None, None);
        assert_eq!(rows.len(), 4);
        assert!(rows.iter().all(|r| r.verdict == Verdict::Pass), "{rows:#?}");
        assert!(rows.iter().all(|r| !r.highlight()), "{rows:#?}");
    }

    #[test]
    fn a_failing_step_is_highlighted_and_the_others_are_not() {
        let rows = rows(
            Some(&report(failed("运维服务器 TLS 证书链无效：UnknownIssuer"))),
            None,
            None,
        );
        let tls = rows
            .iter()
            .find(|r| r.name == STEP_GATEWAY_TLS)
            .expect("没有画出运维服务器 TLS 那一行");
        assert_eq!(tls.verdict, Verdict::Fail);
        assert!(tls.highlight());
        // 反向自证：不是整页都标红了。
        assert_eq!(
            rows.iter().filter(|r| r.highlight()).count(),
            1,
            "{rows:#?}"
        );
    }

    #[test]
    fn a_skipped_step_has_no_verdict_and_is_not_highlighted() {
        let rows = rows(
            Some(&report(StepOutcome::Skipped {
                detail: "运维服务器未连通，未执行".into(),
            })),
            None,
            None,
        );
        let tls = rows.iter().find(|r| r.name == STEP_GATEWAY_TLS).unwrap();
        assert_eq!(tls.verdict, Verdict::Undecided);
        assert!(
            !tls.highlight(),
            "「没跑」被标红，等于凭空报一条没发生过的故障"
        );
    }

    /// W161（落实 W137）：没跑过预检时，四行按 [`ALL_STEPS`] 的**声明
    /// 顺序**排。
    ///
    /// 改红：把 `rows` 里 `None` 那一支的 `ALL_STEPS.iter()` 换成
    /// `ALL_STEPS.iter().rev()`，或者去 `preflight.rs` 的 `steps!` 里
    /// 对调两行——两种改法这条都红。后一种同时会打红 rmc-core 那边
    /// `run()` 产出顺序的那条断言，这正是要的：两个顺序必须一起动。
    #[test]
    fn the_unchecked_page_lists_every_step_in_declaration_order() {
        let rows = rows(None, None, None);
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ALL_STEPS.to_vec(), "没跑过预检时的排版跑偏了");
        assert!(
            rows.iter().all(|r| r.verdict == Verdict::Undecided),
            "还没检查过的步骤不该有结论：{rows:#?}"
        );
        // 反向自证：真的有四行，不是一个空表让上面两条空转。
        assert_eq!(rows.len(), 4);
    }

    #[test]
    fn the_proxy_rows_show_the_endpoint_the_connect_and_the_negotiation() {
        let proxy = ProxyStatus {
            endpoint: "proxy.company.com:8080".into(),
            connect: ConnectOutcome::Established,
            auth: ProxyAuthSummary::FinalTokenIssued {
                package: "NTLM".into(),
                rounds: 2,
            },
        };
        let rows = rows(Some(&report(pass("握手成功"))), Some(&proxy), None);

        let endpoint = rows.iter().find(|r| r.name == PROXY_ENDPOINT_ROW).unwrap();
        assert!(
            endpoint.detail.contains("proxy.company.com:8080"),
            "{endpoint:?}"
        );

        let connect = rows.iter().find(|r| r.name == PROXY_CONNECT_ROW).unwrap();
        assert_eq!(connect.verdict, Verdict::Pass);

        let auth = rows.iter().find(|r| r.name == PROXY_AUTH_ROW).unwrap();
        assert_eq!(auth.verdict, Verdict::Pass, "{auth:?}");
        assert!(auth.detail.contains("NTLM"), "{auth:?}");
    }

    /// 代理认证那一行的结论**真的跟着 CONNECT 走**。
    ///
    /// 这是 W38 那根轴在界面这一层的落地：同一个协商结局，CONNECT 成没成
    /// 必须给出不同的结论。
    ///
    /// 改红：把 `rows` 里 `p.auth.line(p.connect)` 写成
    /// `p.auth.line(ConnectOutcome::Established)`——第二组断言变红。
    #[test]
    fn the_negotiation_row_follows_the_connect_result() {
        let mk = |connect| ProxyStatus {
            endpoint: "proxy.company.com:8080".into(),
            connect,
            auth: ProxyAuthSummary::TokenIssued {
                package: "Negotiate".into(),
                round: 1,
            },
        };
        let row_of = |connect| {
            rows(None, Some(&mk(connect)), None)
                .into_iter()
                .find(|r| r.name == PROXY_AUTH_ROW)
                .expect("没有画出代理认证那一行")
        };

        let ok = row_of(ConnectOutcome::Established);
        assert_eq!(ok.verdict, Verdict::Pass);

        let bad = row_of(ConnectOutcome::Failed);
        assert_eq!(bad.verdict, Verdict::Fail);
        assert_ne!(ok.detail, bad.detail, "两种结果给出了同一句话");
    }

    /// W164 的另一半：`transport::connect` 抛的那句话里指的那一行
    /// **真的存在于这一页上**。
    ///
    /// rmc-core 那边的 `the_failure_text_states_the_fact_and_points_at_the_diagnostics_row`
    /// 只证明错误文案里写着 [`PROXY_AUTH_ROW`] 这个常量的值；证明不了
    /// 诊断页真的画着这么一行。两句话在 Task 9 才第一次相遇，所以守它的
    /// 两条测试分住两个 crate。
    ///
    /// 改红：把 `rows` 里那一行的 `name` 换成任何一个别的字面量（比如
    /// 直接写 `"代理认证（SSPI Negotiate）"`）——指路就成了死指针，这条红。
    #[test]
    fn the_error_text_points_at_a_row_the_page_really_draws() {
        let proxy = ProxyStatus {
            endpoint: "proxy.company.com:8080".into(),
            connect: ConnectOutcome::Failed,
            auth: ProxyAuthSummary::Completed {
                package: "Negotiate".into(),
                rounds: 2,
            },
        };
        let rows = rows(None, Some(&proxy), None);
        assert!(
            rows.iter().any(|r| r.name == PROXY_AUTH_ROW),
            "诊断页上没有一行叫「{PROXY_AUTH_ROW}」，而 rmc-core 的错误文案正指着它：{rows:#?}"
        );

        // 顺带把「两句话不再矛盾」这件事本身断言一次：错误文案只陈述
        // 事实，原因由这一行说，而这一行说的是「代理不接受当前用户」。
        let auth = rows.iter().find(|r| r.name == PROXY_AUTH_ROW).unwrap();
        assert!(auth.detail.contains("不接受当前用户"), "{auth:?}");
    }

    #[test]
    fn the_host_key_row_tells_first_sight_from_a_match() {
        let first = HostKeyRecord::from_model(&("SHA256:aaa".to_string(), true));
        let again = HostKeyRecord::from_model(&("SHA256:aaa".to_string(), false));
        assert_eq!(first.fingerprint(), "SHA256:aaa");

        let detail_of = |hk: &HostKeyRecord| {
            rows(None, None, Some(hk))
                .into_iter()
                .find(|r| r.name == HOST_KEY_ROW)
                .expect("没有画出 host key 那一行")
                .detail
        };
        // 反向自证：「一体机 host key 指纹」那一行也含「host key」三个字，
        // 而且排在前面。这一条确认我们找的是运维服务器那一行。
        let all = rows(None, None, Some(&first));
        assert_eq!(
            all.iter().filter(|r| r.name.contains("host key")).count(),
            2,
            "含「host key」的行数变了，下面的查找可能找错行：{all:#?}"
        );

        let a = detail_of(&first);
        let b = detail_of(&again);
        assert!(a.contains("首次记录"), "{a}");
        assert!(b.contains("与记录一致"), "{b}");
        assert!(a.contains("SHA256:aaa") && b.contains("SHA256:aaa"));
        // 反向自证：两句话真的不同。`from_model` 把 bool 读反了的话，
        // 上面两条会各自红；而如果两个变体画出同一句话，这条红。
        assert_ne!(a, b);
    }

    // ================= 处置建议 =================

    #[test]
    fn nothing_failed_means_no_card_at_all() {
        assert_eq!(
            advice_for(Some(&report(pass("握手成功")))),
            Advice::NoFailure
        );
        assert_eq!(advice_for(None), Advice::NoFailure, "还没跑过预检也不画卡");
        assert!(advice_for(None).card().is_none());
    }

    /// 四类已知失败各有一段自己的处置建议，而且**标题是那一步的名字**。
    ///
    /// 改红：
    /// - 把 `advice_for` 的 `match failure.name` 换回 brief 原稿那种
    ///   `detail.contains("证书")` 的链，然后把 rmc-core 的错误文案改一个
    ///   字——这条会落到 `Unrecognized` 上，当场红；
    /// - 把 `card` 里的 `failed_step` 与 `body` 写反 → 编译不过（具名
    ///   字段，W159 换掉裸元组的收益）。
    #[test]
    fn each_known_failure_gets_its_own_advice_titled_with_the_step() {
        let cases: [(&str, StepOutcome, &[&str]); 5] = [
            (
                STEP_APPLIANCE_TCP,
                failed("一体机不可达：连接超时"),
                &["一体机", "sshd"],
            ),
            (
                STEP_APPLIANCE_HOSTKEY,
                failed("一体机不可达：SSH 握手超时"),
                &["sshd"],
            ),
            (
                STEP_GATEWAY_REACH,
                failed("TCP 连接失败：Connection refused (os error 61)"),
                &["出网", "443"],
            ),
            (
                STEP_GATEWAY_TLS,
                failed("运维服务器的身份与连接码里的指纹不一致：invalid peer certificate: application verification failure"),
                &["指纹", "连接码"],
            ),
            (
                STEP_GATEWAY_TLS,
                failed("代理要求认证，协商失败：代理要求 Basic 认证，本次没有通过"),
                &[PROXY_AUTH_ROW, "出网权限"],
            ),
        ];

        let mut bodies = std::collections::BTreeSet::new();
        for (name, outcome, keywords) in cases {
            let steps = vec![step(STEP_APPLIANCE_TCP, pass("可达")), step(name, outcome)];
            // 上面那条 `Pass` 保证 `first_failure` 真的在往后找，而不是
            // 拿第一条凑数。
            let r = PreflightReport {
                steps: if name == STEP_APPLIANCE_TCP {
                    steps[1..].to_vec()
                } else {
                    steps
                },
            };
            let advice = advice_for(Some(&r));
            let Advice::Known(card) = &advice else {
                panic!("{name} 应当有针对性的建议，却是 {advice:?}");
            };
            assert_eq!(card.failed_step, name, "标题不是失败的那一步");
            for k in keywords {
                assert!(
                    card.body.contains(k),
                    "{name} 的建议里没有「{k}」：{}",
                    card.body
                );
            }
            bodies.insert(card.body.clone());
        }
        // 五格两两不同——两类失败给出同一段建议，等于现场工程师看到的还是
        // 同一条信息。
        assert_eq!(bodies.len(), 5, "有两类失败给出了同一段建议");
    }

    /// 认不出的失败**仍然要画卡**，而且落在 [`Advice::Unrecognized`] 上。
    ///
    /// 这是 W159 点名的那个压平：brief 的 `Option<(String, String)>` 把
    /// 这种情形跟「一切正常」都写成 `None`，于是现场对着一屏红字什么下一步
    /// 都得不到。
    ///
    /// 改红：把 `advice_for` 兜底那一支改成 `return Advice::NoFailure`
    /// ——第一条断言红。
    #[test]
    fn an_unrecognized_failure_still_gets_a_card_that_says_export_the_bundle() {
        let r = PreflightReport {
            steps: vec![step(
                STEP_GATEWAY_TLS,
                failed("TLS 握手中断：connection reset by peer"),
            )],
        };
        let advice = advice_for(Some(&r));
        let Advice::Unrecognized(card) = &advice else {
            panic!("认不出的失败应当落在 Unrecognized 上，却是 {advice:?}");
        };
        assert_eq!(card.failed_step, STEP_GATEWAY_TLS);
        assert!(card.body.contains("导出诊断包"), "{}", card.body);
        assert!(advice.card().is_some(), "认不出也要画卡");
    }

    // ================= 脱敏 =================

    #[test]
    fn redaction_hides_what_was_registered_and_keeps_the_rest() {
        let mut r = Redaction::new();
        r.hide("hunter2").hide("tunnel-zhang");
        let out = r.apply("INFO 用户 tunnel-zhang 登录，口令 hunter2，耗时 6 ms\n");
        assert!(!out.contains("hunter2"), "{out}");
        assert!(!out.contains("tunnel-zhang"), "{out}");
        // 反向自证：不是把整行清空了。清空同样能让上面两条通过——这正是
        // 本项目抓到过 20 次的那种假绿。
        assert!(out.contains("INFO"), "{out}");
        assert!(out.contains("耗时 6 ms"), "{out}");
        assert!(out.contains(REDACTED), "{out}");
        assert!(out.ends_with('\n'), "换行没保住：{out:?}");
    }

    #[test]
    fn an_empty_secret_is_ignored_rather_than_shredding_the_text() {
        let mut r = Redaction::new();
        r.hide("");
        // 现场没填口令是最常见的情形；`"".replace` 会在每两个字符之间
        // 插一个记号，把整份日志搅烂。
        assert_eq!(r.apply("INFO 一切正常\n"), "INFO 一切正常\n");
    }

    #[test]
    fn an_authorization_header_loses_its_value_even_when_nobody_registered_it() {
        // 协商 token 由 SSPI 现场生成，界面从来看不见它，所以它没有被
        // 登记的机会。
        let r = Redaction::new();
        let out = r.apply("DEBUG Proxy-Authorization: Negotiate TlRMTVNTUAABSECRET\n");
        assert!(!out.contains("TlRMTVNTUAABSECRET"), "{out}");
        // 反向自证：头名还在，否则排查时连「这里有过一个认证头」都看不出来。
        assert!(out.contains("Proxy-Authorization"), "{out}");
        assert!(out.ends_with('\n'), "换行没保住：{out:?}");
        // 别的行不受影响。
        assert!(r.apply("INFO 没有认证头\n").contains("没有认证头"));
    }

    #[test]
    fn the_debug_rendering_of_a_redaction_says_nothing_about_the_secrets() {
        let mut r = Redaction::new();
        r.hide("canary-6b21f4-must-never-be-printed");
        let dumped = format!("{r:?}");
        assert!(!dumped.contains("canary"), "{dumped}");
        assert!(!dumped.contains("6b21f4"), "{dumped}");
        // 连条数都不该印：条数泄露「用户填没填口令」。
        assert!(!dumped.contains('1'), "{dumped}");
    }

    // ================= 诊断包 =================

    /// 打开这个包，逐条目读出**字节**。
    fn entries_of(zip_path: &Path) -> Vec<(String, Vec<u8>)> {
        let f = std::fs::File::open(zip_path).expect("打开诊断包");
        let mut archive = zip::ZipArchive::new(f).expect("这不是一个合法的 zip");
        let mut out = Vec::new();
        for i in 0..archive.len() {
            let mut e = archive.by_index(i).expect("读条目");
            let name = e.name().to_string();
            let mut buf = Vec::new();
            e.read_to_end(&mut buf).expect("读条目内容");
            out.push((name, buf));
        }
        out
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack.len() >= needle.len()
            && (0..=haystack.len() - needle.len()).any(|i| &haystack[i..i + needle.len()] == needle)
    }

    fn text_of<'a>(entries: &'a [(String, Vec<u8>)], name: &str) -> &'a [u8] {
        &entries
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("包里没有 {name}：{:?}", names_of(entries)))
            .1
    }

    fn names_of(entries: &[(String, Vec<u8>)]) -> Vec<&str> {
        entries.iter().map(|(n, _)| n.as_str()).collect()
    }

    /// 包里**确实有**该有的东西。
    ///
    /// 这一条单独存在，是因为 brief 原稿那条
    /// `bundle_creates_a_zip_containing_the_report` 只断言了
    /// `exists()` / `extension == "zip"` / `len() > 0`——**一个空 zip 能过
    /// 全部三条**，而它名字里写着 "containing the report"。
    ///
    /// 改红：把 `bundle` 里写 `preflight.txt` 那一段删掉；或者把日志那层
    /// 循环的过滤条件写反（收 `.txt` 不收 `.log`）。
    #[test]
    fn the_bundle_really_carries_the_environment_the_report_and_the_logs() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let logs = dir.path().join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::write(
            logs.join("rmc-2026-09-13.log"),
            "INFO 状态 Idle → Preflight\n",
        )
        .unwrap();
        std::fs::write(logs.join("rmc-2026-09-12.log"), "INFO 昨天的日志\n").unwrap();
        // 不是我们的文件，不许收。
        std::fs::write(logs.join("notes.txt"), "工程师自己的便条").unwrap();
        std::fs::write(logs.join("rmc-config.json"), "{}").unwrap();

        let r = report(failed("运维服务器 TLS 证书链无效：UnknownIssuer"));
        let redaction = Redaction::new();
        let zip = bundle(
            dir.path(),
            &BundleInput {
                environment: "客户端 0.1.0 · 现场记号",
                report: Some(&r),
                log_dir: &logs,
                redaction: &redaction,
            },
        )
        .expect("导出诊断包");

        assert_eq!(zip.extension().and_then(|e| e.to_str()), Some("zip"));
        let entries = entries_of(&zip);
        let names = names_of(&entries);
        assert_eq!(
            names,
            vec![
                "environment.txt",
                "preflight.txt",
                "logs/rmc-2026-09-12.log",
                "logs/rmc-2026-09-13.log",
            ],
            "包里的条目不对"
        );

        assert!(contains_bytes(
            text_of(&entries, "environment.txt"),
            "现场记号".as_bytes()
        ));

        let preflight = text_of(&entries, "preflight.txt");
        for name in ALL_STEPS {
            assert!(
                contains_bytes(preflight, name.as_bytes()),
                "preflight.txt 里没有步骤「{name}」"
            );
        }
        assert!(
            contains_bytes(preflight, "[通过]".as_bytes()),
            "通过的步骤没有被记下来"
        );
        assert!(
            contains_bytes(preflight, "UnknownIssuer".as_bytes()),
            "失败的原因没有被记下来——那正是远程工程师要看的东西"
        );
        assert!(
            contains_bytes(preflight, "[失败/Fatal]".as_bytes()),
            "失败的分类没有被记下来"
        );

        assert!(contains_bytes(
            text_of(&entries, "logs/rmc-2026-09-13.log"),
            "Idle".as_bytes()
        ));
    }

    /// 没跑过预检就不该有 `preflight.txt`——不是一个空条目。
    ///
    /// 空条目会让远程工程师以为预检跑过而且什么都没查出来。
    #[test]
    fn without_a_report_there_is_no_preflight_entry() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let redaction = Redaction::new();
        let zip = bundle(
            dir.path(),
            &BundleInput {
                environment: "客户端 0.1.0",
                report: None,
                log_dir: dir.path(),
                redaction: &redaction,
            },
        )
        .expect("导出诊断包");
        let entries = entries_of(&zip);
        assert_eq!(names_of(&entries), vec!["environment.txt"]);
    }

    /// ★ **W157。这是本任务最要紧的一条测试。**
    ///
    /// 诊断包是这个产品里**唯一会离开这台机器**的产物。「包里不含凭据」
    /// 这件事没有任何编译器或闸门会帮忙，只有这一条守着。
    ///
    /// 三件事缺一不可：
    ///
    /// 1. **金丝雀灌进 `bundle` 看得见的每一个来源**——环境信息、预检
    ///    结果、日志文件，三处各一份（口令与账号各一个）。三个写入点漏掉
    ///    任何一个都会被逮住。
    /// 2. **逐条目读出解压之后的字节**去查，不是查文件名、也不是查 zip
    ///    的原始字节（deflate 之后明文在原始字节里本来就找不到，那样查
    ///    是一条永远为真的断言）。条目名另外单独查一遍。
    /// 3. **反向自证**：每个来源各留一个非密的记号，必须**还在包里**。
    ///    少了这一步，把 `Redaction::apply` 写成 `String::new()`——也就是
    ///    导出一个三个条目全空的包——照样全绿。
    ///
    /// # 变异验证（都实测过，见 task-9-report.md）
    ///
    /// - `bundle` 里 `input.redaction.apply(input.environment)` 换成
    ///   `input.environment` → 红（`environment.txt` 泄露账号）；
    /// - 预检那一段的 `apply(&body)` 换成 `body` → 红（`preflight.txt`
    ///   泄露口令与账号）；
    /// - 日志那一段的 `apply(&text)` 换成 `text` → 红；
    /// - `Redaction::apply` 整个换成 `String::new()` → 反向自证那三条红。
    #[test]
    fn no_entry_in_the_bundle_carries_the_canary_password_or_account() {
        const PASSWORD: &str = "canary-pw-4f81c2-must-never-leave-this-machine";
        const ACCOUNT: &str = "canary-acct-9d3b07-must-never-leave-this-machine";
        // 每个来源各留一个**非密**记号，用来反向自证。
        const MARK_ENV: &str = "mark-env-a1b2";
        const MARK_REPORT: &str = "mark-report-c3d4";
        const MARK_LOG: &str = "mark-log-e5f6";

        let dir = tempfile::tempdir().expect("建临时目录");
        let logs = dir.path().join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::write(
            logs.join("rmc-2026-09-13.log"),
            format!(
                "INFO {MARK_LOG} 用户 {ACCOUNT} 开始认证\n\
                 DEBUG 试了一次 password={PASSWORD}\n\
                 DEBUG Proxy-Authorization: Negotiate TlRMTVNTUAABSECRETTOKEN\n"
            ),
        )
        .unwrap();
        // **条目名那一侧的载荷**。评审实测：没有这一份时，下面那句
        // `!name.contains(canary)` 是**空转的**——把 `apply(name)` 换回
        // `name` 一条都不红，因为没有任何来源把金丝雀灌进文件名。
        // 日志按账号分文件不是杜撰的形状：出问题时按人找日志是常见做法。
        std::fs::write(
            logs.join(format!("rmc-{ACCOUNT}.log")),
            format!("INFO {MARK_LOG} 按账号分出来的那一份\n"),
        )
        .unwrap();

        let r = PreflightReport {
            steps: vec![
                step(STEP_APPLIANCE_TCP, pass(&format!("{MARK_REPORT} 可达"))),
                step(
                    STEP_GATEWAY_TLS,
                    failed(&format!("账号 {ACCOUNT} 口令 {PASSWORD} 被拒")),
                ),
            ],
        };
        let environment = format!("客户端 0.1.0 · {MARK_ENV} · 登录用户 {ACCOUNT} / {PASSWORD}");

        let mut redaction = Redaction::new();
        redaction.hide(PASSWORD).hide(ACCOUNT);

        let zip = bundle(
            dir.path(),
            &BundleInput {
                environment: &environment,
                report: Some(&r),
                log_dir: &logs,
                redaction: &redaction,
            },
        )
        .expect("导出诊断包");

        let entries = entries_of(&zip);

        // --- 反向自证 1：三个条目真的都在。空包不许过。---
        assert_eq!(
            names_of(&entries),
            vec![
                "environment.txt",
                "preflight.txt",
                "logs/rmc-2026-09-13.log",
                "logs/rmc-[已脱敏].log"
            ],
            "三个来源没有都进包，下面的扫描会在一个空包上空转"
        );

        // --- 反向自证 2：每个来源的非密记号都还在。---
        for (entry, mark) in [
            ("environment.txt", MARK_ENV),
            ("preflight.txt", MARK_REPORT),
            ("logs/rmc-2026-09-13.log", MARK_LOG),
        ] {
            assert!(
                contains_bytes(text_of(&entries, entry), mark.as_bytes()),
                "{entry} 里连非密的记号「{mark}」都没了——脱敏把整段清空了，\
                 那下面的金丝雀扫描就是一条永远为真的断言"
            );
        }

        // --- 主断言：任何一个条目的**字节**里都不出现金丝雀。---
        for (name, bytes) in &entries {
            for (what, canary) in [("口令", PASSWORD), ("账号", ACCOUNT)] {
                assert!(!name.contains(canary), "条目**名**里出现了{what}：{name}");
                assert!(
                    !contains_bytes(bytes, canary.as_bytes()),
                    "条目 {name} 的字节里出现了{what}：\n{}",
                    String::from_utf8_lossy(bytes)
                );
            }
            // 顺带：没被登记过的协商 token 也被那条 `Authorization` 规则
            // 挡住了。
            assert!(
                !contains_bytes(bytes, "TlRMTVNTUAABSECRETTOKEN".as_bytes()),
                "条目 {name} 里出现了协商 token"
            );
        }

        // --- 再扫一遍 zip 的**原始字节**。---
        // deflate 之后明文本来就找不到，所以这一条单独看会是空转——它守的
        // 是另一件事：有人把某个条目改成 `Stored`、或者往 zip 注释 /
        // 扩展字段里塞了原文。上面那一轮解压扫描是主断言，这一条是补丁。
        let raw = std::fs::read(&zip).unwrap();
        for canary in [PASSWORD, ACCOUNT] {
            assert!(
                !contains_bytes(&raw, canary.as_bytes()),
                "zip 的原始字节里出现了金丝雀（未压缩的条目？注释？扩展字段？）"
            );
        }
    }

    // ================= W172：从 `Form` 到 zip 字节 =================

    /// **端到端：表单里敲进去的口令与账号，一个字节都到不了 zip 里。**
    ///
    /// 上面那条 `no_entry_in_the_bundle_carries_the_canary_password_or_account`
    /// 守的是 [`bundle`] 这一层——它收一份**已经填好的** [`Redaction`]，
    /// 于是"谁来填、填没填"整件事在它眼皮底下不存在。W172 点名的正是
    /// 这个缺口：在这一轮之前 `Redaction` **一个生产调用方都没有**，
    /// 诊断包照常导得出来，只是里面带着明文口令，而**没有任何闸门会
    /// 因为忘了登记而变红**。
    ///
    /// 这条从 [`crate::form::Form`] 出发，走界面真正会走的那条路
    /// （[`export`]），一路到 zip 的字节。
    ///
    /// # 改实现的哪一行会让它红
    ///
    /// - 把 [`redaction_for`] 的函数体换成 `Redaction::new()`（"忘了
    ///   登记"）→ 主断言当场红；
    /// - 只登记口令、漏掉账号（`r.hide(c.account().as_str())` 那一段
    ///   删掉）→ 账号那一半红；
    /// - 让 [`export`] 绕开 `redaction_for` 自己 `Redaction::new()` →
    ///   同上。
    ///
    /// 三种都实测过，见 task-10-report.md 的变异表。
    #[test]
    fn nothing_the_user_typed_into_the_form_reaches_the_diagnostics_zip() {
        const PASSWORD: &str = "canary-pw-4f81c2-must-never-leave-this-machine";
        // 账号名要能装进一条连接码：`AccountName` 只认小写字母、数字、
        // 连字符，最多 32 位——不能沿用旧版那个任意长字符串。
        const ACCOUNT: &str = "canary9d3b07nomachine";
        const MARK: &str = "mark-e2e-b7c9";

        let dir = tempfile::tempdir().expect("建临时目录");
        let logs = dir.path().join("logs");
        let out = dir.path().join("out");
        std::fs::create_dir_all(&logs).unwrap();

        // 三个来源各灌一份金丝雀，形状照现场：审计日志里会记账号
        // （「口令认证通过 tunnel-zhang」是 rmc-core 真的会写的一行）。
        std::fs::write(
            logs.join("rmc-2026-09-13.log"),
            format!(
                "2026-09-13T11:12:46+08:00 INFO {MARK} 口令认证通过 {ACCOUNT}\n\
                 2026-09-13T11:12:47+08:00 INFO 调试留下的一行 password={PASSWORD}\n"
            ),
        )
        .unwrap();
        let report = PreflightReport {
            steps: vec![step(
                STEP_GATEWAY_TLS,
                failed(&format!("账号 {ACCOUNT} 口令 {PASSWORD} 被拒")),
            )],
        };
        let environment = format!("{MARK} · 登录用户 {ACCOUNT}");

        // **这就是用户敲进去的那份表单。** 连接码现生成——手写的校验位
        // 会算错。
        let code = rmc_core::code::ConnectionCode::new(
            rmc_core::code::AccountName::parse(ACCOUNT).unwrap(),
            "203.0.113.10".parse().unwrap(),
            22000,
            rmc_core::code::ServerFingerprint::of_ed25519_public(&[7u8; 32]),
        )
        .expect("夹具必须合法")
        .to_string();
        let form = crate::form::Form {
            appliance_host: "192.168.100.10".into(),
            appliance_port: "61001".into(),
            code,
            password: Zeroizing::new(PASSWORD.into()),
            remember: false,
            detected_proxy: None,
        };

        let zip = export(&form, Some(&report), &environment, &logs, &out).expect("导出诊断包");

        let entries = entries_of(&zip);
        // 反向自证 1：三个来源都进包了，扫描不是在一个空包上空转。
        assert_eq!(
            names_of(&entries),
            vec![
                "environment.txt",
                "preflight.txt",
                "logs/rmc-2026-09-13.log"
            ],
            "三个来源没有都进包"
        );
        // 反向自证 2：非密的记号还在，脱敏没有把整段清空。
        for entry in ["environment.txt", "logs/rmc-2026-09-13.log"] {
            assert!(
                contains_bytes(text_of(&entries, entry), MARK.as_bytes()),
                "{entry} 连非密的记号都没了，下面的扫描会空转"
            );
        }

        // 主断言。
        for (name, bytes) in &entries {
            for (what, canary) in [("口令", PASSWORD), ("账号", ACCOUNT)] {
                assert!(
                    !contains_bytes(bytes, canary.as_bytes()),
                    "条目 {name} 里出现了用户在表单上敲进去的{what}：\n{}",
                    String::from_utf8_lossy(bytes)
                );
            }
        }
        let raw = std::fs::read(&zip).unwrap();
        for canary in [PASSWORD, ACCOUNT] {
            assert!(
                !contains_bytes(&raw, canary.as_bytes()),
                "zip 原始字节里有金丝雀"
            );
        }
    }

    /// 没填口令时**不许**把整份日志打花。
    ///
    /// `"".replace(..)` 会在每两个字符之间插一个记号。`Redaction::hide`
    /// 自己挡着空串，这条守的是"[`redaction_for`] 真的走了那条挡板"
    /// ——而"现场还没填口令就先导一包"恰恰是最常见的用法。
    #[test]
    fn an_empty_password_does_not_shred_the_bundle() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let logs = dir.path().join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::write(
            logs.join("rmc-2026-09-13.log"),
            "2026-09-13T11:00:00+08:00 INFO 一行普通的日志\n",
        )
        .unwrap();

        let form = crate::form::Form::default();
        assert!(form.password.is_empty() && form.code.is_empty());

        let zip = export(&form, None, "环境信息一行", &logs, dir.path()).expect("导出诊断包");
        let entries = entries_of(&zip);
        assert_eq!(
            String::from_utf8_lossy(text_of(&entries, "environment.txt")),
            "环境信息一行"
        );
        assert!(contains_bytes(
            text_of(&entries, "logs/rmc-2026-09-13.log"),
            "一行普通的日志".as_bytes()
        ));
        assert!(
            !contains_bytes(text_of(&entries, "environment.txt"), REDACTED.as_bytes()),
            "空口令把整份文本打花了"
        );
    }

    // ================= W180：第一次导出 =================

    /// **干净机器上的第一次导出必须成功。**
    ///
    /// 这是评审实测出来的一个真 bug，不只是测试问题：
    /// 今天还没写过任何一条审计日志时 `log_dir` 根本不存在，原来
    /// `bundle` 里那句 `for entry in read_dir(log_dir)?` 会把整次导出
    /// 判成失败——**而 zip 文件已经被 `File::create` 建出来了**。
    ///
    /// 现场第一次点「导出诊断包」恰恰就是这种情形（而且那多半正是
    /// 连不上、急着要包的时候），后果是：界面报失败，盘上留下一个
    /// 打得开、却悄悄缺了日志的包——工程师把它发出去，两头都不知道缺料。
    ///
    /// 改红：把 `write_bundle` 里那个 `match read_dir` 换回
    /// `for entry in read_dir(input.log_dir)?`。
    #[test]
    fn the_very_first_export_on_a_clean_machine_succeeds() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let logs = dir.path().join("logs"); // 故意**不建**它
        assert!(!logs.exists());

        let form = crate::form::Form::default();
        let zip = export(&form, None, "客户端 0.1.0", &logs, dir.path())
            .expect("第一次导出就失败了——干净机器上这是必然发生的那一次");

        // 出来的是一个**打得开**的包，不是半成品。
        let entries = entries_of(&zip);
        assert_eq!(names_of(&entries), vec!["environment.txt"]);
        assert_eq!(
            String::from_utf8_lossy(text_of(&entries, "environment.txt")),
            "客户端 0.1.0"
        );
    }

    /// 日志目录**读不出来**（不是"不存在"）时，包里要说一句。
    ///
    /// 静默少一个 `logs/` 是最糟的：收到包的人会以为这台机器真的一条
    /// 日志都没写过。
    ///
    /// 改红：把那个 `Err(e) => { ... }` 分支体换成 `{}`。
    #[test]
    fn a_log_directory_that_cannot_be_read_is_reported_inside_the_bundle() {
        let dir = tempfile::tempdir().expect("建临时目录");
        // 路径被一个**文件**占住：`read_dir` 必然失败，且不是 NotFound。
        let logs = dir.path().join("logs");
        std::fs::write(&logs, b"not a directory").unwrap();

        let form = crate::form::Form::default();
        let zip = export(&form, None, "客户端 0.1.0", &logs, dir.path())
            .expect("日志读不出来不该让整次导出失败");

        let entries = entries_of(&zip);
        assert!(
            names_of(&entries).contains(&LOGS_UNAVAILABLE),
            "日志读不出来却一声不响：{:?}",
            names_of(&entries)
        );
        // 反向自证：环境信息照样进包了，包不是空的。
        assert!(names_of(&entries).contains(&"environment.txt"));
    }

    /// 失败时**不留半成品**。
    ///
    /// # W196：这条守卫换过一次夹具，代价写在这里
    ///
    /// 上一版的夹具是「日志目录里躺着一个名字像日志文件的**目录**」：
    /// `read_dir` 把它列出来，随后 `std::fs::read` 在它上面失败
    /// （`EISDIR`），而那时 zip 已经建出来了。
    ///
    /// 这一轮把「单个日志文件读不出来」改成了优雅降级（W196），那个
    /// 夹具于是**再也失败不了**——这条守卫因为自己那句反向自证
    /// （`assert!(err.is_err())`）当场变红，是它自己把这次行为变更报出来
    /// 的。改完之后 `write_bundle` 没有任何一条现实输入能让它失败：
    /// 它只会因为输出文件本身出事（盘满、写到一半掉电、杀软掐掉句柄）
    /// 而失败，而那些在 macOS 上没有确定性的夹具。
    ///
    /// 出路是把清理那一层抽成 [`write_or_clean`]，这里喂一个「**先把
    /// 文件建出来**、再返回 `Err`」的闭包——那正是"盘满"在磁盘上留下的
    /// 形状。
    ///
    /// **它此后不再证明的事**：`write_bundle` 真的会失败。那一条现在
    /// 没有任何自动化覆盖，记在 task-11-report.md 的「改什么都不会红」。
    ///
    /// 改红：把 `write_or_clean` 里那句
    /// `let _ = std::fs::remove_file(out_path);` 删掉。
    #[test]
    fn a_failed_export_leaves_no_half_filled_bundle_behind() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let target = out.join("rmc-diagnostics-1.zip");

        let err = write_or_clean(&target, |p| {
            // 先建出文件——半成品必须真的在盘上出现过，否则下面那条
            // 断言在"压根没建过"时是永远为真的空转。
            std::fs::write(p, b"PK\x03\x04 half-written")?;
            assert!(p.exists(), "夹具没能让半成品出现在盘上");
            Err(std::io::Error::other("模拟：写到一半盘满了"))
        });

        assert!(err.is_err(), "夹具没能让导出失败，下面那条断言是空转的");
        // 主断言：输出目录里一个文件都没留下。
        let left: Vec<String> = std::fs::read_dir(&out)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(left.is_empty(), "失败之后留下了缺料的半成品：{left:?}");

        // 反向自证之二：成功那一路不许把文件删掉，也要交出正确的路径。
        let ok = write_or_clean(&target, |p| std::fs::write(p, b"done")).expect("写成功了却报了错");
        assert_eq!(ok, target);
        assert_eq!(std::fs::read(&target).unwrap(), b"done");
    }

    /// **W196：单个日志文件读不出来，照样出包。**
    ///
    /// 这是上一轮（Task 10 修复轮）引入的行为回退：`std::fs::read` 上
    /// 那个 `?` 让「一个读不出来的日志文件」把**整包**判成失败，而
    /// `bundle` 随即连同已经写好的环境信息与预检结果一起删掉。
    ///
    /// Windows 上「被别的进程占住」「正在轮转」「杀软挡住」都是现场常见
    /// 形态——也就是说**最需要诊断包的那一次，恰恰是导不出来的那一次**。
    /// 而紧挨着的「整个目录列不出来」反而是宽容的，两者自相矛盾。
    ///
    /// 改红：把 `read_log_range` 那一处的 `match` 换回 `?`。
    #[test]
    fn one_unreadable_log_file_does_not_kill_the_whole_bundle() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let logs = dir.path().join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::write(logs.join("rmc-2026-09-12.log"), b"good line\n").unwrap();
        // 一个**目录**，名字却长得像日志文件：`read_dir` 会列出它，
        // 而它读不出来。这正是上一版夹具用的那一档。
        std::fs::create_dir(logs.join("rmc-2026-09-13.log")).unwrap();

        let form = crate::form::Form::default();
        let zip = export(&form, None, "客户端 0.1.0", &logs, dir.path())
            .expect("一个读不出来的日志文件不该让整包失败");

        let entries = entries_of(&zip);
        let names = names_of(&entries);
        // 读得出来的那一份照样进包了。
        assert!(
            names.contains(&"logs/rmc-2026-09-12.log"),
            "好的那份日志也没进包：{names:?}"
        );
        assert!(names.contains(&"environment.txt"));
        // 读不出来的那一份**不许静默消失**，包里要说一句。
        assert!(
            names.contains(&LOGS_INCOMPLETE),
            "少了一份日志却一声不响：{names:?}"
        );
        let note = String::from_utf8_lossy(text_of(&entries, LOGS_INCOMPLETE)).into_owned();
        assert!(
            note.contains("rmc-2026-09-13.log"),
            "说明里没点名是哪一份日志：{note}"
        );
        // 反向自证：好的那一份**不**在说明里，说明不是一条恒定的话。
        assert!(!note.contains("rmc-2026-09-12.log"), "{note}");
    }

    /// 全都读得出来的时候**不该**多出那条说明。
    ///
    /// 少了这条，上面那条在「`LOGS_INCOMPLETE` 每次都写」时也是绿的。
    #[test]
    fn a_healthy_log_directory_gets_no_incomplete_note() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let logs = dir.path().join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::write(logs.join("rmc-2026-09-12.log"), b"good line\n").unwrap();

        let form = crate::form::Form::default();
        let zip = export(&form, None, "客户端 0.1.0", &logs, dir.path()).expect("导出");
        let entries = entries_of(&zip);
        let names = names_of(&entries);
        assert!(
            !names.contains(&LOGS_INCOMPLETE),
            "什么都没少却写了一条「日志不全」：{names:?}"
        );
        assert!(names.contains(&"logs/rmc-2026-09-12.log"));
    }

    // ================= W197：诊断包的大小上限 =================

    /// 预算按**从新到旧**分配，超出的从头部丢、保留尾部。
    ///
    /// 纯函数上测，不用真造一个 500MB 的夹具（那会把开发机的盘填满，
    /// 而且慢得没法跑）。
    ///
    /// 改红：把 `plan_logs` 里 `.enumerate().rev()` 的 `.rev()` 去掉
    /// ——预算会从最老的日志开始花，盘上日志一多，**今天那一份反而进
    /// 不了包**。最后那组断言当场红。
    #[test]
    fn the_log_budget_is_spent_on_the_newest_files_first() {
        // 一个文件就超过单文件上限：只收尾部。
        let plan = plan_logs(&[("rmc-1.log".into(), LOG_ENTRY_LIMIT + 100)]);
        assert_eq!(
            plan[0].take,
            LogTake::Tail {
                bytes: LOG_ENTRY_LIMIT,
                dropped: 100
            }
        );

        // 装得下的原样收。
        let plan = plan_logs(&[("rmc-1.log".into(), 10), ("rmc-2.log".into(), 20)]);
        assert_eq!(
            plan.iter().map(|p| p.take).collect::<Vec<_>>(),
            vec![LogTake::Whole, LogTake::Whole]
        );
        // 输出顺序跟输入一致，同一份输入产出同一份包。
        assert_eq!(plan[0].name, "rmc-1.log");

        // 总预算吃紧：五个文件各占满单文件上限，总预算只够四个。
        let n = (LOG_TOTAL_BUDGET / LOG_ENTRY_LIMIT) as usize;
        assert!(n >= 2, "总预算至少要放得下两个满额文件");
        let files: Vec<(String, u64)> = (0..=n)
            .map(|i| (format!("rmc-{i}.log"), LOG_ENTRY_LIMIT))
            .collect();
        let plan = plan_logs(&files);
        // 最老的那一个被挤掉，最新的那几个都在。
        assert_eq!(plan[0].take, LogTake::Skipped, "被挤掉的不是最老的那一份");
        for p in &plan[1..] {
            assert_eq!(p.take, LogTake::Whole, "{}：新日志反而没收全", p.name);
        }
        // 收进来的总量不超过预算。
        let taken: u64 = plan
            .iter()
            .map(|p| match p.take {
                LogTake::Whole => p.size,
                LogTake::Tail { bytes, .. } => bytes,
                LogTake::Skipped => 0,
            })
            .sum();
        assert!(taken <= LOG_TOTAL_BUDGET, "{taken} 超过了总预算");
    }

    /// **一份超大的日志只有尾部进包，而且包里说清楚了。**
    ///
    /// 夹具用一个临时调小的观察口做不到（常量是编译期的），所以这里
    /// 真写一个比 [`LOG_ENTRY_LIMIT`] 大一点的文件——4MB 出头，写盘
    /// 不到一秒，跑完就扔。
    ///
    /// 改红：把 `read_log_range` 里的 `seek` 那一段删掉（永远从 0 读）
    /// ——第二条断言当场红（包里会出现开头那个金丝雀）。
    #[test]
    fn an_oversized_log_keeps_only_its_tail_and_says_so() {
        const HEAD: &str = "head-marker-8b1d2f";
        const TAIL: &str = "tail-marker-4e9c07";

        let dir = tempfile::tempdir().expect("建临时目录");
        let logs = dir.path().join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let mut body = String::with_capacity(LOG_ENTRY_LIMIT as usize + 4096);
        body.push_str(HEAD);
        while body.len() < LOG_ENTRY_LIMIT as usize + 1024 {
            body.push_str("filler line\n");
        }
        body.push_str(TAIL);
        let size = body.len() as u64;
        assert!(size > LOG_ENTRY_LIMIT, "夹具没有超过单文件上限");
        std::fs::write(logs.join("rmc-2026-09-13.log"), &body).unwrap();

        let form = crate::form::Form::default();
        let zip = export(&form, None, "客户端 0.1.0", &logs, dir.path()).expect("导出");
        let entries = entries_of(&zip);
        let kept = text_of(&entries, "logs/rmc-2026-09-13.log");

        // 收进来的不超过上限。
        assert!(
            kept.len() as u64 <= LOG_ENTRY_LIMIT,
            "收了 {} 字节，超过单文件上限 {LOG_ENTRY_LIMIT}",
            kept.len()
        );
        // 丢的是头，留的是尾——出事的记录在最后。
        assert!(
            !contains_bytes(kept, HEAD.as_bytes()),
            "整个文件都被读进来了，上限没有生效"
        );
        assert!(
            contains_bytes(kept, TAIL.as_bytes()),
            "留下的不是尾部，最近的记录被丢掉了"
        );
        // 包里说清楚少了什么。
        let note = String::from_utf8_lossy(text_of(&entries, LOGS_INCOMPLETE)).into_owned();
        assert!(note.contains("rmc-2026-09-13.log"), "{note}");
        assert!(
            note.contains(&size.to_string()),
            "说明里没写原始大小：{note}"
        );
    }

    // ================= 环境信息 =================

    #[test]
    fn the_environment_line_names_the_client_version() {
        let line = environment_line();
        assert!(
            line.contains(env!("CARGO_PKG_VERSION")),
            "环境信息里没有客户端版本：{line}"
        );
        for banned in crate::BANNED_WORDS {
            assert!(!line.contains(banned), "{line}");
        }
    }

    // ================= W160：这一页不许自己去查代理 =================

    /// **rmc-app 的整份源码里不许出现 `effective_proxy` 的调用。**
    ///
    /// W160（落实 W43）：`Transport::effective_proxy` 会在协商途中改写
    /// `ProxyEndpointRecorder`，而**没有任何测试会因此变红**。界面每重画
    /// 一帧就查一次的话，正在进行的代理认证会被悄悄搅乱。
    ///
    /// 在这条之前，这条纪律**只有一句文档**，效力完全取决于下一个人会不会
    /// 读到它——Task 10 要接的正是这一块。
    ///
    /// 扫描跳过行首是 `//` 的行，所以本模块顶部那段说明它自己不会命中；
    /// 这也意味着把调用写在一行注释里扫不到，而那样写本来就不是调用。
    ///
    /// 改红：往 `view/diagnostics.rs` 里写一行
    /// `let _ = transport.effective_proxy(gateway).await;` —— 这条当场红。
    ///
    /// **测试的名字里刻意不写那个符号**：函数名那一行不是注释，扫描器
    /// 会把它当成一处命中，测试永远红。第一次写的时候就是这么红的。
    #[test]
    fn this_crate_never_polls_the_transport_for_the_current_proxy() {
        // needle 拼出来而不是直接写成一个字面量：写成字面量的话，**这一行
        // 自己**就是一处命中，测试永远红。
        let forbidden = concat!("effective", "_proxy");
        let hits = grep_src(forbidden);
        assert!(
            hits.is_empty(),
            "rmc-app 里不许调 Transport::{forbidden}（W43/W160）：\n{}",
            hits.join("\n")
        );

        // 反向自证：扫描器真的走到了 rmc-app 的源码、真的会命中。
        // 锚点刻意选**别的文件**里的一行——选本文件里的，这个断言可以被
        // 「只扫到 diag.rs 自己写的那个字面量」满足，又是一条空转。
        let anchor = grep_src("pub const WINDOW_TITLE");
        assert!(
            anchor.iter().any(|h| h.starts_with("lib.rs:")),
            "扫描器没在 lib.rs 里找到 WINDOW_TITLE，它八成没走到 src/：{anchor:?}"
        );
    }

    /// rmc-app 的 `src/` 下含 `needle` 的**非注释行**，形如
    /// `diag.rs:123: <原文>`。
    fn grep_src(needle: &str) -> Vec<String> {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("读 src 目录") {
                let path = entry.expect("读目录项").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let rel = path
                    .strip_prefix(&root)
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                let text = std::fs::read_to_string(&path).expect("读源文件");
                for (i, line) in text.lines().enumerate() {
                    let t = line.trim_start();
                    if t.starts_with("//") {
                        continue;
                    }
                    if t.contains(needle) {
                        out.push(format!("{rel}:{}: {t}", i + 1));
                    }
                }
            }
        }
        out
    }
}
