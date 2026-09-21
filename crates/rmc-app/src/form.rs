//! 维护页的表单状态与校验。
//!
//! 按两段连接分组：维护目标只放一体机，运维服务器组只有一行——连接码
//! （地址、账号、指纹都从它解析，界面上没有分开的框）。这里**只有判断，
//! 没有控件**——见 `lib.rs` 顶部的 crate 级约定。
//!
//! # Task 8：连接码进表单
//!
//! 原来这里是四个分开的框（`gateway_host`/`gateway_port`/`username` 拼出
//! 运维服务器与账号，`appliance_host`/`appliance_port` 是一体机），运维
//! 人员现场对着一份纸条把地址、端口、账号分别抄进三个框，抄错一处就连不
//! 上却查不出哪里错。方案改成：运维服务器那三格合并成一条「连接码」，
//! 由运维一次性生成、工程师原样粘贴；地址、账号、指纹都从这一条字符串里
//! 解析出来，格式错了（粘漏、粘串）rmc-core 的校验位会当场发现，不需要
//! 工程师自己核对三个字段有没有抄对。
//!
//! 这一步（Task 8）只接线：连接码解析出来的指纹已经流到
//! `rmc_core::tunnel::TunnelParams`，但**还没有任何人核对它**——TLS 仍然
//! 只走公共 CA、SSH 仍然只走 known_hosts，指纹比对是 Task 9 的事，端口
//! 仍然是 `Config::reverse_port`（Task 10 换）。中间态在功能上自相矛盾
//! 是刻意的，只存在于这条 feature 分支。
//!
//! # W139：校验的出口带字段身份，不是一串裸字符串
//!
//! brief 原稿是 `Result<(HostPort, HostPort), Vec<&'static str>>`。那个
//! `Vec<&'static str>` **说不出是哪个框错了**，而维护页要做的正是「把出错
//! 的那个输入框标红」——视图只能拿字符串去 `contains("一体机端口")`，
//! 文案一改就悄悄失配。
//!
//! 这是同一个缺陷类在这个项目里的第四次：Task 2 的 `resolve()`（不走代理
//! vs 解析失败）、Task 3 的 `next_token()`（协商成功结束 vs 失败结束）、
//! Task 4 的 `load()`（没记住 vs 解不开）。前三次的解法都是**带类型的
//! 出口**，这次也一样：[`FieldError`] 带 [`Field`]（哪个框）与
//! [`Reason`]（为什么）。
//!
//! 成功一侧同样收紧了：返回的不是一对裸地址，而是 [`Validated`]——携带
//! 解析好的 [`ConnectionCode`] 与校验过关系的一体机地址。`rmc-core` 那个
//! 「拿到值本身就是校验通过的证据」的思路在这里体现为：`Validated` 的
//! 唯一生产入口就是 `validate()` 本身。
//!
//! # W140：语义校验只有一份，在 rmc-core
//!
//! 一体机地址是否合法（不能等于运维服务器、不能指向本机）一律**调用**
//! `rmc_core::config::ValidatedAddresses::validate`，错误文案**原样**带
//! 回来挂到字段上（[`Reason::Rejected`]）。这里不重写语义规则，只做
//! **格式解析**（字符串 → 类型）。

use rmc_core::addr::HostPort;
use rmc_core::code::ConnectionCode;
use rmc_core::config::ValidatedAddresses;
use zeroize::Zeroizing;

/// 出错的那个输入框。视图据此把对应的框标红。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    ApplianceHost,
    AppliancePort,
    /// 连接码。地址、账号、指纹都从它解析——运维服务器组现在只有这一行
    /// 输入框，见模块顶部「Task 8」一节。
    Code,
    Password,
}

impl Field {
    /// 四个字段，声明顺序即界面从上到下的顺序。
    pub const ALL: [Field; 4] = [
        Field::ApplianceHost,
        Field::AppliancePort,
        Field::Code,
        Field::Password,
    ];

    /// 输入框在界面上的名字。**这是会上屏的字符串**，所以全 crate 只有
    /// 这一份，错误文案也从这里拼——不许在别处另写一份「一体机端口」。
    pub fn label(self) -> &'static str {
        match self {
            Field::ApplianceHost => "一体机地址",
            Field::AppliancePort => "一体机端口",
            Field::Code => "连接码",
            Field::Password => "密码",
        }
    }
}

/// 一个字段为什么不合法。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// 还没填。
    Empty,
    /// 端口不是 1-65535 的整数（含 `0` 与非数字）。
    NotAPort,
    /// 主机名/IP 本身不合法，见 `rmc_core::addr` 的 `valid_host`。
    BadHost,
    /// rmc-core 拒绝了这个值——可能是 `ConnectionCode::parse`（连接码
    /// 格式、校验位、域名）或者 [`ValidatedAddresses::validate`]（地址
    /// 关系）。
    ///
    /// 文案**原样**来自 rmc-core，界面这边一个字都不重写（W140）。
    Rejected(String),
}

/// 哪个框、为什么。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    pub field: Field,
    pub reason: Reason,
}

impl FieldError {
    /// 画在界面上的那句话。
    ///
    /// 除了 [`Reason::Rejected`]，一律是「字段名 + 原因」拼出来的——
    /// 字段名只有 [`Field::label`] 一份，改标签时错误文案自动跟着变。
    pub fn message(&self) -> String {
        match &self.reason {
            Reason::Empty => format!("{}不能为空", self.field.label()),
            Reason::NotAPort => format!("{}必须是 1-65535 的整数", self.field.label()),
            Reason::BadHost => format!("{}不是合法的主机名或 IP", self.field.label()),
            // rmc-core 的原话里已经点了名，再前缀一遍字段名会变成
            // 「一体机地址配置错误：一体机地址……」。
            Reason::Rejected(m) => m.clone(),
        }
    }
}

/// 未开启页的表单状态。
///
/// [`Default`] 是**全空**：首次启动时地址栏是空的，「开启远程维护」是灰的。
/// 画板上那几个示例地址是占位示意，不是内置默认值；真正的初始值由 Task 10
/// 从配置/上次输入载入。
#[derive(Clone, Default)]
pub struct Form {
    pub appliance_host: String,
    pub appliance_port: String,
    /// 连接码原文。地址、账号、指纹都从它解析，界面上没有分开的框。
    pub code: String,
    pub password: Zeroizing<String>,
    pub remember: bool,
    /// 自动检测的出网代理，None 表示直连。不是输入项。
    pub detected_proxy: Option<String>,
}

/// W141：**手写，不许 derive。**
///
/// `Zeroizing` 的 `Debug` 是**转发**的——`zeroize-1.9.0/src/lib.rs:602` 是
/// `#[derive(Debug, Default, Eq, PartialEq)] #[repr(transparent)]
/// pub struct Zeroizing<Z>(Z)`。也就是说 `#[derive(Debug)]` 在 `Form` 上会
/// 把口令**原样打全**，而口令是这个产品唯一真正敏感的东西，这一页是它
/// 唯一的入口。`code` 不是秘密（连接码本身没有秘密，见
/// `rmc_core::code` 模块文档），照常打印。
///
/// 改红：把这个 impl 删掉换成 `#[derive(Debug)]`，
/// `debug_output_redacts_the_password` 与
/// `app_debug_output_redacts_the_password` 两条一起红。
impl std::fmt::Debug for Form {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Form")
            .field("appliance_host", &self.appliance_host)
            .field("appliance_port", &self.appliance_port)
            .field("code", &self.code)
            .field("password", &Redacted(self.password.len()))
            .field("remember", &self.remember)
            .field("detected_proxy", &self.detected_proxy)
            .finish()
    }
}

/// 口令在 `Debug` 里的替身。只说长度，不说内容——长度对排查
/// 「是不是粘进了尾随空格」有用，而它本身不足以还原口令。
struct Redacted(usize);

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted {} chars>", self.0)
    }
}

/// [`Form::validate`] 成功时给出的值：解析好的连接码 + 校验过关系的
/// 一体机地址。这是拨号（Task 10 的 `Command::Start`）真正需要的一对
/// 输入——字段私有由 [`ConnectionCode`] 自己的构造函数负责，这里不再
/// 重复；把两者装进一个结构体只是为了让 `validate()` 的成功一侧带类型,
/// 不是又一层校验。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validated {
    pub code: ConnectionCode,
    pub appliance: HostPort,
}

impl Form {
    /// 连接码解析成功时给出 [`ConnectionCode`]，供界面画只读的「地址 ·
    /// 账号」小字（[`crate::view::maintain`]）。跟 [`validate`]
    /// (Self::validate) 不同：这里不做「一体机不能等于运维服务器」那道
    /// 关系校验，只看连接码这一个字段自己合不合法——用户还没填一体机
    /// 地址时也该能看见「地址 · 账号」这行只读文字。
    pub fn parsed_code(&self) -> Option<ConnectionCode> {
        ConnectionCode::parse(self.code.trim()).ok()
    }

    /// 格式解析 + 语义校验。成功时给出 [`Validated`]，失败时给出**每个
    /// 出错字段各一条**。
    ///
    /// 错误顺序是固定的（一体机地址、一体机端口、连接码、密码、最后是
    /// rmc-core 的语义拒绝），测试因此可以整份比对，而不是只数个数
    /// （W142）。
    pub fn validate(&self) -> Result<Validated, Vec<FieldError>> {
        let mut errs = Vec::new();

        let appliance = parse_addr(
            &self.appliance_host,
            &self.appliance_port,
            Field::ApplianceHost,
            Field::AppliancePort,
            &mut errs,
        );

        let code = if self.code.trim().is_empty() {
            errs.push(FieldError {
                field: Field::Code,
                reason: Reason::Empty,
            });
            None
        } else {
            match ConnectionCode::parse(self.code.trim()) {
                Ok(c) => Some(c),
                Err(e) => {
                    errs.push(FieldError {
                        field: Field::Code,
                        reason: Reason::Rejected(e.to_string()),
                    });
                    None
                }
            }
        };

        if self.password.is_empty() {
            errs.push(FieldError {
                field: Field::Password,
                reason: Reason::Empty,
            });
        }

        // W140：语义校验不在这里重写一份,调 rmc-core。两条规则
        // （一体机不能等于运维服务器、一体机不能指向本机）都在那边,
        // 文案也在那边。这道校验以前靠 gateway_host,现在靠连接码里
        // 解析出来的 IP（`code.server()`）。
        let validated = match (appliance, code) {
            (Some(a), Some(c)) => match ValidatedAddresses::validate(c.server(), a.clone()) {
                Ok(_) => Some(Validated {
                    code: c,
                    appliance: a,
                }),
                Err(e) => {
                    // 两条规则说的都是「一体机这个地址不该是这个值」,
                    // 所以标红的是一体机地址那个框。
                    errs.push(FieldError {
                        field: Field::ApplianceHost,
                        reason: Reason::Rejected(e.to_string()),
                    });
                    None
                }
            },
            _ => None,
        };

        match validated {
            Some(v) if errs.is_empty() => Ok(v),
            _ => Err(errs),
        }
    }

    pub fn can_start(&self) -> bool {
        self.validate().is_ok()
    }

    /// 该**画到界面上**的错误：空字段不报。
    ///
    /// 空框自己看得见是空的，首次打开就糊几行红字只会挡住真正的问题；
    /// 而「开启远程维护」同时是灰的，已经说明了「还不能开始」。
    ///
    /// 这**不是第二份校验**——它是 [`validate`](Self::validate) 结果上的
    /// 一次过滤，规则只有一份。`can_start` 走的仍然是完整的 `validate`,
    /// 两者不会分叉。
    pub fn visible_errors(&self) -> Vec<FieldError> {
        self.validate()
            .err()
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e.reason != Reason::Empty)
            .collect()
    }

    /// 这个框该不该标红。跟 [`visible_errors`](Self::visible_errors) 同源。
    pub fn is_marked(&self, field: Field) -> bool {
        self.visible_errors().iter().any(|e| e.field == field)
    }

    /// 认证失败后调用，只清口令，其余已填内容保留。
    pub fn clear_password(&mut self) {
        self.password = Zeroizing::new(String::new());
    }

    pub fn egress_label(&self) -> String {
        match self.detected_proxy.as_deref() {
            Some(p) => format!("经系统代理 {p}"),
            None => "直连".to_string(),
        }
    }
}

/// 把一对「主机框 + 端口框」解析成 [`HostPort`]，出错的分别挂到各自的框上。
///
/// 主机名的合法性**与端口无关**：用一个恒定合法的端口探一次，免得端口写
/// 错时主机名的错误要等到用户改完端口的下一轮才冒出来。
fn parse_addr(
    host: &str,
    port: &str,
    host_field: Field,
    port_field: Field,
    errs: &mut Vec<FieldError>,
) -> Option<HostPort> {
    const PROBE_PORT: u16 = 1;

    let host = host.trim();
    let port = port.trim();

    let host_ok = if host.is_empty() {
        errs.push(FieldError {
            field: host_field,
            reason: Reason::Empty,
        });
        false
    } else if HostPort::new(host, PROBE_PORT).is_err() {
        errs.push(FieldError {
            field: host_field,
            reason: Reason::BadHost,
        });
        false
    } else {
        true
    };

    // `HostPort::new` 自己也拒绝 0，但那要等主机名也合法才走得到；端口
    // 框该不该标红跟主机名无关，所以在这里各判各的。
    let parsed_port = match port.parse::<u16>() {
        Ok(p) if p != 0 => Some(p),
        _ => {
            errs.push(FieldError {
                field: port_field,
                reason: if port.is_empty() {
                    Reason::Empty
                } else {
                    Reason::NotAPort
                },
            });
            None
        }
    };

    match (host_ok, parsed_port) {
        (true, Some(p)) => HostPort::new(host, p).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmc_core::banned_word_in;
    use rmc_core::code::{AccountName, ServerFingerprint};

    /// 一条能通过全部校验的连接码，账号 `tunnel-zhang`、地址
    /// `203.0.113.10:22000`。**现生成，不手写常量**——手写的校验位会算
    /// 错，而且一改格式就全废（见控制者补充）。
    fn good_code() -> String {
        ConnectionCode::new(
            AccountName::parse("tunnel-zhang").unwrap(),
            "203.0.113.10".parse().unwrap(),
            22000,
            ServerFingerprint::of_ed25519_public(&[7u8; 32]),
        )
        .expect("夹具必须合法")
        .to_string()
    }

    /// 一个能通过全部校验的表单。
    fn good() -> Form {
        Form {
            appliance_host: "192.168.1.1".into(),
            appliance_port: "61001".into(),
            code: good_code(),
            password: Zeroizing::new(CANARY.into()),
            remember: false,
            detected_proxy: None,
        }
    }

    /// W141：金丝雀必须是一个**不会偶然出现**的串。
    ///
    /// brief 原稿用的是 `"pw"`——两个字符，`format!("{f:?}")` 里随便哪个
    /// 中文标点的转义、哪个字段名都可能凑出它，而且它短到即使真的泄漏也
    /// 可能被别的内容"恰好"掩盖。这个项目的第 17 个假绿就是这个形状：
    /// 断言是对的、泄漏真的发生了，但子串匹配认不出来。
    const CANARY: &str = "canary-7f3a9e-must-never-be-printed";

    fn err_of(f: &Form) -> Vec<FieldError> {
        f.validate().expect_err("这个表单本该校验失败")
    }

    #[test]
    fn valid_form_yields_the_validated_pair() {
        let v = good().validate().expect("这个表单本该通过");
        assert_eq!(v.appliance.to_string(), "192.168.1.1:61001");
        assert_eq!(v.code.server().to_string(), "203.0.113.10:22000");
        assert_eq!(v.code.account().as_str(), "tunnel-zhang");
        assert!(good().can_start());
        assert!(good().visible_errors().is_empty());
    }

    /// 首尾空白要在解析前吃掉——现场是从邮件/聊天工具里粘贴连接码的。
    #[test]
    fn surrounding_whitespace_is_trimmed_before_parsing() {
        let mut f = good();
        f.appliance_host = "  192.168.1.1  ".into();
        f.appliance_port = " 61001 ".into();
        let code = good_code();
        f.code = format!("  {code}  ");
        let v = f.validate().expect("带空白的粘贴应当被接受");
        assert_eq!(v.appliance.to_string(), "192.168.1.1:61001");
    }

    #[test]
    fn empty_password_blocks_start_and_names_the_field() {
        let mut f = good();
        f.password = Zeroizing::new(String::new());
        assert!(!f.can_start());
        assert_eq!(
            err_of(&f),
            vec![FieldError {
                field: Field::Password,
                reason: Reason::Empty
            }]
        );
    }

    #[test]
    fn bad_appliance_port_is_reported_on_that_field() {
        let mut f = good();
        f.appliance_port = "abc".into();
        let errs = err_of(&f);
        assert_eq!(
            errs,
            vec![FieldError {
                field: Field::AppliancePort,
                reason: Reason::NotAPort
            }],
            "{errs:?}"
        );
        assert_eq!(errs[0].message(), "一体机端口必须是 1-65535 的整数");
        // 错的是端口那个框，不是地址那个框——W139 要的就是这一条。
        assert!(f.is_marked(Field::AppliancePort));
        assert!(!f.is_marked(Field::ApplianceHost));
    }

    /// `0` 能被 `parse::<u16>()` 接受，却不是一个端口。
    #[test]
    fn a_port_of_zero_is_not_a_port() {
        let mut f = good();
        f.appliance_port = "0".into();
        assert_eq!(
            err_of(&f),
            vec![FieldError {
                field: Field::AppliancePort,
                reason: Reason::NotAPort
            }]
        );
        // 65536 越界，`parse::<u16>()` 自己会拒。
        let mut f = good();
        f.appliance_port = "65536".into();
        assert_eq!(err_of(&f)[0].field, Field::AppliancePort);
        // 边界两端都要能过。
        let mut f = good();
        f.appliance_port = "65535".into();
        assert!(f.can_start());
        f.appliance_port = "1".into();
        assert!(f.can_start());
    }

    /// 主机名坏了 + 端口也坏了，两个框各报各的，不许互相掩盖。
    #[test]
    fn a_broken_host_and_a_broken_port_are_reported_together() {
        let mut f = good();
        f.appliance_host = "bad host".into();
        f.appliance_port = "x".into();
        assert_eq!(
            err_of(&f),
            vec![
                FieldError {
                    field: Field::ApplianceHost,
                    reason: Reason::BadHost
                },
                FieldError {
                    field: Field::AppliancePort,
                    reason: Reason::NotAPort
                },
            ]
        );
    }

    /// 连接码格式错，红字指向连接码这一框，而且是 rmc-core 给的那句话。
    ///
    /// 改红：`validate` 里把 `CodeError` 的文案换成一句固定的话——比如
    /// 把 `Reason::Rejected(e.to_string())` 换成
    /// `Reason::Rejected("坏了".into())`。
    #[test]
    fn a_bad_code_marks_the_code_field_with_the_parser_message() {
        let mut f = good();
        f.code = "rmc1:nonsense".into();
        let errs = f.visible_errors();
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].field, Field::Code);
        match &errs[0].reason {
            Reason::Rejected(msg) => {
                assert!(msg.contains("格式不对"), "{msg}");
                assert_eq!(banned_word_in(msg), None, "{msg}");
            }
            r => panic!("{r:?}"),
        }
    }

    #[test]
    fn a_domain_in_the_code_is_refused_with_the_dedicated_text() {
        let mut f = good();
        // 校验位随之失效——先撞 Checksum，也是 Rejected，但仍然标在
        // 连接码这一框上，且不含禁用词。
        f.code = good_code().replace("203.0.113.10", "ops.example.com");
        assert!(f.is_marked(Field::Code));
        let errs = err_of(&f);
        match &errs
            .iter()
            .find(|e| e.field == Field::Code)
            .expect("连接码框该标红")
            .reason
        {
            Reason::Rejected(msg) => assert_eq!(banned_word_in(msg), None, "{msg}"),
            r => panic!("{r:?}"),
        }
    }

    #[test]
    fn empty_code_blocks_start_silently_like_the_other_empty_fields() {
        let mut f = good();
        f.code.clear();
        assert!(!f.can_start());
        assert!(f.visible_errors().is_empty(), "空着不标红");
    }

    /// 一体机地址不能等于运维服务器地址——这条校验以前靠 gateway_host,
    /// 现在靠连接码里的 IP。
    #[test]
    fn appliance_equal_to_the_server_in_the_code_is_rejected() {
        let mut f = good();
        f.appliance_host = "203.0.113.10".into();
        f.appliance_port = "22000".into();
        assert!(f.is_marked(Field::ApplianceHost));
    }

    #[test]
    fn parsed_code_exposes_address_and_account_for_the_read_only_line() {
        let f = good();
        let c = f.parsed_code().expect("好的连接码");
        assert_eq!(c.account().as_str(), "tunnel-zhang");
        assert_eq!(c.server().to_string(), "203.0.113.10:22000");
        let mut bad = f.clone();
        bad.code = "x".into();
        assert!(bad.parsed_code().is_none());
    }

    /// W140：语义校验只有一份，在 rmc-core。
    ///
    /// 断言的是**文案逐字等于 rmc-core 的原话**，不是「包含某几个字」——
    /// 一旦有人在这边重写一份（哪怕只是措辞不同），这条立刻红。
    #[test]
    fn a_loopback_appliance_is_rejected_by_rmc_core_verbatim() {
        let mut f = good();
        f.appliance_host = "127.0.0.1".into();
        let errs = err_of(&f);

        let from_core = ValidatedAddresses::validate(
            "203.0.113.10:22000".parse().unwrap(),
            "127.0.0.1:61001".parse().unwrap(),
        )
        .expect_err("rmc-core 本该拒绝回环一体机")
        .to_string();

        assert_eq!(
            errs,
            vec![FieldError {
                field: Field::ApplianceHost,
                reason: Reason::Rejected(from_core.clone())
            }]
        );
        assert_eq!(errs[0].message(), from_core);
        assert_eq!(banned_word_in(&from_core), None);
    }

    /// W140 的另一半：容易漏掉的第二条规则。
    ///
    /// 自己重写一份校验最会漏的就是它——而它正是「运维服务器」这个词在
    /// rmc-core 里的落点（`一体机地址不能与运维服务器地址相同`）。
    #[test]
    fn an_appliance_equal_to_the_server_is_rejected_by_rmc_core_verbatim() {
        let mut f = good();
        f.appliance_host = "203.0.113.10".into();
        f.appliance_port = "22000".into();
        let errs = err_of(&f);

        let from_core = ValidatedAddresses::validate(
            "203.0.113.10:22000".parse().unwrap(),
            "203.0.113.10:22000".parse().unwrap(),
        )
        .expect_err("rmc-core 本该拒绝一体机与运维服务器同地址")
        .to_string();

        assert_eq!(
            errs,
            vec![FieldError {
                field: Field::ApplianceHost,
                reason: Reason::Rejected(from_core.clone())
            }]
        );
        assert!(from_core.contains("运维服务器"), "{from_core}");
        assert_eq!(banned_word_in(&from_core), None);
    }

    /// W142：brief 原稿是 `unwrap_err().len() >= 3`——只数个数，
    /// 返回十条无关错误也能过。这里整份比对。
    #[test]
    fn all_errors_are_reported_at_once() {
        let mut f = good();
        f.appliance_port = "0".into();
        f.code = "rmc1:nonsense".into();
        f.password = Zeroizing::new(String::new());
        assert_eq!(
            err_of(&f),
            vec![
                FieldError {
                    field: Field::AppliancePort,
                    reason: Reason::NotAPort
                },
                FieldError {
                    field: Field::Code,
                    reason: Reason::Rejected(
                        ConnectionCode::parse("rmc1:nonsense")
                            .unwrap_err()
                            .to_string()
                    )
                },
                FieldError {
                    field: Field::Password,
                    reason: Reason::Empty
                },
            ]
        );
    }

    #[test]
    fn clear_password_empties_it_and_keeps_everything_else() {
        let mut f = good();
        f.remember = true;
        let code_before = f.code.clone();
        f.clear_password();
        assert!(f.password.is_empty());
        assert_eq!(f.code, code_before);
        assert_eq!(f.appliance_host, "192.168.1.1");
        assert!(f.remember, "「记住密码」这个勾不该被一起清掉");
        assert!(!f.can_start(), "口令清了就不该还能开始");
    }

    #[test]
    fn egress_label_names_the_proxy_when_detected() {
        let mut f = good();
        f.detected_proxy = Some("proxy.company.com:8080".into());
        assert_eq!(f.egress_label(), "经系统代理 proxy.company.com:8080");
    }

    #[test]
    fn egress_label_says_direct_when_no_proxy() {
        assert_eq!(good().egress_label(), "直连");
    }

    /// W141：口令不许进 `Debug`。
    ///
    /// 金丝雀是一个独特串，不是 brief 那个两字符的 `"pw"`。
    /// 改红：把 `impl Debug for Form` 删掉换成 `#[derive(Debug)]`——
    /// `Zeroizing` 的 `Debug` 是转发的，口令会被原样打全。
    #[test]
    fn debug_output_redacts_the_password() {
        let f = good();
        let dumped = format!("{f:?}");

        // 反向自证：`Debug` 真的印了东西、真的走到了这个结构体。
        // 少了这一步，一个 `write!(f, "")` 的空实现也能让下面全绿。
        assert!(dumped.contains("Form"), "{dumped}");
        assert!(dumped.contains("tunnel-zhang"), "{dumped}");
        assert!(dumped.contains("192.168.1.1"), "{dumped}");
        assert!(
            dumped.contains("password"),
            "口令字段本身得在，只是内容要遮住"
        );

        assert!(!dumped.contains(CANARY), "口令原样进了 Debug：{dumped}");
        // 连片段都不许有。
        assert!(!dumped.contains("7f3a9e"), "口令片段进了 Debug：{dumped}");
        assert!(dumped.contains("<redacted"), "{dumped}");

        // `{:#?}`（多行展开）走的是同一个 impl，但真出过「只测了一种
        // 格式」的漏。
        let pretty = format!("{f:#?}");
        assert!(!pretty.contains(CANARY), "{pretty}");
    }

    /// 口令也不许经 `Clone` 之外的任何顺手路径漏出去：表单被整份
    /// `Clone` 之后，副本的 `Debug` 同样得是遮住的。
    #[test]
    fn a_cloned_form_redacts_its_password_too() {
        let f = good().clone();
        assert!(!format!("{f:?}").contains(CANARY));
        assert_eq!(*f.password, CANARY, "内容本身得原样克隆过来");
    }

    /// 四个字段一个槽位。**穷尽 match**：往 `Field` 加变体时这里直接
    /// 编译不过；补一个 `=> 4` 又会让 `[false; 4]` 越界。
    fn field_index(f: Field) -> usize {
        match f {
            Field::ApplianceHost => 0,
            Field::AppliancePort => 1,
            Field::Code => 2,
            Field::Password => 3,
        }
    }

    #[test]
    fn field_all_lists_every_variant_exactly_once() {
        let mut seen = [false; 4];
        for f in Field::ALL {
            let i = field_index(f);
            assert!(!seen[i], "第 {i} 个字段在 ALL 里出现了两次");
            seen[i] = true;
        }
        for (i, hit) in seen.iter().enumerate() {
            assert!(*hit, "第 {i} 个字段没进 Field::ALL");
        }
    }

    /// W138 在 rmc-app 这一侧的第一道闸：**每个字段名、每条错误文案**都
    /// 不许出现禁用词。源码扫描在 `tests/wording.rs`，这条是按值走一遍。
    #[test]
    fn no_field_label_or_error_message_says_banned_words() {
        // 反向自证：匹配器真的会发火。
        assert_eq!(banned_word_in("Gateway 地址"), Some("Gateway"));

        let rejected = ValidatedAddresses::validate(
            "203.0.113.10:22000".parse().unwrap(),
            "127.0.0.1:61001".parse().unwrap(),
        )
        .expect_err("本该被拒")
        .to_string();

        for field in Field::ALL {
            assert!(!field.label().is_empty(), "{field:?} 的标签是空串");
            assert_eq!(banned_word_in(field.label()), None, "{field:?} 的标签");
            for reason in [
                Reason::Empty,
                Reason::NotAPort,
                Reason::BadHost,
                Reason::Rejected(rejected.clone()),
            ] {
                let e = FieldError { field, reason };
                assert!(!e.message().is_empty(), "{e:?} 的文案是空串");
                assert_eq!(banned_word_in(&e.message()), None, "{e:?}");
            }
        }
    }

    /// 空字段不画红字，但仍然拦着「开启」；填错的字段两件事都做。
    #[test]
    fn empty_fields_are_blocking_but_not_shouted_about() {
        let blank = Form::default();
        assert!(!blank.can_start(), "全空的表单不该能开始");
        assert!(
            blank.visible_errors().is_empty(),
            "首次打开不该糊一屏红字：{:?}",
            blank.visible_errors()
        );
        for field in Field::ALL {
            assert!(!blank.is_marked(field), "{field:?} 在全空时被标红了");
        }
        // 反向自证：`visible_errors` 不是恒空。
        let mut f = good();
        f.appliance_port = "abc".into();
        assert_eq!(f.visible_errors().len(), 1, "{:?}", f.visible_errors());
        assert!(f.is_marked(Field::AppliancePort));

        // 一个空框 + 一个填错的框：只画填错的那条，但两条都拦着开始。
        let mut f = good();
        f.appliance_port = "abc".into();
        f.password = Zeroizing::new(String::new());
        assert_eq!(f.validate().unwrap_err().len(), 2);
        assert_eq!(f.visible_errors().len(), 1);
        assert_eq!(f.visible_errors()[0].field, Field::AppliancePort);
        assert!(!f.can_start());
    }

    /// `can_start` 与 `validate` 必须是同一件事的两种问法。
    #[test]
    fn can_start_never_disagrees_with_validate() {
        let mutations: [fn(&mut Form); 5] = [
            |f| f.password = Zeroizing::new(String::new()),
            |f| f.appliance_port = "0".into(),
            |f| f.code = "rmc1:nonsense".into(),
            |f| f.appliance_host = "127.0.0.1".into(),
            |f| f.code.clear(),
        ];
        let mut cases = vec![Form::default(), good()];
        for mutate in mutations {
            let mut f = good();
            mutate(&mut f);
            cases.push(f);
        }
        let mut ok_seen = false;
        let mut err_seen = false;
        for f in cases {
            assert_eq!(f.can_start(), f.validate().is_ok(), "{f:?}");
            if f.can_start() {
                ok_seen = true;
            } else {
                err_seen = true;
            }
        }
        // 两侧都得真的出现过，否则上面那圈断言可以被「恒 false」糊过去。
        assert!(ok_seen && err_seen);
    }
}
