//! 维护页的表单状态与校验。
//!
//! 按两段连接分组：维护目标只放一体机，运维服务器组含地址、出网、账号、
//! 口令。这里**只有判断，没有控件**——见 `lib.rs` 顶部的 crate 级约定。
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
//! 成功一侧同样收紧了：返回的不是一对裸 [`HostPort`]，而是
//! [`ValidatedAddresses`]——rmc-core 那个「拿到值本身就是校验通过的证据」
//! 的类型。Task 10 的 Supervisor 需要的正是它，中间不再有一个「拿着两个
//! 裸地址、还能绕开校验」的形态。
//!
//! # W140：语义校验只有一份，在 rmc-core
//!
//! brief 让这里自己重写「一体机不能指向本机」。那会造出第二份真相：
//!
//! - 规则会漂移。rmc-core 的 [`ValidatedAddresses::validate`] 其实有**两**
//!   条规则（还有「一体机不能与运维服务器同地址」），brief 只抄了一条。
//! - **重写就会把刚被 W125 清掉的那个词写回来**：rmc-core 现在的原话是
//!   「一体机地址不能与运维服务器地址相同」，照着 brief 的思路重写一份，
//!   十有八九写成带 Gateway 的版本。
//!
//! 所以这里只做**格式解析**（字符串 → [`HostPort`]），语义校验一律
//! **调用** rmc-core，错误文案**原样**带回来挂到字段上
//! （[`Reason::Rejected`]）。

use rmc_core::addr::HostPort;
use rmc_core::config::ValidatedAddresses;
use zeroize::Zeroizing;

/// 出错的那个输入框。视图据此把对应的框标红。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    ApplianceHost,
    AppliancePort,
    /// 运维服务器地址。**标识符沿用 rmc-core 的 `gateway`**（`Config::gateway`、
    /// `ValidatedAddresses::gateway()`），需求禁的是**界面上的字**，见
    /// [`Field::label`]。
    GatewayHost,
    GatewayPort,
    Username,
    Password,
}

impl Field {
    /// 六个字段，声明顺序即界面从上到下的顺序。
    pub const ALL: [Field; 6] = [
        Field::ApplianceHost,
        Field::AppliancePort,
        Field::GatewayHost,
        Field::GatewayPort,
        Field::Username,
        Field::Password,
    ];

    /// 输入框在界面上的名字。**这是会上屏的字符串**，所以全 crate 只有
    /// 这一份，错误文案也从这里拼——不许在别处另写一份「一体机端口」。
    pub fn label(self) -> &'static str {
        match self {
            Field::ApplianceHost => "一体机地址",
            Field::AppliancePort => "一体机端口",
            Field::GatewayHost => "运维服务器地址",
            Field::GatewayPort => "运维服务器端口",
            Field::Username => "账号",
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
    /// rmc-core 的 [`ValidatedAddresses::validate`] 拒绝了这对地址。
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
            // rmc-core 的原话里已经点了名（「一体机地址不能……」），
            // 再前缀一遍字段名会变成「一体机地址配置错误：一体机地址……」。
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
    pub gateway_host: String,
    pub gateway_port: String,
    pub username: String,
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
/// 唯一的入口。
///
/// 改红：把这个 impl 删掉换成 `#[derive(Debug)]`，
/// `debug_output_redacts_the_password` 与
/// `app_debug_output_redacts_the_password` 两条一起红。
impl std::fmt::Debug for Form {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Form")
            .field("appliance_host", &self.appliance_host)
            .field("appliance_port", &self.appliance_port)
            .field("gateway_host", &self.gateway_host)
            .field("gateway_port", &self.gateway_port)
            .field("username", &self.username)
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

impl Form {
    /// 格式解析 + 语义校验。成功时给出 rmc-core 的
    /// [`ValidatedAddresses`]，失败时给出**每个出错字段各一条**。
    ///
    /// 错误顺序是固定的（一体机地址、一体机端口、运维服务器地址、
    /// 运维服务器端口、账号、密码、最后是 rmc-core 的语义拒绝），
    /// 测试因此可以整份比对，而不是只数个数（W142）。
    pub fn validate(&self) -> Result<ValidatedAddresses, Vec<FieldError>> {
        let mut errs = Vec::new();

        let appliance = parse_addr(
            &self.appliance_host,
            &self.appliance_port,
            Field::ApplianceHost,
            Field::AppliancePort,
            &mut errs,
        );
        let gateway = parse_addr(
            &self.gateway_host,
            &self.gateway_port,
            Field::GatewayHost,
            Field::GatewayPort,
            &mut errs,
        );

        if self.username.trim().is_empty() {
            errs.push(FieldError {
                field: Field::Username,
                reason: Reason::Empty,
            });
        }
        if self.password.is_empty() {
            errs.push(FieldError {
                field: Field::Password,
                reason: Reason::Empty,
            });
        }

        // W140：语义校验不在这里重写一份，调 rmc-core。两条规则
        // （一体机不能等于运维服务器、一体机不能指向本机）都在那边，
        // 文案也在那边。
        let validated = match (appliance, gateway) {
            (Some(a), Some(g)) => match ValidatedAddresses::validate(g, a) {
                Ok(v) => Some(v),
                Err(e) => {
                    // 两条规则说的都是「一体机这个地址不该是这个值」，
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
    /// 空框自己看得见是空的，首次打开就糊六行红字只会挡住真正的问题；
    /// 而「开启远程维护」同时是灰的，已经说明了「还不能开始」。
    ///
    /// 这**不是第二份校验**——它是 [`validate`](Self::validate) 结果上的
    /// 一次过滤，规则只有一份。`can_start` 走的仍然是完整的 `validate`，
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

    /// 一个能通过全部校验的表单。
    ///
    /// 地址刻意不用画板里那个 `gateway.company.com`：它含禁用词，
    /// rmc-core 为它开了一条明确的豁免（那是**数据**，是方案设计.md
    /// §3.10 的示意域名），但没有理由把这个豁免再复制到界面 crate 来。
    fn good() -> Form {
        Form {
            appliance_host: "192.168.100.10".into(),
            appliance_port: "61001".into(),
            gateway_host: "ops.example.com".into(),
            gateway_port: "443".into(),
            username: "tunnel-zhang".into(),
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
        assert_eq!(v.appliance().to_string(), "192.168.100.10:61001");
        assert_eq!(v.gateway().to_string(), "ops.example.com:443");
        assert!(good().can_start());
        assert!(good().visible_errors().is_empty());
    }

    /// 首尾空白要在解析前吃掉——现场是从邮件里粘贴地址的。
    #[test]
    fn surrounding_whitespace_is_trimmed_before_parsing() {
        let mut f = good();
        f.appliance_host = "  192.168.100.10  ".into();
        f.appliance_port = " 61001 ".into();
        let v = f.validate().expect("带空白的粘贴应当被接受");
        assert_eq!(v.appliance().to_string(), "192.168.100.10:61001");
    }

    #[test]
    fn empty_username_blocks_start_and_names_the_field() {
        let mut f = good();
        f.username.clear();
        assert!(!f.can_start());
        assert_eq!(
            err_of(&f),
            vec![FieldError {
                field: Field::Username,
                reason: Reason::Empty
            }]
        );
        // 只填空格也算空。
        f.username = "   ".into();
        assert!(!f.can_start());
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
        f.gateway_port = "0".into();
        assert_eq!(
            err_of(&f),
            vec![FieldError {
                field: Field::GatewayPort,
                reason: Reason::NotAPort
            }]
        );
        // 65536 越界，`parse::<u16>()` 自己会拒。
        let mut f = good();
        f.gateway_port = "65536".into();
        assert_eq!(err_of(&f)[0].field, Field::GatewayPort);
        // 边界两端都要能过。
        let mut f = good();
        f.gateway_port = "65535".into();
        assert!(f.can_start());
        f.gateway_port = "1".into();
        assert!(f.can_start());
    }

    /// W138：brief 原稿这条断言的是 `e.contains("Gateway 地址")`——
    /// 一条**会上屏**的用户可见字符串，里面是需求明令禁止的词。
    #[test]
    fn bad_server_host_is_reported_on_that_field_without_the_banned_word() {
        let mut f = good();
        f.gateway_host = "gate way".into();
        let errs = err_of(&f);
        assert_eq!(
            errs,
            vec![FieldError {
                field: Field::GatewayHost,
                reason: Reason::BadHost
            }],
            "{errs:?}"
        );
        assert_eq!(errs[0].message(), "运维服务器地址不是合法的主机名或 IP");
        assert_eq!(banned_word_in(&errs[0].message()), None);
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
            "ops.example.com:443".parse().unwrap(),
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

    /// W140 的另一半：brief 根本没抄的那条规则。
    ///
    /// 自己重写一份校验最会漏的就是它——而它正是「运维服务器」这个词在
    /// rmc-core 里的落点（`一体机地址不能与运维服务器地址相同`）。
    #[test]
    fn an_appliance_equal_to_the_server_is_rejected_by_rmc_core_verbatim() {
        let mut f = good();
        f.appliance_host = "ops.example.com".into();
        f.appliance_port = "443".into();
        let errs = err_of(&f);

        let from_core = ValidatedAddresses::validate(
            "ops.example.com:443".parse().unwrap(),
            "ops.example.com:443".parse().unwrap(),
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
        f.username.clear();
        f.appliance_port = "0".into();
        f.gateway_host = "bad host".into();
        assert_eq!(
            err_of(&f),
            vec![
                FieldError {
                    field: Field::AppliancePort,
                    reason: Reason::NotAPort
                },
                FieldError {
                    field: Field::GatewayHost,
                    reason: Reason::BadHost
                },
                FieldError {
                    field: Field::Username,
                    reason: Reason::Empty
                },
            ]
        );
    }

    #[test]
    fn clear_password_empties_it_and_keeps_everything_else() {
        let mut f = good();
        f.remember = true;
        f.clear_password();
        assert!(f.password.is_empty());
        assert_eq!(f.username, "tunnel-zhang");
        assert_eq!(f.appliance_host, "192.168.100.10");
        assert_eq!(f.gateway_host, "ops.example.com");
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
        assert!(dumped.contains("192.168.100.10"), "{dumped}");
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

    /// 六个字段一个槽位。**穷尽 match**：往 `Field` 加变体时这里直接
    /// 编译不过；补一个 `=> 6` 又会让 `[false; 6]` 越界。
    fn field_index(f: Field) -> usize {
        match f {
            Field::ApplianceHost => 0,
            Field::AppliancePort => 1,
            Field::GatewayHost => 2,
            Field::GatewayPort => 3,
            Field::Username => 4,
            Field::Password => 5,
        }
    }

    #[test]
    fn field_all_lists_every_variant_exactly_once() {
        let mut seen = [false; 6];
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
            "ops.example.com:443".parse().unwrap(),
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
        f.username.clear();
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
            |f| f.gateway_host = "bad host".into(),
            |f| f.appliance_host = "127.0.0.1".into(),
            |f| f.username.clear(),
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
