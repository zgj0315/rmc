//! 「记住密码」的接线。
//!
//! # W200：Task 4 做完的零件，到这一轮才有生产调用方
//!
//! Task 4 把 DPAPI 密封、[`FileSecretStore`](rmc_win::secret::FileSecretStore)、
//! 以及**四种取回失败的分类**（[`LoadOutcome`]）全做完了，105 条测试；
//! Task 10 把落点（`AppPaths::secrets_dir`）与 `Core::secrets` 也造了
//! 出来。但 rmc-app 里**一个生产读方都没有**——维护页上那个「记住密码」
//! 勾选框至今什么都不做，勾了也白勾。
//!
//! 这一轮接三处：
//!
//! 1. 连接成功且勾了「记住密码」→ 按 `账号@运维服务器` 存进
//!    [`SecretStore`]（[`save`]）；
//! 2. 启动时按同一个 key 取回、填进密码框（[`recall`] + [`Recall::fill`]）；
//! 3. **取回失败时把 Task 4 那四种分类的诊断话画在密码框旁**——那正是
//!    W21 当初要求带类型出口的全部意义（「换了 Windows 账号解不开」这句话
//!    得有地方显示）。
//!
//! # 为什么还要多存一个 `last-account.txt`
//!
//! key 是 `账号@运维服务器主机:端口`，而 [`Form::default`] 是**全空的**
//! ——启动那一刻我们根本不知道 key 是什么，第 2 条于是无从谈起。
//! [`FileSecretStore`](rmc_win::secret::FileSecretStore) 又把 key 哈希成
//! 文件名，盘上也反查不回来。
//!
//! 所以存一份**不含任何秘密**的账号记录（账号名 + 运维服务器地址，三行
//! 纯文本）在应用目录下。这三样本来就是用户下次还得再敲一遍的东西，
//! 「记住密码」在用户心里本来也包含「记住我连的是哪台」。
//!
//! **口令一个字节都不在这个文件里**，`account_file_never_carries_the_password`
//! 守这条。
//!
//! # 口令全程只走 `Zeroizing<String>`
//!
//! [`Recall::fill`] 消费 `self`（而不是借用）就是为了把
//! [`LoadOutcome::Loaded`] 里那一份**移动**进 [`Form::password`]，中间
//! 不产生第二份拷贝。

use crate::form::Form;
use crate::wiring::AppPaths;
use rmc_win::secret::{LoadOutcome, SecretStore};

/// 记住密码的那个账号。**不含口令。**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub username: String,
    /// 运维服务器主机名或 IP。
    pub host: String,
    /// 运维服务器端口，原样保存用户敲的那个串。
    pub port: String,
}

impl Account {
    /// 从表单上取。三样里有一样是空的就没有账号可记——**不拼一个半截
    /// 的 key**，那会让「记住」与「取回」用的 key 对不上。
    pub fn from_form(form: &Form) -> Option<Self> {
        let username = form.username.trim();
        let host = form.gateway_host.trim();
        let port = form.gateway_port.trim();
        if username.is_empty() || host.is_empty() || port.is_empty() {
            return None;
        }
        Some(Self {
            username: username.to_string(),
            host: host.to_string(),
            port: port.to_string(),
        })
    }

    /// 存进 [`SecretStore`] 用的 key：`账号@运维服务器主机:端口`。
    ///
    /// 形状跟 Task 4 文档里写的那个例子一致
    /// （`tunnel-zhang@…:443`）——换一台运维服务器、换一个账号就是另一份
    /// 记录，互不覆盖。
    pub fn key(&self) -> String {
        format!("{}@{}:{}", self.username, self.host, self.port)
    }

    /// 写进 `last-account.txt` 的内容：三行，一行一样。
    ///
    /// 不用 key 那个单行形式反过来解析：账号名里可以有 `@`，主机名里
    /// 可以有 `:`（IPv6），反解析要么容易出错、要么得再定一套转义规则。
    /// 三行纯文本没有这些问题。
    pub fn encode(&self) -> String {
        format!("{}\n{}\n{}\n", self.username, self.host, self.port)
    }

    /// 读回来。格式不对返回 `None`——**不猜**，猜出来的账号会去取一份
    /// 不存在的密码，然后在密码框旁边写一句莫名其妙的话。
    pub fn decode(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        let username = lines.next()?.trim().to_string();
        let host = lines.next()?.trim().to_string();
        let port = lines.next()?.trim().to_string();
        if username.is_empty() || host.is_empty() || port.is_empty() {
            return None;
        }
        Some(Self {
            username,
            host,
            port,
        })
    }
}

/// 一次「记住 / 不再记住」的结局。
///
/// 带类型，不是 `io::Result<()>`（W193 那一串）：调用方要分得清
/// 「存好了」「按用户的意思清掉了」「表单还不够拼出 key」三件事，
/// 而它们在 `Ok(())` 里是同一个值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveOutcome {
    /// 已经按这个 key 记住了。
    Saved { key: String },
    /// 用户没勾（或者取消了勾选）：密文与账号记录都清掉了。
    Cleared,
    /// 表单上还拼不出 key（账号或运维服务器地址是空的），或者口令是空的。
    /// 什么都没做。
    Incomplete,
    /// 出错了。**不静默吞掉**——记住密码失败而用户以为记住了，下次启动
    /// 会莫名其妙地要他重新输入。带的是 `io::Error` 的说明，不含口令。
    Failed(String),
}

/// 连接成功之后调用：按「记住密码」的勾决定存还是清。
///
/// **只在连接成功之后调**：口令没被运维服务器验过就存下来，等于把一个
/// 打错的口令记一年。
pub fn save(paths: &AppPaths, store: &dyn SecretStore, form: &Form) -> SaveOutcome {
    let Some(account) = Account::from_form(form) else {
        return SaveOutcome::Incomplete;
    };
    let key = account.key();

    if !form.remember {
        // 取消勾选（或者从来没勾）：两样都清掉。Task 4 的 `clear` 会连
        // 写到一半留下的 `.tmp` 一起删（W25）。
        return match clear(paths, store, &key) {
            Ok(()) => SaveOutcome::Cleared,
            Err(e) => SaveOutcome::Failed(e.to_string()),
        };
    }

    if form.password.is_empty() {
        return SaveOutcome::Incomplete;
    }

    if let Err(e) = store.save(&key, &form.password) {
        return SaveOutcome::Failed(e.to_string());
    }
    // 账号记录**后写**：密文没存成就不该留下一条指向它的账号记录，
    // 否则下次启动会取到 `NotRemembered` 并在密码框旁边说一句
    // 「这台机器上没有记住过密码」，而用户明明勾了。
    if let Err(e) = write_account(paths, &account) {
        // 密文已经写进去了，但账号记录写不成——把密文也清掉，不留一份
        // 谁也找不回来的孤儿密文。
        let _ = store.clear(&key);
        return SaveOutcome::Failed(e.to_string());
    }
    SaveOutcome::Saved { key }
}

/// 把密文与账号记录都清掉。
fn clear(paths: &AppPaths, store: &dyn SecretStore, key: &str) -> std::io::Result<()> {
    // 两步都走完再报第一个错——半路 return 会留下另一半（同 Task 4 的
    // `SecretStore::clear` 自己那条 W25）。
    let secret = store.clear(key);
    let account = match std::fs::remove_file(paths.last_account()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    };
    secret.and(account)
}

fn write_account(paths: &AppPaths, account: &Account) -> std::io::Result<()> {
    std::fs::create_dir_all(paths.root())?;
    std::fs::write(paths.last_account(), account.encode())
}

/// 启动时取回的结局。
///
/// 两个变体，不是一个 `Option<LoadOutcome>`：「这台机器上从来没记过
/// 账号」与「记过，但取回时出了事」要显示的东西完全不同。
#[derive(Debug)]
pub enum Recall {
    /// 没有账号记录——第一次运行，或者用户取消过勾选。
    NoAccount,
    /// 记过这个账号；密码取回的结局见 `outcome`。
    Remembered {
        account: Account,
        outcome: LoadOutcome,
    },
}

/// 启动时按上次记下的账号取回密码。
pub fn recall(paths: &AppPaths, store: &dyn SecretStore) -> Recall {
    let Ok(text) = std::fs::read_to_string(paths.last_account()) else {
        return Recall::NoAccount;
    };
    let Some(account) = Account::decode(&text) else {
        tracing::warn!("账号记录的格式不对，当作没有记过");
        return Recall::NoAccount;
    };
    let outcome = store.load_outcome(&account.key());
    Recall::Remembered { account, outcome }
}

impl Recall {
    /// 把取回的东西填进表单，交出**密码框旁边要画的那句话**。
    ///
    /// 消费 `self`：[`LoadOutcome::Loaded`] 里那一份
    /// `Zeroizing<String>` 直接**移动**进 [`Form::password`]，中间不产生
    /// 第二份口令拷贝。
    ///
    /// 四种失败分类各说各的话（W21 / W200 第 3 条）——尤其是
    /// [`LoadOutcome::UnsealFailed`]，它就是「换了 Windows 账号 / 换了
    /// 机器」那一格，以前跟「没记过」一样只是一个 `None`，密码框空着
    /// 而一句解释都没有。
    ///
    /// 取回成功那一格也说一句：它同时告诉用户「这个口令还没经过运维
    /// 服务器验证」。
    pub fn fill(self, form: &mut Form) -> Option<String> {
        let Recall::Remembered { account, outcome } = self else {
            return None;
        };
        // 账号与运维服务器地址无论口令取没取回来都填上——用户下次还得
        // 敲它们，而且密码框旁边那句话说的正是「这台运维服务器」。
        form.username = account.username;
        form.gateway_host = account.host;
        form.gateway_port = account.port;
        // 勾上：用户上次确实勾了。取回失败时也勾着，这样他重新输入之后
        // 连上，会按同一个 key 再记一次。
        form.remember = true;

        let (_, note) = outcome.diagnostic();
        if let Some(secret) = outcome.into_secret() {
            form.password = secret;
        }
        Some(note)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmc_win::secret::{FileSecretStore, Sealer};
    use std::sync::Arc;
    use zeroize::Zeroizing;

    /// 口令的金丝雀。独特串，不是两个字符——本项目第 17 个假绿就是
    /// 「短金丝雀在长输出里碰巧被掩盖」。
    const CANARY: &str = "canary-9d41c7-remembered-password";

    /// 可逆的假密封器（字节取反），验存储层逻辑用。
    struct FlipSealer;

    impl Sealer for FlipSealer {
        fn seal(&self, plain: &[u8]) -> Option<Vec<u8>> {
            Some(plain.iter().map(|b| !b).collect())
        }
        fn unseal(&self, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
            Some(Zeroizing::new(sealed.iter().map(|b| !b).collect()))
        }
    }

    /// 解不开——「换了 Windows 账号」那一格。
    struct BrokenSealer;

    impl Sealer for BrokenSealer {
        fn seal(&self, plain: &[u8]) -> Option<Vec<u8>> {
            Some(plain.to_vec())
        }
        fn unseal(&self, _sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
            None
        }
    }

    fn store_at<S: Sealer + 'static>(paths: &AppPaths, sealer: S) -> Arc<dyn SecretStore> {
        Arc::new(FileSecretStore::new(paths.secrets_dir(), Box::new(sealer)))
    }

    fn filled_form() -> Form {
        Form {
            appliance_host: "192.168.100.10".into(),
            appliance_port: "61001".into(),
            gateway_host: "ops.example.com".into(),
            gateway_port: "443".into(),
            username: "tunnel-zhang".into(),
            password: Zeroizing::new(CANARY.into()),
            remember: true,
            detected_proxy: None,
        }
    }

    // ================= key 与账号记录 =================

    /// key 就是 `账号@运维服务器主机:端口`。
    ///
    /// 改红：把 `key()` 里的 `@` 换成别的分隔符，或者把 host 与
    /// username 对调——这条逐字比对，当场红。
    #[test]
    fn the_key_is_the_account_at_the_server() {
        let a = Account::from_form(&filled_form()).expect("表单填满了，该有账号");
        assert_eq!(a.key(), "tunnel-zhang@ops.example.com:443");
    }

    /// 三样里缺一样就没有 key，**不拼半截的**。
    #[test]
    fn an_incomplete_form_has_no_account() {
        for wreck in [
            |f: &mut Form| f.username.clear(),
            |f: &mut Form| f.gateway_host.clear(),
            |f: &mut Form| f.gateway_port.clear(),
            // 只填空格也算空。
            |f: &mut Form| f.username = "   ".into(),
        ] {
            let mut f = filled_form();
            wreck(&mut f);
            assert!(Account::from_form(&f).is_none(), "{f:?} 不该拼出账号");
        }
        // 反向自证：填满的那一份确实拼得出来。
        assert!(Account::from_form(&filled_form()).is_some());
    }

    /// 写出去再读回来是同一个账号。
    ///
    /// 改红：把 `encode` 里三行的顺序换一下（比如 host 写在 username
    /// 前面）——`decode` 读回来的 username 会是主机名，这条当场红。
    #[test]
    fn an_account_survives_a_round_trip() {
        let a = Account::from_form(&filled_form()).expect("有账号");
        let back = Account::decode(&a.encode()).expect("写出去的应当读得回来");
        assert_eq!(back, a);
        assert_eq!(back.username, "tunnel-zhang");
        assert_eq!(back.host, "ops.example.com");
        assert_eq!(back.port, "443");
    }

    /// 格式不对就当没记过，**不猜**。
    #[test]
    fn a_broken_account_record_is_refused() {
        assert!(Account::decode("").is_none());
        assert!(Account::decode("只有一行").is_none());
        assert!(
            Account::decode("zhang\nops.example.com").is_none(),
            "少一行"
        );
        assert!(
            Account::decode("zhang\n\n443").is_none(),
            "中间那行是空的也不行"
        );
        // 反向自证：合法的那一份能过。
        assert!(Account::decode("zhang\nops.example.com\n443\n").is_some());
    }

    // ================= 存 =================

    /// **连接成功 + 勾了记住 → 口令真的进了 SecretStore，而且盘上没有
    /// 明文。**
    ///
    /// 断的是哪一根线：在这一轮之前，`Core::secrets` 与 `Form::remember`
    /// 之间**一个生产调用方都没有**——勾选框什么都不做，而六道闸门全绿。
    ///
    /// 改红：把 `save` 里 `store.save(&key, &form.password)` 那一行
    /// 删掉（改成 `let _ = ..;` 也一样）——第二组断言当场红。
    #[test]
    fn a_checked_remember_really_writes_the_sealed_password() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);
        let form = filled_form();

        // 反向自证：存之前确实取不到。
        assert!(matches!(
            store.load_outcome("tunnel-zhang@ops.example.com:443"),
            LoadOutcome::NotRemembered
        ));

        assert_eq!(
            save(&paths, store.as_ref(), &form),
            SaveOutcome::Saved {
                key: "tunnel-zhang@ops.example.com:443".into()
            }
        );

        // 主断言：按同一个 key 取得回来，而且是同一个口令。
        let got = store
            .load("tunnel-zhang@ops.example.com:443")
            .expect("存进去了却取不回来");
        assert_eq!(*got, CANARY);

        // 盘上**没有明文**：整个应用目录下的每一个文件都不许出现金丝雀。
        for file in walk(dir.path()) {
            let bytes = std::fs::read(&file).expect("读得到");
            assert!(
                !contains(&bytes, CANARY.as_bytes()),
                "{file:?} 里躺着明文口令"
            );
        }
    }

    /// 账号记录里**一个口令字节都没有**。
    ///
    /// 这是本轮唯一一个新落盘的文件，而它不经 DPAPI。
    #[test]
    fn the_account_file_never_carries_the_password() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);
        save(&paths, store.as_ref(), &filled_form());

        let text = std::fs::read_to_string(paths.last_account()).expect("账号记录应当写出来了");
        // 反向自证：文件确实有内容、确实是这个账号的。
        assert!(text.contains("tunnel-zhang"), "{text}");
        assert!(text.contains("ops.example.com"), "{text}");
        assert!(!text.contains(CANARY), "账号记录里躺着明文口令：{text}");
        // 连片段都不许有。
        assert!(!text.contains("9d41c7"), "{text}");
    }

    /// **没勾（或者取消勾选）→ 两样都清掉。**
    ///
    /// 改红：把 `save` 里 `if !form.remember` 那一支删掉——取消勾选
    /// 之后密文还躺在盘上，而用户以为不再记住了。
    #[test]
    fn unchecking_remember_clears_both_the_secret_and_the_account() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);

        save(&paths, store.as_ref(), &filled_form());
        // 反向自证：确实记住过，下面那两条断言因此带载。
        assert!(store.load("tunnel-zhang@ops.example.com:443").is_some());
        assert!(paths.last_account().exists());

        let mut f = filled_form();
        f.remember = false;
        assert_eq!(save(&paths, store.as_ref(), &f), SaveOutcome::Cleared);

        assert!(
            store.load("tunnel-zhang@ops.example.com:443").is_none(),
            "取消勾选之后密文还在盘上"
        );
        assert!(!paths.last_account().exists(), "账号记录还在");
        // 再清一次不出事。
        assert_eq!(save(&paths, store.as_ref(), &f), SaveOutcome::Cleared);
    }

    /// 表单不完整、或者口令是空的，什么都不做。
    #[test]
    fn an_incomplete_form_saves_nothing() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);

        assert_eq!(
            save(&paths, store.as_ref(), &Form::default()),
            SaveOutcome::Incomplete
        );
        let mut f = filled_form();
        f.password = Zeroizing::new(String::new());
        assert_eq!(save(&paths, store.as_ref(), &f), SaveOutcome::Incomplete);
        assert!(!paths.last_account().exists(), "什么都不该落盘");
    }

    // ================= 取 =================

    /// **启动时按同一个 key 取回、填进密码框。**
    ///
    /// 改红：把 `recall` 的 `store.load_outcome(&account.key())` 换成
    /// `load_outcome("")`——key 对不上，取回变成 `NotRemembered`，
    /// 密码框空着。这条当场红。
    #[test]
    fn a_remembered_password_comes_back_on_the_next_start() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);
        save(&paths, store.as_ref(), &filled_form());

        // 下一次启动：一张全空的表单。
        let mut form = Form::default();
        assert!(form.password.is_empty(), "夹具本该是空表单");

        let note = recall(&paths, store.as_ref()).fill(&mut form);

        assert_eq!(*form.password, CANARY, "密码框没有被填上");
        assert_eq!(form.username, "tunnel-zhang");
        assert_eq!(form.gateway_host, "ops.example.com");
        assert_eq!(form.gateway_port, "443");
        assert!(form.remember, "「记住密码」这个勾没有跟着回来");
        // 取回成功也说一句——它顺带告诉用户「还没经过运维服务器验证」。
        let note = note.expect("取回成功也该有一句说明");
        assert_eq!(
            note,
            LoadOutcome::Loaded(Zeroizing::new(String::new()))
                .diagnostic()
                .1
        );
        assert!(!note.contains(CANARY), "说明里带上了口令：{note}");
    }

    /// 没记过账号：什么都不填，也没有那句话。
    ///
    /// 少了这条，上面那条在「`fill` 每次都填一份写死的东西」时也是绿的。
    #[test]
    fn a_machine_that_never_remembered_fills_nothing() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);

        let mut form = Form::default();
        assert!(recall(&paths, store.as_ref()).fill(&mut form).is_none());
        assert!(form.password.is_empty());
        assert!(form.username.is_empty());
        assert!(!form.remember);
    }

    /// **W200 第 3 条：四种失败分类各自的诊断话都得有地方显示。**
    ///
    /// 尤其是 `UnsealFailed`——「换了 Windows 账号或换了机器就解不开」
    /// 这句话就是 W21 当初要带类型出口的全部理由。
    ///
    /// 改红：把 `Recall::fill` 里的 `outcome.diagnostic()` 换成一句写死
    /// 的话（或者直接 `None`）——这条当场红，而且能说出是哪一格。
    #[test]
    fn every_failure_class_puts_its_own_words_next_to_the_password_box() {
        // 四种失败分类 + 成功那一格，一格都不许漏。
        let cases: [(LoadOutcome, &str); LoadOutcome::VARIANTS] = [
            (LoadOutcome::NotRemembered, "没有为这个运维服务器记住过密码"),
            (
                LoadOutcome::Unreadable("权限不足".into()),
                "记住的密码读不出来",
            ),
            (LoadOutcome::UnsealFailed, "换了账号或换了机器就解不开"),
            (LoadOutcome::NotUtf8, "这份记录已经损坏"),
            (
                LoadOutcome::Loaded(Zeroizing::new(CANARY.into())),
                "已从本机取回记住的密码",
            ),
        ];

        for (outcome, want) in cases {
            let variant = outcome.variant_name();
            let loaded = matches!(outcome, LoadOutcome::Loaded(_));
            let recall = Recall::Remembered {
                account: Account {
                    username: "tunnel-zhang".into(),
                    host: "ops.example.com".into(),
                    port: "443".into(),
                },
                outcome,
            };
            let mut form = Form::default();
            let note = recall.fill(&mut form).expect("记过账号就该有一句说明");

            assert!(
                note.contains(want),
                "{variant} 那一格说的不是它自己的话：{note}"
            );
            assert!(!note.contains(CANARY), "{variant}：说明里带上了口令");
            assert_eq!(
                rmc_core::banned_word_in(&note),
                None,
                "{variant} 的说明含禁用词：{note}"
            );
            // 账号那三样无论成败都填上了。
            assert_eq!(form.username, "tunnel-zhang");
            assert!(form.remember, "{variant}：勾没有跟着回来");
            // 只有 Loaded 那一格会填口令。
            assert_eq!(
                !form.password.is_empty(),
                loaded,
                "{variant}：密码框该不该被填上，判反了"
            );
        }
    }

    /// 端到端走一遍「换了 Windows 账号」：存的时候解得开，取的时候解不开。
    ///
    /// 这一格是 W21 的全部理由，也是四格里唯一一个在真实世界里**很常见**
    /// 的（换笔记本、换域账号）。
    #[test]
    fn a_secret_sealed_by_another_account_says_so_instead_of_staying_silent() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        // 存的时候用一个能密封的。
        save(
            &paths,
            store_at(&paths, FlipSealer).as_ref(),
            &filled_form(),
        );
        // 取的时候换一个解不开的——这就是换了 Windows 账号。
        let broken = store_at(&paths, BrokenSealer);

        let mut form = Form::default();
        let note = recall(&paths, broken.as_ref())
            .fill(&mut form)
            .expect("解不开也该说一句");

        assert!(form.password.is_empty(), "解不开却填了口令");
        assert!(
            note.contains("换了账号或换了机器就解不开"),
            "解不开时说的不是那句话：{note}"
        );
        // 账号还在，用户重新输入密码就能接着用。
        assert_eq!(form.username, "tunnel-zhang");
        assert!(form.remember);
    }

    // ---------- 小工具 ----------

    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return out;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
        out
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
