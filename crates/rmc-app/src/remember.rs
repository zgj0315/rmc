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

    // # W202：上一次记的是谁，**必须在这里读**
    //
    // `last-account.txt` 只记得住**一个**账号，所以任何一个不等于它的
    // key 都是**谁也找不回来的孤儿**：`recall` 只会按记录里那一个去取。
    //
    // 修的是这样一条真实路径（评审写了 PoC）：用户记住 `A@运维服务器`
    // → 把账号改成 `B` → 取消勾选「记住密码」。上一版按**当前表单**
    // 拼出的 `B@运维服务器` 去清（本来就不存在），账号记录被删掉，而
    // `A@运维服务器` 的密文**永久留在盘上，而且再也没有任何路径指得到
    // 它**——用户明确说了「不再记住」。
    //
    // 读必须在 [`write_account`] **之前**：那一步会把它覆盖掉。
    let previous = previous_key(paths);

    if !form.remember {
        // 取消勾选（或者从来没勾）：当前 key、上一次那个 key、账号记录，
        // 三样都清掉。Task 4 的 `clear` 会连写到一半留下的 `.tmp` 一起
        // 删（W25）。
        return match clear(paths, store, &key, previous.as_deref()) {
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
        //
        // W203：这一支上一轮是**零覆盖**的（评审两枪双绿）。它跟 W202
        // 是同一个危害面，夹具见
        // `a_failed_account_record_rolls_the_ciphertext_back`。
        let _ = store.clear(&key);
        return SaveOutcome::Failed(e.to_string());
    }
    // W202 的另一半：账号换了，上一份密文从此再没有任何路径指得到它。
    // **必须在新的两样都写成之后**才清——反过来的话，新密文写失败时
    // 旧的那份已经被毁了，用户两边都没了。
    if let Some(old) = previous.filter(|p| *p != key) {
        if let Err(e) = store.clear(&old) {
            // 不吞掉，但也不因此把这次「记住」判成失败：新的那份确实
            // 存好了，用户要的事已经做到。
            tracing::warn!(error = %e, "上一个账号的密文没能清掉，它已经取不回来了");
        }
    }
    SaveOutcome::Saved { key }
}

/// 上一次记住的那个账号的 key。没有记录、或者记录坏了就是 `None`。
fn previous_key(paths: &AppPaths) -> Option<String> {
    let text = std::fs::read_to_string(paths.last_account()).ok()?;
    Account::decode(&text).map(|a| a.key())
}

/// 把密文与账号记录都清掉。
///
/// `previous` 是上一次记住的那个 key（W202）：账号改过之后它跟 `key`
/// 不是一回事，而它才是盘上真正躺着密文的那一个。
fn clear(
    paths: &AppPaths,
    store: &dyn SecretStore,
    key: &str,
    previous: Option<&str>,
) -> std::io::Result<()> {
    // 每一步都走完再报第一个错——半路 return 会留下另外几样（同 Task 4
    // 的 `SecretStore::clear` 自己那条 W25）。
    let mut result = store.clear(key);
    if let Some(old) = previous.filter(|p| *p != key) {
        result = result.and(store.clear(old));
    }
    let account = match std::fs::remove_file(paths.last_account()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    };
    result.and(account)
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

    /// **W202：改了账号再取消勾选，旧密文不许留在盘上。**
    ///
    /// 评审的 PoC。上一版按**当前表单**拼出的 key 去清，于是：
    ///
    /// 1. 记住 `tunnel-zhang@ops.example.com:443`；
    /// 2. 把账号改成 `tunnel-li`；
    /// 3. 取消勾选「记住密码」→ 清的是 `tunnel-li@...`（本来就不存在），
    ///    账号记录被删掉，而 `tunnel-zhang@...` 的密文**永久留在盘上，
    ///    而且再也没有任何路径指得到它**（下次启动 `recall` 直接
    ///    `NoAccount`）。
    ///
    /// 密文是 DPAPI 绑定的、不是明文泄露，但用户明确说了「不再记住」
    /// 而东西还在、还删不掉。
    ///
    /// 改红：把 `save` 里 `clear(..)` 的第四个参数换成 `None`
    /// （也就是退回只清当前 key），第二组断言当场红。
    #[test]
    fn changing_the_account_then_unchecking_leaves_no_orphan_ciphertext() {
        const KEY_A: &str = "tunnel-zhang@ops.example.com:443";
        const KEY_B: &str = "tunnel-li@ops.example.com:443";

        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);

        // 1. 记住 A。
        assert_eq!(
            save(&paths, store.as_ref(), &filled_form()),
            SaveOutcome::Saved { key: KEY_A.into() }
        );
        // 反向自证：A 的密文确实躺在盘上，下面那条断言因此带载。
        assert!(store.load(KEY_A).is_some());

        // 2. 用户把账号改成 B，3. 取消勾选。
        let mut f = filled_form();
        f.username = "tunnel-li".into();
        f.remember = false;
        assert_eq!(save(&paths, store.as_ref(), &f), SaveOutcome::Cleared);

        // 主断言：**旧账号的密文也清掉了**。
        assert!(
            store.load(KEY_A).is_none(),
            "改了账号再取消勾选，上一个账号的密文永久留在了盘上，\
             而且再也没有任何路径指得到它"
        );
        assert!(store.load(KEY_B).is_none());
        assert!(!paths.last_account().exists());
        // 盘上真的一个密文文件都不剩。
        assert_eq!(
            sealed_files(&paths).len(),
            0,
            "密文目录里还剩：{:?}",
            sealed_files(&paths)
        );
    }

    /// W202 的另一半：换一个账号继续记住，**上一份密文也不该留成孤儿**。
    ///
    /// `last-account.txt` 只记得住一个账号，所以旧那份从此取不回来。
    ///
    /// 改红：把 `save` 末尾那段 `if let Some(old) = previous.filter(..)`
    /// 整块删掉——盘上会攒下两份密文，而其中一份谁也够不着。
    #[test]
    fn remembering_a_second_account_does_not_orphan_the_first_one() {
        const KEY_A: &str = "tunnel-zhang@ops.example.com:443";
        const KEY_B: &str = "tunnel-li@ops.example.com:443";

        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);

        save(&paths, store.as_ref(), &filled_form());
        assert!(store.load(KEY_A).is_some(), "夹具本该先记住 A");

        let mut f = filled_form();
        f.username = "tunnel-li".into();
        assert_eq!(
            save(&paths, store.as_ref(), &f),
            SaveOutcome::Saved { key: KEY_B.into() }
        );

        // 新的那份在，旧的那份没了。
        assert_eq!(*store.load(KEY_B).expect("新账号没记住"), CANARY);
        assert!(
            store.load(KEY_A).is_none(),
            "换了账号，上一份密文留成了谁也够不着的孤儿"
        );
        assert_eq!(sealed_files(&paths).len(), 1, "{:?}", sealed_files(&paths));

        // 而且下一次启动取回的是新那个账号。
        let mut form = Form::default();
        recall(&paths, store.as_ref()).fill(&mut form);
        assert_eq!(form.username, "tunnel-li");
        assert_eq!(*form.password, CANARY);
    }

    /// **新密文写失败时，上一份必须还在——顺序不能反过来。**
    ///
    /// `save` 里清旧 key 那一步**排在新的两样都写成之后**，注释写明了
    /// 理由：反过来的话新密文写失败时旧的那份已经被毁，用户两边都没了。
    ///
    /// 复审实测：把顺序改成「先清旧、后写新」，**211 条全绿**——
    /// 因为**从来没有任何测试让 `store.save` 在存在 `previous` 时失败过**，
    /// 而那正是这个顺序唯一守的东西。这条就是补那一枪的。
    ///
    /// 改红：把 `save` 里的 `store.clear(&old)` 挪到 `store.save(..)` 之前。
    #[test]
    fn a_failed_save_leaves_the_previous_secret_alone() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        // 上一次记的是 A，账号记录也指着它。
        std::fs::create_dir_all(paths.root()).expect("建目录");
        std::fs::write(
            paths.last_account(),
            Account {
                username: "tunnel-zhang".into(),
                host: "ops.example.com".into(),
                port: "443".into(),
            }
            .encode(),
        )
        .expect("写账号记录");

        // 这一次换成别的账号，而存储写不进去。
        let store = RecordingStore::failing_to_save();
        let mut f = filled_form();
        f.username = "tunnel-li".into();
        let outcome = save(&paths, &store, &f);

        assert!(
            matches!(outcome, SaveOutcome::Failed(_)),
            "存储写不进去却报成功了：{outcome:?}"
        );
        // 主断言：**旧那份一次都没被清过**。顺序反过来时这里会看到 KEY_A。
        assert!(
            store.cleared().is_empty(),
            "新密文没写成，却已经把上一份清掉了：{:?}",
            store.cleared()
        );
        // 反向自证：夹具真的走到了「有 previous」那条路——账号记录还在，
        // 也就是说 `previous_key` 读得出东西来。
        assert!(
            paths.last_account().exists(),
            "夹具没造出「上一次记过别的账号」这个前提"
        );
    }

    /// **重复记住同一个账号，不许把刚存进去的那一份当成「上一个」清掉。**
    ///
    /// 这是生产里**最常走到**的一条路：用户勾着「记住密码」，每连成功
    /// 一次就走一遍 [`save`]，第二次起 `previous` 就等于当前 key。
    ///
    /// # 这道筛与它守的危害面**都是本轮新引入的**，不是历史缺陷
    ///
    /// 复审核过 `git show 86c5cc9:…/remember.rs`：上一版的 `save` 里
    /// **根本没有 `previous` 这个概念**，`clear` 也只有三个参数——
    /// 每次连成功只是用同一个 key 覆盖写一遍，**不存在「把刚存的清掉」
    /// 这条路**。所以「记住密码第二次连接就失效」这个 bug
    /// **从来没有发生过**。
    ///
    /// 这道 `filter` 是修 W202（换账号留孤儿密文）时顺带开出来的新危害面，
    /// 筛和这条测试是同一轮里配套加上的。上一版注释把它写成
    /// 「上一轮那一枪全绿」，容易被读成「旧代码里一直有这个坑」——**不是**。
    ///
    /// 改红：把 `save` 末尾 `previous.filter(|p| *p != key)` 里的
    /// `filter` 去掉——第二次「记住」会把自己刚存的密文清掉，下次启动
    /// 密码框是空的。
    #[test]
    fn remembering_the_same_account_twice_keeps_it() {
        const KEY: &str = "tunnel-zhang@ops.example.com:443";

        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);

        assert_eq!(
            save(&paths, store.as_ref(), &filled_form()),
            SaveOutcome::Saved { key: KEY.into() }
        );
        // 反向自证：第一次之后 `last-account.txt` 确实在了，第二次的
        // `previous` 因此**不是** `None`——少了这一步，下面那次调用走的
        // 是跟第一次一样的路，什么都证明不了。
        assert!(paths.last_account().exists());

        assert_eq!(
            save(&paths, store.as_ref(), &filled_form()),
            SaveOutcome::Saved { key: KEY.into() }
        );

        assert_eq!(
            *store.load(KEY).expect("第二次「记住」把自己刚存的清掉了"),
            CANARY
        );
        assert_eq!(sealed_files(&paths).len(), 1, "{:?}", sealed_files(&paths));
        // 下一次启动照常取得回来。
        let mut form = Form::default();
        recall(&paths, store.as_ref()).fill(&mut form);
        assert_eq!(*form.password, CANARY);
    }

    /// **`clear` 里第一步失败也要把后面几步走完。**
    ///
    /// 同 Task 4 的 `SecretStore::clear` 自己那条 W25：半路 `return` 会
    /// 把另外几样留在盘上，而用户点的是「不再记住密码」。
    ///
    /// 上一轮的 F6 那一枪（把 `.and(..)` 换成 `?` 提前返回）**全绿**——
    /// 没有任何测试让 `store.clear` 失败过。补上，用一个会在指定 key 上
    /// 报错的假存储。
    ///
    /// 改红：把 `clear` 里的 `let mut result = store.clear(key);` 换成
    /// `store.clear(key)?;`。
    ///
    /// # 这条注释上一版是假的，订正记在这里
    ///
    /// 上一版写的是「把 `result = result.and(store.clear(old));` 换成
    /// `store.clear(old)?;`」——**复审按字面注入，实测 211 全绿**。
    /// 原因看得很清楚：这条测试让**第一步**（当前 key）失败，而那个 `?`
    /// 挂在**第二步**（旧 key，它是成功的）上，早返根本不触发。
    ///
    /// 所以这条测试守的是「**第一步**失败也要走完后面几步」，
    /// 而 **`clear` 第二步的早返至今零覆盖**——真发生时会跳过删账号记录，
    /// 用户点了「不再记住密码」而 `last-account.txt` 还在。
    /// 要覆盖它只需把 `RecordingStore::failing_on` 的目标换成旧 key，
    /// 按 W206 记账不修。
    #[test]
    fn clearing_finishes_every_step_even_after_the_first_one_fails() {
        const KEY_A: &str = "tunnel-zhang@ops.example.com:443";
        const KEY_B: &str = "tunnel-li@ops.example.com:443";

        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        // 上一次记的是 A。
        std::fs::create_dir_all(paths.root()).expect("建目录");
        std::fs::write(
            paths.last_account(),
            Account {
                username: "tunnel-zhang".into(),
                host: "ops.example.com".into(),
                port: "443".into(),
            }
            .encode(),
        )
        .expect("写账号记录");

        // 当前表单是 B，取消勾选；而清 B 这一步会失败。
        let store = RecordingStore::failing_on(KEY_B);
        let mut f = filled_form();
        f.username = "tunnel-li".into();
        f.remember = false;

        let out = save(&paths, &store, &f);

        // 夹具自证：确实失败了，下面两条因此不是空转。
        assert!(matches!(out, SaveOutcome::Failed(_)), "{out:?}");

        let cleared = store.cleared();
        // 第一步（当前 key）走了。
        assert!(cleared.contains(&KEY_B.to_string()), "{cleared:?}");
        // **主断言**：第一步失败了，第二步（上一个 key）照样走。
        assert!(
            cleared.contains(&KEY_A.to_string()),
            "第一步失败就不走了，上一个账号的密文留在了盘上：{cleared:?}"
        );
        // 第三步（账号记录）也走了。
        assert!(!paths.last_account().exists(), "账号记录也没删掉");
    }

    /// **W203：账号记录写不成时，已经写进去的密文要回滚。**
    ///
    /// 这一支上一轮是**零覆盖**的（评审两枪双绿：把 `store.clear(&key)`
    /// 删掉、把失败分支改成返回 `Saved`，都没有任何测试变红）——它根本
    /// 进不去。它守的跟 W202 是同一个危害面：一份谁也找不回来的孤儿密文。
    ///
    /// 夹具（评审给的造法）：把 `last-account.txt` 那个**路径先建成一个
    /// 目录**，`std::fs::write` 必失败，于是 `save` 走进回滚支。
    ///
    /// 改红：把那一支里的 `let _ = store.clear(&key);` 删掉，或者把
    /// `return SaveOutcome::Failed(..)` 改成 `SaveOutcome::Saved`。
    #[test]
    fn a_failed_account_record_rolls_the_ciphertext_back() {
        const KEY: &str = "tunnel-zhang@ops.example.com:443";

        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);
        // 路径被一个**目录**占住：`fs::write` 必失败。
        std::fs::create_dir_all(paths.last_account()).expect("建目录");

        let out = save(&paths, store.as_ref(), &filled_form());

        // 夹具自证：确实走进了失败那一支，下面两条断言因此不是空转。
        assert!(
            matches!(out, SaveOutcome::Failed(_)),
            "夹具没能让账号记录写失败：{out:?}"
        );
        // 主断言：密文回滚了。
        assert!(
            store.load(KEY).is_none(),
            "账号记录写不成，密文却留在了盘上——那是一份谁也找不回来的孤儿"
        );
        assert_eq!(
            sealed_files(&paths).len(),
            0,
            "密文目录里还剩：{:?}",
            sealed_files(&paths)
        );
        // 失败的说明里不许带口令。
        let SaveOutcome::Failed(detail) = out else {
            unreachable!("上面刚 match 过")
        };
        assert!(!detail.contains(CANARY), "失败说明里带上了口令：{detail}");

        // 反向自证：路径不被占住时这条路是通的（否则上面那条
        // 「密文没了」可能只是因为压根没写进去过）。
        let dir2 = tempfile::tempdir().expect("建临时目录");
        let paths2 = AppPaths::at(dir2.path().to_path_buf());
        let store2 = store_at(&paths2, FlipSealer);
        assert_eq!(
            save(&paths2, store2.as_ref(), &filled_form()),
            SaveOutcome::Saved { key: KEY.into() }
        );
        assert!(store2.load(KEY).is_some());
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

    /// 一个记录「clear 被调了哪些 key」、并且可以在指定 key 上报错的
    /// 假存储。`clear` 的分步语义只能这样观察。
    #[derive(Default)]
    struct RecordingStore {
        cleared: std::sync::Mutex<Vec<String>>,
        fail_on: Option<String>,
        /// `save` 一律失败。用来观察 `save` 里「先写新、后清旧」那个顺序。
        save_fails: bool,
    }

    impl RecordingStore {
        fn failing_on(key: &str) -> Self {
            Self {
                fail_on: Some(key.to_string()),
                ..Self::default()
            }
        }

        fn failing_to_save() -> Self {
            Self {
                save_fails: true,
                ..Self::default()
            }
        }

        fn cleared(&self) -> Vec<String> {
            self.cleared.lock().expect("锁").clone()
        }
    }

    impl SecretStore for RecordingStore {
        fn save(&self, _key: &str, _secret: &str) -> std::io::Result<()> {
            if self.save_fails {
                return Err(std::io::Error::other("假存储：写不进去"));
            }
            Ok(())
        }

        fn load_outcome(&self, _key: &str) -> LoadOutcome {
            LoadOutcome::NotRemembered
        }

        fn clear(&self, key: &str) -> std::io::Result<()> {
            self.cleared.lock().expect("锁").push(key.to_string());
            if self.fail_on.as_deref() == Some(key) {
                return Err(std::io::Error::other("模拟：这个 key 清不掉"));
            }
            Ok(())
        }
    }

    /// 密文目录下的 `.sealed` 文件。W202/W203 靠它数「盘上还剩几份」。
    fn sealed_files(paths: &AppPaths) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(paths.secrets_dir())
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".sealed"))
            .collect();
        out.sort();
        out
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
