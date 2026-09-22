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
//! # 为什么还要多存一份 `connection-code.txt`
//!
//! key 是 `账号@运维服务器 IP:端口`，而 [`Form::default`] 是**全空的**
//! ——启动那一刻我们根本不知道 key 是什么，第 2 条于是无从谈起。
//! [`FileSecretStore`](rmc_win::secret::FileSecretStore) 又把 key 哈希成
//! 文件名，盘上也反查不回来。
//!
//! 所以存一份**不含任何秘密**的连接码（一行纯文本）在应用目录下。
//! 用户下次还得再粘一遍，「记住密码」在用户心里本来也包含「记住我连的
//! 是哪台」。
//!
//! **口令一个字节都不在这个文件里**，`account_file_never_carries_the_password`
//! 守这条。
//!
//! # Task 8：`Account` 换成持有解析好的 [`ConnectionCode`]
//!
//! 原来这里是 `Account { username, host, port }` 三个裸字符串，`key()`
//! 直接拼 `format!("{username}@{host}:{port}")`。表单侧的三个框合并成
//! 一条连接码之后（见 `form::Form` 上「Task 8」一节），`Account` 改成
//! 持有一份 [`ConnectionCode`]——字段私有，构造入口只有 [`from_form`]
//! 与 [`decode`]，两者都在构造那一刻拒绝了不合法的连接码，`key()`/
//! `encode()` 因此**不可能失败**，不需要一个 `.expect(...)` 的炸点
//! （见 rmc-core 里 `HostPort`、`ValidatedAddresses` 同族的做法）。
//!
//! **`key()` 产出的字符串形态跟今天完全一样**：`账号@IP:端口`——旧版
//! 三段式的 `host` 字段以前也只接受 IP/主机名，连接码把它收紧成只接受
//! IP，`key()` 拼字符串这一步没有变。这一点很要紧：升级前用旧版三段式
//! 记住的密文，key 是按「账号@主机:端口」这个**字符串**定位的，只要
//! 新版拼出的字符串跟旧版逐字一致，旧密文升级后照样能取回来；这条由
//! [`the_key_is_the_account_at_the_server`] 与
//! [`the_key_format_matches_the_old_three_part_shape_byte_for_byte`]
//! 两条测试钉住。
//!
//! # Task 11 + R11-2：`connection-code.txt` 与 `remembered-key.txt`
//! 是两个问题的答案，不能共用一份记录
//!
//! Task 11 给「上一次连的是哪台」（`connection-code.txt`）加了第二个
//! 写方——[`persist_code`]，每次连接成功都写，跟「记住密码」的勾、跟
//! [`save`] 成不成功都无关。而 [`save`] 自己一直靠**同一份**记录回答
//! 另一个完全不同的问题：「盘上那份密文属于哪个 key」（W202 的孤儿
//! 密文清理靠它，见 [`previous_key`]）。
//!
//! 两个问题共用一份答案，一旦 `persist_code` 在 [`save`] 失败之后把
//! 记录改成了别的账号，「上一次记住的是谁」这个答案就会被误导——密文
//! 真的在盘上，却再也没有路径找得到它，永久孤儿。这是复审在 R11-2
//! 抓到的真实回归，PoC 见
//! [`persist_code_failing_a_save_does_not_orphan_the_previous_secret`]。
//!
//! 修法：拆成两份独立记录，[`AppPaths::remembered_key`] 只由
//! [`save`] 自己的成功路径写、[`clear`] 删——[`persist_code`] 永远
//! 碰不到它。

use crate::form::Form;
use crate::wiring::AppPaths;
use rmc_core::code::ConnectionCode;
use rmc_win::secret::{LoadOutcome, SecretStore};

/// 记住密码的那个账号。**不含口令。**
///
/// 字段私有：构造入口只有 [`Account::from_form`] 与 [`Account::decode`]，
/// 两者都只在连接码合法时才产出一个值——不存在「拼出一个内容非法的
/// `Account`」这条路，`key()`/`encode()` 因此不需要处理失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    code: ConnectionCode,
}

impl Account {
    /// 从表单上取。连接码解析不出来就没有账号可记——**不拼一个半截
    /// 的 key**，那会让「记住」与「取回」用的 key 对不上。
    pub fn from_form(form: &Form) -> Option<Self> {
        Some(Self {
            code: form.parsed_code()?,
        })
    }

    /// 存进 [`SecretStore`] 用的 key：`账号@运维服务器 IP:端口`。
    ///
    /// 形状跟旧版三段式（`账号@主机:端口`）**逐字一致**——升级后用户
    /// 已经记住的密文要按同一个字符串才能取回来，见模块文档「Task 8」
    /// 一节。
    pub fn key(&self) -> String {
        format!(
            "{}@{}:{}",
            self.code.account(),
            self.code.ip(),
            self.code.port()
        )
    }

    /// 写进 `connection-code.txt` 的内容：连接码原样一行。
    pub fn encode(&self) -> String {
        format!("{}\n", self.code)
    }

    /// 读回来。第一行解析不出合法连接码就返回 `None`——**不猜**，猜出来
    /// 的账号会去取一份不存在的密码，然后在密码框旁边写一句莫名其妙的
    /// 话。
    pub fn decode(text: &str) -> Option<Self> {
        let code = ConnectionCode::parse(text.lines().next()?.trim()).ok()?;
        Some(Self { code })
    }

    /// 这个账号连接码里的账号名——`Recall::fill` 用它填回表单。
    pub fn code(&self) -> &ConnectionCode {
        &self.code
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
    /// 表单上还拼不出 key（连接码解析不出来），或者口令是空的。
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
    // # 终审 FR-3：**「不再记住」这条路不许依赖表单能不能解析**
    //
    // 这三行原来在函数最前面，`remember = false` 那一支排在它后面——于是
    // 「取消勾选时连接码恰好是坏的」这种再普通不过的组合（用户一边改连接码
    // 一边把勾去掉、粘贴粘了半条、把框清空重填）会在这里就 `Incomplete`
    // 返回，**一个字节都不清**：上一个账号的 DPAPI 密文与
    // `remembered-key.txt` 原样留在盘上，下次启动照样把口令自动填回密码
    // 框。用户明确说了
    // 「不再记住」，而软件什么都没做，也没告诉他。
    //
    // 「要清掉哪一份密文」这个问题的答案本来也不在表单里——它在
    // `remembered_key` 记录里（W202/R11-2，见下面 `previous` 那一段）。
    // 表单只是**附加**了一份「当前这个 key 也一并清掉」的保险，缺了它不
    // 影响正确性。所以把解析挪到「确实要存」那一支的开头去。
    let previous = previous_key(paths);

    if !form.remember {
        // 取消勾选（或者从来没勾）：`remembered_key` 指着的那份密文清掉，
        // 记录本身也删掉——盘上不该再有任何一个 key 被当成「记住着」。
        // 表单能解析的话，顺手把它拼出来的 key 也清一遍（多一层保险：
        // 万一是从没有 `remembered_key` 记录的老版本升上来的）；解析不出
        // 来就只按 `previous` 清，**不再因此整支跳过**。
        // **不碰连接码文件**（Task 11）：那份记录现在由 `persist_code`
        // 独立维护，跟「记住密码」这个勾无关——用户「不再记住密码」不等于
        // 「不想让软件记得上次连的是哪台」。
        let current = Account::from_form(form).map(|a| a.key());
        return match clear(paths, store, current.as_deref(), previous.as_deref()) {
            Ok(()) => SaveOutcome::Cleared,
            Err(e) => SaveOutcome::Failed(e.to_string()),
        };
    }

    let Some(account) = Account::from_form(form) else {
        return SaveOutcome::Incomplete;
    };
    let key = account.key();

    // # W202：上一次记的是谁，读的是哪一份记录
    //
    // （读本身在函数开头，终审 FR-3 把它连同「不再记住」那一支一起提到了
    // `Account::from_form` 前面；下面这段说的是**为什么读那一份**。）
    //
    // R11-2 修复轮：这个问题的答案来自 [`AppPaths::remembered_key`]，
    // **不是** `connection-code.txt`——两者故意拆开（见 `AppPaths` 上的
    // 说明）。`remembered_key` 只有 [`save`] 自己的成功路径会写，
    // [`persist_code`] 摸不到它，于是「哪个 key 有密文」这件事不会被
    // 一次跟密文毫不相干的写方悄悄改掉。
    //
    // 修的是这样一条真实路径（评审写了 PoC，见
    // `persist_code_failing_a_save_does_not_orphan_the_previous_secret`）：
    // 用户记住 `A@运维服务器` → 把连接码换成 `B`，这次密文写不进去
    // → 取消勾选「记住密码」。如果「上一次是谁」跟 `connection-code.txt`
    // 共用一份记录，`persist_code` 会在密文写失败之后照样把它改成 `B`，
    // 于是 `previous` 被错当成 `B`（等于 `key`，被
    // `previous.filter(|p| *p != key)` 过滤掉），`A@运维服务器` 的密文
    // **永久留在盘上，而且再也没有任何路径指得到它**。
    //
    // 读必须在 [`write_remembered_key`] **之前**：那一步会把它覆盖掉，
    // 所以 `previous` 在函数开头就读好了（见上）。
    if form.password.is_empty() {
        return SaveOutcome::Incomplete;
    }

    if let Err(e) = store.save(&key, &form.password) {
        return SaveOutcome::Failed(e.to_string());
    }
    // 账号记录（`connection-code.txt`）：跟密文定位键是两份独立记录
    // （R11-2），这里继续写它只是为了不破坏「`save` 成功时账号记录也
    // 跟着更新」这条既有行为——生产路径上 `App::persist_connection_code`
    // 已经无条件写过一次了，这里重复写是无害的幂等操作。
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
    // R11-2：密文定位键**后写**，理由跟上面账号记录那一支一样——写不
    // 成就不该留下一份指向它的记录，那正是 W202 要防的「孤儿」本身：
    // 密文真的存在，但没有任何路径能找到它。
    if let Err(e) = write_remembered_key(paths, &key) {
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

/// 盘上那份密文（如果有）属于哪个 key。没有记录就是 `None`。
///
/// R11-2：读的是 [`AppPaths::remembered_key`]，**不是**
/// `connection-code.txt`——后者从 Task 11 起还会被 [`persist_code`] 写，
/// 那个写方跟「盘上有没有密文」毫无关系，混在一起读就是 W202 那条
/// 回归的根源。
fn previous_key(paths: &AppPaths) -> Option<String> {
    let key = std::fs::read_to_string(paths.remembered_key()).ok()?;
    let key = key.trim();
    if key.is_empty() {
        None
    } else {
        Some(key.to_string())
    }
}

fn write_remembered_key(paths: &AppPaths, key: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(paths.root())?;
    std::fs::write(paths.remembered_key(), key)
}

/// 把密文清掉，`remembered_key` 记录也删掉。**不碰连接码文件**
/// （Task 11）：那份记录不是秘密，也不是「记住密码」的一部分，删不删
/// 密文跟它无关——见 [`persist_code`]。
///
/// `previous` 是上一次记住的那个 key（W202）：账号改过之后它跟 `key`
/// 不是一回事，而它才是盘上真正躺着密文的那一个。
///
/// 终审 FR-3：`key`（表单当前这一条）是 `Option`——连接码解析不出来时
/// 它是 `None`，而**清理照样要做**，靠的是 `previous`（`remembered_key`
/// 记录，见 [`previous_key`]）。真正回答「盘上那份密文属于谁」的从来
/// 就是 `previous`，`key` 只是一层附加保险。
fn clear(
    paths: &AppPaths,
    store: &dyn SecretStore,
    key: Option<&str>,
    previous: Option<&str>,
) -> std::io::Result<()> {
    // 每一步都走完再报第一个错——半路 return 会留下另外几样（同 Task 4
    // 的 `SecretStore::clear` 自己那条 W25）。
    let mut result = Ok(());
    if let Some(key) = key {
        result = result.and(store.clear(key));
    }
    if let Some(old) = previous.filter(|p| Some(*p) != key) {
        result = result.and(store.clear(old));
    }
    // 清完密文，`remembered_key` 也该删掉——清完之后盘上没有任何一个
    // key 还「记住着」，这份记录留着就是撒谎。
    let record = match std::fs::remove_file(paths.remembered_key()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    };
    result.and(record)
}

fn write_account(paths: &AppPaths, account: &Account) -> std::io::Result<()> {
    std::fs::create_dir_all(paths.root())?;
    std::fs::write(paths.connection_code(), account.encode())
}

/// 连接成功那一拍调用：把连接码记下来，供下次启动预填——**跟「记住
/// 密码」的勾无关**（Task 11）。这是本文件里唯一一处不看 `form.remember`
/// 就落盘的函数：连接码本身没有秘密（见 `rmc_core::code` 模块文档），
/// 用户下次还要粘贴同一条连接码，「记住我上次连的是哪台」跟「记住密码」
/// 是两件事——前者不该被后者那个勾挡住。
///
/// 连接码解析不出来（表单还没填完）时什么都不做，返回 `Ok(())`：
/// 调用方（`App::apply`）已经用 `Form::parsed_code` 先挡过一轮，这里
/// 再挡一次只是防跳过那道门直接调用。
///
/// **R11-4：已知与 brief 的偏离**——brief 明写这里要「原子写：临时文件
/// 加 rename」，这里用的是裸 `std::fs::write`（走 [`write_account`]）。
/// brief 同一句话又说「沿用本文件既有写法」，而本文件既有的
/// `write_account` 从 Task 8 起就是非原子的裸写——两句话字面上矛盾，
/// 选了后半句：保持跟 [`save`] 里那份账号记录写法一致，不为这一个
/// 函数单开一套原子写。降级路径是安全的：半截文件读回来
/// `Account::decode` 直接判 `None`（见 [`read_account`]），最坏情况是
/// 「这次没预填上」，不是脏读或崩溃。
pub fn persist_code(paths: &AppPaths, form: &Form) -> std::io::Result<()> {
    let Some(account) = Account::from_form(form) else {
        return Ok(());
    };
    write_account(paths, &account)
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
    let Some(account) = read_account(paths) else {
        return Recall::NoAccount;
    };
    let outcome = store.load_outcome(&account.key());
    Recall::Remembered { account, outcome }
}

fn read_account(paths: &AppPaths) -> Option<Account> {
    let text = std::fs::read_to_string(paths.connection_code()).ok()?;
    let account = Account::decode(&text);
    if account.is_none() {
        tracing::warn!("账号记录的格式不对，当作没有记过");
    }
    account
}

/// 只读连接码，**不碰任何密文、不需要 [`SecretStore`]**（Task 11）。
///
/// [`recall`] 内部也是先读这一份记录再去问密文；这里单独导出一份，
/// 给「这台机器没有密码存储」（非 Windows，或者装配失败）那条路径用
/// ——连接码不是秘密，记不住密码不该连「记得上次连的是哪台」都一起
/// 丢了。见 `crate::App::recall_password`。
pub fn recall_code(paths: &AppPaths) -> Option<String> {
    read_account(paths).map(|a| a.code().to_string())
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
        // 连接码无论口令取没取回来都填上——用户下次还得粘它，而且密码
        // 框旁边那句话说的正是「这台运维服务器」。
        form.code = account.code().to_string();
        // R11-3 修复轮：`Recall::Remembered` 现在**不再**意味着「用户上次
        // 确实勾了记住密码」——`connection-code.txt` 从 Task 11 起由
        // [`persist_code`] 无条件写，跟这个勾完全无关。`NotRemembered`
        // 就是「压根没有密文」，勾不该自己跳出来，否则用户没勾过、连了
        // 一次，下次启动却发现「记住密码」被自己点亮，再连一次口令就
        // 真的进了 DPAPI——这是一次真实的 opt-in 变 opt-out 的回归。
        //
        // 其余四格（`Unreadable`/`UnsealFailed`/`NotUtf8`/`Loaded`）都是
        // 「盘上真有一份密文记录」，只是读的结局不同——这四格下「用户上次
        // 确实勾了」这条注释仍然成立：`load_outcome` 只有在
        // `SecretStore::clear`/从未 `save` 过时才会给 `NotRemembered`
        // （`FileSecretStore` 的行为，见 rmc-win 的 105 条测试），别的
        // 四种结局都要求密文文件真的存在过。取回失败时也勾着，这样他
        // 重新输入之后连上，会按同一个 key 再记一次。
        form.remember = !matches!(outcome, LoadOutcome::NotRemembered);

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
    use rmc_core::code::{AccountName, ServerFingerprint};
    use rmc_win::secret::{FileSecretStore, Sealer};
    use std::sync::Arc;
    use zeroize::Zeroizing;

    /// 口令的金丝雀。独特串，不是两个字符——本项目第 17 个假绿就是
    /// 「短金丝雀在长输出里碰巧被掩盖」。
    const CANARY: &str = "canary-9d41c7-remembered-password";

    /// 一条合法的连接码，账号可选（不同账号用来演「换了账号」的场景），
    /// 地址固定 `203.0.113.10:22000`。**现生成，不手写常量**——手写的
    /// 校验位会算错。
    fn code_for(account: &str) -> String {
        ConnectionCode::new(
            AccountName::parse(account).unwrap(),
            "203.0.113.10".parse().unwrap(),
            22000,
            ServerFingerprint::of_ed25519_public(&[7u8; 32]),
        )
        .expect("夹具必须合法")
        .to_string()
    }

    fn good_code() -> String {
        code_for("tunnel-zhang")
    }

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

    /// 包一层**真实**存储，只在指定的 key 上让 `save` 失败——其余方法
    /// 原样转发。R11-2 的 W202 回归 PoC 要的是「A 的密文真的躺在盘上」
    /// 这个事实（不是假存储里的空气），同时要让「换成 B 的这次
    /// `save`」真的失败，`RecordingStore::failing_to_save()` 那种「全部
    /// 失败」的假货做不到这个组合。
    struct FailSaveOn<'a> {
        inner: &'a dyn SecretStore,
        fail_key: &'a str,
    }

    impl SecretStore for FailSaveOn<'_> {
        fn save(&self, key: &str, secret: &str) -> std::io::Result<()> {
            if key == self.fail_key {
                return Err(std::io::Error::other("模拟：这个 key 写不进去"));
            }
            self.inner.save(key, secret)
        }
        fn load_outcome(&self, key: &str) -> LoadOutcome {
            self.inner.load_outcome(key)
        }
        fn clear(&self, key: &str) -> std::io::Result<()> {
            self.inner.clear(key)
        }
    }

    fn filled_form() -> Form {
        Form {
            appliance_host: "192.168.100.10".into(),
            appliance_port: "61001".into(),
            code: good_code(),
            password: Zeroizing::new(CANARY.into()),
            remember: true,
            detected_proxy: None,
        }
    }

    // ================= key 与账号记录 =================

    /// key 就是 `账号@运维服务器 IP:端口`。
    ///
    /// 改红：把 `key()` 里的 `@` 换成别的分隔符，或者把 IP 与账号
    /// 对调——这条逐字比对，当场红。
    #[test]
    fn the_key_is_the_account_at_the_server() {
        let a = Account::from_form(&filled_form()).expect("表单填满了，该有账号");
        assert_eq!(a.key(), "tunnel-zhang@203.0.113.10:22000");
    }

    /// **W200 定案的要害**：`key()` 产出的字符串形态要跟升级前的旧版
    /// 三段式（`账号@主机:端口`）逐字一致——否则用户升级后取不回已经
    /// 记住的密码，而且不会报错（`SecretStore::load_outcome` 找不到就
    /// 是 `NotRemembered`，跟「从没记过」没有区别，用户会以为软件出了
    /// 别的问题）。
    ///
    /// 这条不检查实现细节，只检查**产出的字符串**——即使有人把
    /// `Account` 内部再重构一遍，只要这条字符串没变，旧密文就取得回来。
    ///
    /// 改红：把 `key()` 里 `self.code.ip()` 换成
    /// `self.code.server()`（`HostPort` 的 `Display` 会连端口一起打出
    /// 来，key 变成 `账号@IP:端口:端口`）——当场红。
    #[test]
    fn the_key_format_matches_the_old_three_part_shape_byte_for_byte() {
        let old_style = format!("{}@{}:{}", "tunnel-zhang", "203.0.113.10", "22000");
        let a = Account::from_form(&filled_form()).expect("表单填满了，该有账号");
        assert_eq!(a.key(), old_style);
    }

    /// 连接码解析不出来就没有 key，**不拼半截的**。
    #[test]
    fn an_incomplete_form_has_no_account() {
        for wreck in [
            |f: &mut Form| f.code.clear(),
            |f: &mut Form| f.code = "   ".into(),
            |f: &mut Form| f.code = "rmc1:nonsense".into(),
        ] {
            let mut f = filled_form();
            wreck(&mut f);
            assert!(Account::from_form(&f).is_none(), "{f:?} 不该拼出账号");
        }
        // 反向自证：填满的那一份确实拼得出来。
        assert!(Account::from_form(&filled_form()).is_some());
    }

    /// 写出去再读回来是同一个账号。
    #[test]
    fn an_account_survives_a_round_trip() {
        let a = Account::from_form(&filled_form()).expect("有账号");
        let back = Account::decode(&a.encode()).expect("写出去的应当读得回来");
        assert_eq!(back, a);
        assert_eq!(back.code().account().as_str(), "tunnel-zhang");
        assert_eq!(back.code().server().to_string(), "203.0.113.10:22000");
    }

    /// 格式不对就当没记过，**不猜**。
    #[test]
    fn a_broken_account_record_is_refused() {
        assert!(Account::decode("").is_none());
        assert!(Account::decode("这不是连接码").is_none());
        assert!(Account::decode("rmc1:nonsense").is_none());
        // 反向自证：合法的那一份能过，多一行尾随内容不影响——只看第一行。
        assert!(Account::decode(&format!("{}\n额外的一行\n", good_code())).is_some());
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
            store.load_outcome("tunnel-zhang@203.0.113.10:22000"),
            LoadOutcome::NotRemembered
        ));

        assert_eq!(
            save(&paths, store.as_ref(), &form),
            SaveOutcome::Saved {
                key: "tunnel-zhang@203.0.113.10:22000".into()
            }
        );

        // 主断言：按同一个 key 取得回来，而且是同一个口令。
        let got = store
            .load("tunnel-zhang@203.0.113.10:22000")
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

        let text = std::fs::read_to_string(paths.connection_code()).expect("账号记录应当写出来了");
        // 反向自证：文件确实有内容、确实是这个账号的、确实只有一行。
        assert!(text.contains("tunnel-zhang"), "{text}");
        assert!(text.contains("203.0.113.10"), "{text}");
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(!text.contains(CANARY), "账号记录里躺着明文口令：{text}");
        // 连片段都不许有。
        assert!(!text.contains("9d41c7"), "{text}");
    }

    /// **没勾（或者取消勾选）→ 密文清掉，连接码留着（Task 11）。**
    ///
    /// 在 Task 11 之前，`clear` 连账号记录（`connection-code.txt`）一起
    /// 删——这条测试当时叫 `..._clears_both_the_secret_and_the_account`。
    /// Task 11 把两者拆开：连接码不是秘密，也不是「记住密码」的一部分，
    /// 它现在只由 [`persist_code`] 独立维护，`clear` 不该碰它。
    ///
    /// 改红：把 `save` 里 `if !form.remember` 那一支删掉——取消勾选
    /// 之后密文还躺在盘上，而用户以为不再记住了（第一组断言红）；或者
    /// 把 `clear` 里的 `store.clear(key)` 删掉（同一组断言红）；或者在
    /// `clear` 末尾加回一句 `std::fs::remove_file(paths.connection_
    /// code())`——R11-2 修复轮把 `paths` 参数还给了 `clear`（它现在要
    /// 靠 `paths` 去删 `remembered_key` 记录），这条注入实测过真的能把
    /// 连接码那条断言（第二组）打红。
    #[test]
    fn unchecking_remember_clears_the_secret_but_keeps_the_code() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);

        save(&paths, store.as_ref(), &filled_form());
        // 反向自证：确实记住过，下面那两条断言因此带载。
        assert!(store.load("tunnel-zhang@203.0.113.10:22000").is_some());
        assert!(paths.connection_code().exists());

        let mut f = filled_form();
        f.remember = false;
        assert_eq!(save(&paths, store.as_ref(), &f), SaveOutcome::Cleared);

        assert!(
            store.load("tunnel-zhang@203.0.113.10:22000").is_none(),
            "取消勾选之后密文还在盘上"
        );
        // Task 11：连接码不再被 `clear` 删掉——它跟「记住密码」这个勾
        // 是两件事。
        assert!(
            paths.connection_code().exists(),
            "取消勾选却把连接码也删了：它不是秘密，不该跟着密文一起清"
        );
        // 再清一次不出事。
        assert_eq!(save(&paths, store.as_ref(), &f), SaveOutcome::Cleared);
    }

    /// 换一副夹具再验一遍同一根线：连接码这次由独立的 [`persist_code`]
    /// 落盘（不是靠 `save` 记住密码时顺手写的），取消勾选之后它照样
    /// 留着，密文目录清空。跟上面那条覆盖的是同一处 `clear`，但夹具
    /// 造法不同，任何一条测不到这条能测到。
    ///
    /// 改红：`clear` 末尾加回一句 `std::fs::remove_file(paths.
    /// connection_code())`——R11-2 把 `paths` 参数还给了 `clear`
    /// （删 `remembered_key` 记录要用它），这条注入实测过真的能打红。
    #[test]
    fn clearing_the_password_keeps_the_code() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);
        let form = filled_form();

        persist_code(&paths, &form).expect("落盘连接码不该失败");
        assert_eq!(
            save(&paths, store.as_ref(), &form),
            SaveOutcome::Saved {
                key: "tunnel-zhang@203.0.113.10:22000".into()
            }
        );
        // 反向自证：确实记住过。
        assert!(store.load("tunnel-zhang@203.0.113.10:22000").is_some());

        let mut f = form;
        f.remember = false;
        assert_eq!(save(&paths, store.as_ref(), &f), SaveOutcome::Cleared);

        assert!(
            store.load("tunnel-zhang@203.0.113.10:22000").is_none(),
            "取消勾选之后密文还在盘上"
        );
        assert!(paths.connection_code().exists(), "连接码不该被清掉");
        assert_eq!(sealed_files(&paths).len(), 0, "{:?}", sealed_files(&paths));
    }

    /// **W202：改了账号再取消勾选，旧密文不许留在盘上。**
    ///
    /// 评审的 PoC。上一版按**当前表单**拼出的 key 去清，于是：
    ///
    /// 1. 记住 `tunnel-zhang@运维服务器`；
    /// 2. 把连接码换成 `tunnel-li@同一台运维服务器`；
    /// 3. 取消勾选「记住密码」→ 清的是 `tunnel-li@...`（本来就不存在），
    ///    账号记录被删掉，而 `tunnel-zhang@...` 的密文**永久留在盘上，
    ///    而且再也没有任何路径指得到它**（下次启动 `recall` 直接
    ///    `NoAccount`）。
    ///
    /// 密文是 DPAPI 绑定的、不是明文泄露，但用户明确说了「不再记住」
    /// 而东西还在、还删不掉。
    ///
    /// 改红：把 `save` 里 `clear(..)` 的第四个参数（`previous.as_deref()`）
    /// 换成 `None`（也就是退回只清当前 key），第二组断言当场红。
    /// （R11-2 修复轮把 `paths` 参数还给了 `clear`——它现在要靠 `paths`
    /// 去删 `remembered_key` 记录，`previous` 因此又是第四个参数，跟
    /// Task 11 之前的位置一样，只是这次 `paths` 用来删的文件不同了。）
    #[test]
    fn changing_the_account_then_unchecking_leaves_no_orphan_ciphertext() {
        const KEY_A: &str = "tunnel-zhang@203.0.113.10:22000";
        const KEY_B: &str = "tunnel-li@203.0.113.10:22000";

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

        // 2. 用户把连接码换成 B（同一台运维服务器，账号不同），
        // 3. 取消勾选。
        let mut f = filled_form();
        f.code = code_for("tunnel-li");
        f.remember = false;
        assert_eq!(save(&paths, store.as_ref(), &f), SaveOutcome::Cleared);

        // 主断言：**旧账号的密文也清掉了**。
        assert!(
            store.load(KEY_A).is_none(),
            "改了账号再取消勾选，上一个账号的密文永久留在了盘上，\
             而且再也没有任何路径指得到它"
        );
        assert!(store.load(KEY_B).is_none());
        // Task 11：`clear` 不再删连接码，它现在只由 `persist_code` 管；
        // 这里留着的是第 1 步写下的 A——W202 关心的是密文不许成孤儿，
        // 不是这个文件本身。
        assert!(paths.connection_code().exists());
        // 盘上真的一个密文文件都不剩。
        assert_eq!(
            sealed_files(&paths).len(),
            0,
            "密文目录里还剩：{:?}",
            sealed_files(&paths)
        );
    }

    /// **R11-2 修复轮：W202 回归 PoC，收成正式测试。**
    ///
    /// Task 11 给 `connection-code.txt` 加了第二个写方
    /// （[`persist_code`]），它既不看「记住密码」的勾，也不管
    /// `save` 成没成功——生产路径上 `App::apply` 每次连接成功都会调它，
    /// 跟 `remember_password`（也就是这里的 [`save`]）的成败完全无关。
    ///
    /// 如果「盘上那份密文属于哪个 key」（[`previous_key`]）还读
    /// `connection-code.txt`，就会撞上这条真实路径：
    ///
    /// 1. 记住 `A@运维服务器` 成功；
    /// 2. 换成 `B@同一台运维服务器`，这次 `store.save` 失败（磁盘满、
    ///    权限变化……）；
    /// 3. `persist_code` 照样把 `connection-code.txt` 改成 `B`——它不
    ///    知道、也不该知道第 2 步失败了；
    /// 4. 用户取消勾选「记住密码」→ `previous_key` 读到 `B`（错的，
    ///    `B` 从来没有真的存进密文）→ `clear` 里
    ///    `previous.filter(|p| *p != key)` 把它当成「跟当前 key 一样」
    ///    过滤掉 → **只清了 `B`（本来就不存在），`A` 的密文一次都没被
    ///    碰过，而且从此没有任何路径指得到它**——永久孤儿。
    ///
    /// 修法（本轮）：`previous_key` 改读 [`AppPaths::remembered_key`]，
    /// 一份只由 [`save`] 自己的成功路径写的独立记录，`persist_code`
    /// 摸不到它。
    ///
    /// 改红：把 `previous_key` 里的 `std::fs::read_to_string(paths.
    /// remembered_key())` 换成 `std::fs::read_to_string(paths.
    /// connection_code()).ok().and_then(|t| Account::decode(&t)).map(|a|
    /// a.key())`（也就是退回读 `connection-code.txt`）——主断言当场红。
    #[test]
    fn persist_code_failing_a_save_does_not_orphan_the_previous_secret() {
        const KEY_A: &str = "tunnel-zhang@203.0.113.10:22000";
        const KEY_B: &str = "tunnel-li@203.0.113.10:22000";

        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);

        // 1. 记住 A 成功。
        assert_eq!(
            save(&paths, store.as_ref(), &filled_form()),
            SaveOutcome::Saved { key: KEY_A.into() }
        );
        // 反向自证：A 的密文真的躺在盘上。
        assert!(store.load(KEY_A).is_some(), "夹具没能先记住 A");

        // 2. 换成 B，这次 `store.save` 失败。
        let mut form_b = filled_form();
        form_b.code = code_for("tunnel-li");
        let failing = FailSaveOn {
            inner: store.as_ref(),
            fail_key: KEY_B,
        };
        let outcome = save(&paths, &failing, &form_b);
        assert!(
            matches!(outcome, SaveOutcome::Failed(_)),
            "夹具没能让这次 save 失败：{outcome:?}"
        );

        // 3. `App::apply` 里 `persist_connection_code` 跟 `remember_
        // password` 的成败无关，一样会跑——这是 Task 11 的立意，这条
        // 测试故意原样保留这一步，不能因为它「看起来是罪魁」就删掉它。
        persist_code(&paths, &form_b).expect("落盘连接码不该失败");
        assert_eq!(
            std::fs::read_to_string(paths.connection_code())
                .expect("connection-code.txt 应该在")
                .trim(),
            code_for("tunnel-li").trim(),
            "connection-code.txt 该被 persist_code 改成 B 了——这正是本测试的前提"
        );

        // 4. 用户取消勾选。
        let mut f = form_b;
        f.remember = false;
        assert_eq!(save(&paths, store.as_ref(), &f), SaveOutcome::Cleared);

        // 主断言：A 的密文没有变成孤儿——`previous_key` 没有被第 3 步
        // 误导，正确识别出 A 是「上一次记住的那个」并清掉了它。
        assert!(
            store.load(KEY_A).is_none(),
            "A 的密文成了孤儿：没有被清掉，也没有任何路径指得到它"
        );
        assert_eq!(sealed_files(&paths).len(), 0, "{:?}", sealed_files(&paths));
    }

    /// W202 的另一半：换一个账号继续记住，**上一份密文也不该留成孤儿**。
    ///
    /// `connection-code.txt` 只记得住一个账号，所以旧那份从此取不回来。
    ///
    /// 改红：把 `save` 末尾那段 `if let Some(old) = previous.filter(..)`
    /// 整块删掉——盘上会攒下两份密文，而其中一份谁也够不着。
    #[test]
    fn remembering_a_second_account_does_not_orphan_the_first_one() {
        const KEY_A: &str = "tunnel-zhang@203.0.113.10:22000";
        const KEY_B: &str = "tunnel-li@203.0.113.10:22000";

        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);

        save(&paths, store.as_ref(), &filled_form());
        assert!(store.load(KEY_A).is_some(), "夹具本该先记住 A");

        let mut f = filled_form();
        f.code = code_for("tunnel-li");
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
        assert_eq!(form.code, code_for("tunnel-li"));
        assert_eq!(*form.password, CANARY);
    }

    /// **新密文写失败时，上一份必须还在——顺序不能反过来。**
    ///
    /// `save` 里清旧 key 那一步**排在新的两样都写成之后**，注释写明了
    /// 理由：反过来的话新密文写失败时旧的那份已经被毁，用户两边都没了。
    ///
    /// 改红：把 `save` 里的 `store.clear(&old)` 挪到 `store.save(..)` 之前。
    #[test]
    fn a_failed_save_leaves_the_previous_secret_alone() {
        const KEY_A: &str = "tunnel-zhang@203.0.113.10:22000";

        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        // 上一次记的是 A——R11-2 之后这个前提由 `remembered_key` 记录，
        // 不是 `connection-code.txt`（那份记录跟密文毫无关系）。写的是
        // 裸 key 字符串，不经 `Account`——这条测试只关心磁盘上那份记录
        // 长什么样，不关心怎么构造出来的。
        std::fs::create_dir_all(paths.root()).expect("建目录");
        std::fs::write(paths.remembered_key(), KEY_A).expect("写密文定位键");

        // 这一次换成别的账号，而存储写不进去。
        let store = RecordingStore::failing_to_save();
        let mut f = filled_form();
        f.code = code_for("tunnel-li");
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
        // 反向自证：夹具真的走到了「有 previous」那条路——`remembered_
        // key` 记录还在，也就是说 `previous_key` 读得出东西来。
        assert!(
            paths.remembered_key().exists(),
            "夹具没造出「上一次记过别的账号」这个前提"
        );
    }

    /// **重复记住同一个账号，不许把刚存进去的那一份当成「上一个」清掉。**
    ///
    /// 这是生产里**最常走到**的一条路：用户勾着「记住密码」，每连成功
    /// 一次就走一遍 [`save`]，第二次起 `previous` 就等于当前 key。
    ///
    /// 改红：把 `save` 末尾 `previous.filter(|p| *p != key)` 里的
    /// `filter` 去掉——第二次「记住」会把自己刚存的密文清掉，下次启动
    /// 密码框是空的。
    #[test]
    fn remembering_the_same_account_twice_keeps_it() {
        const KEY: &str = "tunnel-zhang@203.0.113.10:22000";

        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);

        assert_eq!(
            save(&paths, store.as_ref(), &filled_form()),
            SaveOutcome::Saved { key: KEY.into() }
        );
        // 反向自证：第一次之后 `connection-code.txt` 确实在了，第二次的
        // `previous` 因此**不是** `None`——少了这一步，下面那次调用走的
        // 是跟第一次一样的路，什么都证明不了。
        assert!(paths.connection_code().exists());

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

    /// **`clear` 里第一步失败，后面几步也要走完。**
    ///
    /// 同 Task 4 的 `SecretStore::clear` 自己那条 W25：半路 `return` 会
    /// 把另外几样留在盘上，而用户点的是「不再记住密码」。
    ///
    /// `clear` 现在三步：清当前 key、清上一个 key、删
    /// `remembered_key` 记录（R11-2；跟 Task 11 之前的第三步不是同一个
    /// 文件——那时候第三步删的是账号记录 `connection-code.txt`，现在
    /// 那份记录已经不归 `clear` 管，见 [`persist_code`]；这里的第三步
    /// 删的是 `remembered_key`，「盘上那份密文属于哪个 key」这个答案，
    /// 清完密文这份记录也该跟着消失）。
    ///
    /// 改红：把 `clear` 里的 `let mut result = store.clear(key);` 换成
    /// `store.clear(key)?;`。
    #[test]
    fn clearing_finishes_every_step_even_after_the_first_one_fails() {
        const KEY_A: &str = "tunnel-zhang@203.0.113.10:22000";
        const KEY_B: &str = "tunnel-li@203.0.113.10:22000";

        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        // 上一次记的是 A——`remembered_key` 才是 `previous_key` 读的
        // 那份记录（R11-2）。账号记录（`connection-code.txt`）也顺手写
        // 一份，代表「用户确实连过 A」这个更完整的现实场景，也用来验证
        // 它不受这次 `clear` 影响。
        std::fs::create_dir_all(paths.root()).expect("建目录");
        std::fs::write(paths.remembered_key(), KEY_A).expect("写密文定位键");
        std::fs::write(
            paths.connection_code(),
            format!("{}\n", code_for("tunnel-zhang")),
        )
        .expect("写账号记录");

        // 当前表单是 B，取消勾选；而清 B 这一步会失败。
        let store = RecordingStore::failing_on(KEY_B);
        let mut f = filled_form();
        f.code = code_for("tunnel-li");
        f.remember = false;

        let out = save(&paths, &store, &f);

        // 夹具自证：确实失败了，下面几条因此不是空转。
        assert!(matches!(out, SaveOutcome::Failed(_)), "{out:?}");

        let cleared = store.cleared();
        // 第一步（当前 key）走了。
        assert!(cleared.contains(&KEY_B.to_string()), "{cleared:?}");
        // 第一步失败了，第二步（上一个 key）照样走。
        assert!(
            cleared.contains(&KEY_A.to_string()),
            "第一步失败就不走了，上一个账号的密文留在了盘上：{cleared:?}"
        );
        // **主断言之一**：第三步（删 `remembered_key`）也走了，尽管
        // 第一步失败了。
        assert!(
            !paths.remembered_key().exists(),
            "第一步失败就不走了，remembered_key 记录留在了盘上"
        );
        // 账号记录不归 `clear` 管，原样留着。
        assert!(
            paths.connection_code().exists(),
            "账号记录不该被 clear 删掉"
        );
    }

    /// **W203：账号记录写不成时，已经写进去的密文要回滚。**
    ///
    /// 这一支上一轮是**零覆盖**的（评审两枪双绿：把 `store.clear(&key)`
    /// 删掉、把失败分支改成返回 `Saved`，都没有任何测试变红）——它根本
    /// 进不去。它守的跟 W202 是同一个危害面：一份谁也找不回来的孤儿密文。
    ///
    /// 夹具（评审给的造法）：把 `connection-code.txt` 那个**路径先建成
    /// 一个目录**，`std::fs::write` 必失败，于是 `save` 走进回滚支。
    ///
    /// 改红：把那一支里的 `let _ = store.clear(&key);` 删掉，或者把
    /// `return SaveOutcome::Failed(..)` 改成 `SaveOutcome::Saved`。
    #[test]
    fn a_failed_account_record_rolls_the_ciphertext_back() {
        const KEY: &str = "tunnel-zhang@203.0.113.10:22000";

        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);
        // 路径被一个**目录**占住：`fs::write` 必失败。
        std::fs::create_dir_all(paths.connection_code()).expect("建目录");

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
    ///
    /// **终审 FR-3 调整了第一句的夹具**：`Form::default()` 的
    /// `remember` 是 `false`，而「不再记住」这条路现在**不依赖表单能否
    /// 解析**（见 [`save`] 开头那段），空表单 + 没勾 = 一次「清掉」
    /// （没东西可清，但结局是 `Cleared` 而不是 `Incomplete`）。
    /// `Incomplete` 现在专指「确实要存、但表单还拼不出 key 或口令是空
    /// 的」——这里就按那个意思重新造夹具：勾着、但连接码是空的。
    #[test]
    fn an_incomplete_form_saves_nothing() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);

        let empty = Form {
            remember: true,
            ..Form::default()
        };
        assert_eq!(
            save(&paths, store.as_ref(), &empty),
            SaveOutcome::Incomplete
        );
        let mut f = filled_form();
        f.password = Zeroizing::new(String::new());
        assert_eq!(save(&paths, store.as_ref(), &f), SaveOutcome::Incomplete);
        assert!(!paths.connection_code().exists(), "什么都不该落盘");
    }

    /// **终审 FR-3：取消勾选时连接码恰好不可解析，旧密文照样要清掉。**
    ///
    /// 原来 [`save`] 第一句就是 `Account::from_form(form)?`，解析不出来
    /// 直接 `Incomplete` 返回——**一个字节都不清**。于是「一边改连接码
    /// 一边把勾去掉」「粘贴只粘了半条」「把框清空重填」这类再普通不过的
    /// 操作，结局是：用户明确选了「不再记住」，而上一个账号的密文与
    /// `remembered-key.txt` 原样留在盘上，下次启动照样把口令自动填回
    /// 密码框，还什么都不说。
    ///
    /// 夹具里那条坏连接码是 `"rmc1:这不是连接码"`——它不含任何一个被
    /// 断言的关键词，也解析不出账号，`Account::from_form` 必定 `None`
    /// （下面第一句反向自证直接钉住这一点，不靠推断）。
    ///
    /// 改红（**实测过**，用等价、更小的一处注入）：在 [`save`] 里
    /// `if !form.remember {` 上面加一行
    /// `let Some(_probe) = Account::from_form(form) else { return
    /// SaveOutcome::Incomplete; };`——这就是「不再记住」那一支重新依赖
    /// 表单能否解析的老行为。实际输出：
    /// `assertion left == right failed: 用户说了不再记住，不能因为表单
    /// 拼不出 key 就整支跳过 / left: Incomplete / right: Cleared`。
    #[test]
    fn unchecking_remember_clears_even_when_the_code_no_longer_parses() {
        const KEY: &str = "tunnel-zhang@203.0.113.10:22000";

        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let store = store_at(&paths, FlipSealer);

        // 1. 先真的记住一份。
        assert_eq!(
            save(&paths, store.as_ref(), &filled_form()),
            SaveOutcome::Saved { key: KEY.into() }
        );
        // 反向自证：密文与「记住的是谁」两样都在盘上，下面的断言因此带载。
        assert!(store.load(KEY).is_some());
        assert!(paths.remembered_key().exists());

        // 2. 用户把连接码改坏了（还没改完、粘了半条……），同时把勾去掉。
        let mut f = filled_form();
        f.code = "rmc1:这不是连接码".into();
        f.remember = false;
        // 反向自证：这条连接码确实解析不出账号——否则这条测试测的就不是
        // 「解析不出来时也要清」。
        assert!(
            Account::from_form(&f).is_none(),
            "夹具的连接码必须是真的解析不出来的"
        );

        assert_eq!(
            save(&paths, store.as_ref(), &f),
            SaveOutcome::Cleared,
            "用户说了不再记住，不能因为表单拼不出 key 就整支跳过"
        );
        assert!(
            store.load(KEY).is_none(),
            "取消勾选时连接码恰好坏掉，旧账号的密文就永久留在盘上了"
        );
        assert!(
            !paths.remembered_key().exists(),
            "「记住的是谁」这份记录也该没了，留着就是撒谎"
        );
        assert_eq!(sealed_files(&paths).len(), 0, "{:?}", sealed_files(&paths));
    }

    // ================= Task 11：连接码独立落盘 =================

    /// **不勾记住密码，连接成功也要把连接码记下来；下次启动预填。**
    ///
    /// 这是本轮（Task 11）新加的函数：[`persist_code`] 不看
    /// `form.remember`——连接码不是秘密，「记住我上次连的是哪台」跟
    /// 「记住密码」是两件事，见模块文档「为什么还要多存一份
    /// `connection-code.txt`」一节。
    ///
    /// brief 原稿这条测试写的是 `recall(&paths, &NoStore)` 与
    /// `Recall { code, secret, .. }` 那个扁平结构——本文件里 `Recall`
    /// 早在 Task 4/8 就已经是 `NoAccount` / `Remembered { account,
    /// outcome }` 这个带四种失败分类的枚举，`NoStore` 这个类型也不存在
    /// （`SecretStore` 是 trait，测试一律用 `store_at(&paths,
    /// FlipSealer)` 造一个空的）。两者语义等价：`fill` 只在
    /// `outcome` 是 `Loaded` 时才填口令，跟 brief 说的「口令只在密文
    /// 存在且解得开时填」是同一件事，这里换成本文件的现成 API 验，
    /// 不重新发明一套。
    ///
    /// 改红：给 `persist_code` 加一句 `if !form.remember { return
    /// Ok(()); }`。
    ///
    /// R11-3 修复轮补的一条：`recall(...).fill(...)` 现在**不能**把
    /// 「记住密码」的勾自己点亮——这里从没调用过 `save`，盘上没有任何
    /// 密文，`load_outcome` 该是 `NotRemembered`，勾该保持不勾。改红：
    /// 把 `Recall::fill` 里的 `!matches!(outcome, LoadOutcome::
    /// NotRemembered)` 换回 `true`——这条断言当场红。
    #[test]
    fn the_code_is_persisted_regardless_of_remember() {
        let dir = tempfile::tempdir().expect("建临时目录");
        let paths = AppPaths::at(dir.path().to_path_buf());
        let mut f = filled_form();
        f.remember = false;

        persist_code(&paths, &f).expect("落盘连接码不该失败");

        let text =
            std::fs::read_to_string(paths.connection_code()).expect("连接码文件应当写出来了");
        assert_eq!(text.trim(), good_code().trim());

        // 没有任何密文：recall 只填连接码，口令留空，勾也不该自己亮起来
        // ——用户从没勾过「记住密码」，`persist_code` 只是记了「上次连的
        // 是哪台」，两件事不能混在一起。
        let store = store_at(&paths, FlipSealer);
        let mut form = Form::default();
        let note = recall(&paths, store.as_ref()).fill(&mut form);
        assert_eq!(form.code, good_code());
        assert!(form.password.is_empty(), "没有密文却填了口令");
        assert!(
            !form.remember,
            "从没记过密码，「记住密码」这个勾却自己跳出来了"
        );
        assert!(note.is_some(), "记过账号就该有一句说明");
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
        assert_eq!(form.code, good_code(), "连接码没有原样填回来");
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
        assert!(form.code.is_empty());
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
            // R11-3：只有 `NotRemembered` 这一格该让「记住密码」的勾
            // 保持不勾——它是「压根没有密文」，另外四格都意味着盘上真有
            // 一份密文记录（哪怕读不出来/解不开/坏了），「用户上次确实
            // 勾了」这条推断只对这四格成立。
            let not_remembered = matches!(outcome, LoadOutcome::NotRemembered);
            let recall = Recall::Remembered {
                account: Account::decode(&good_code()).expect("夹具连接码必须合法"),
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
            // 连接码无论成败都填上了。
            assert_eq!(form.code, good_code(), "{variant}：连接码没填回来");
            // R11-3：`NotRemembered` 那一格勾**不该**跟着回来（没有密文，
            // 不是「用户上次勾了」的证据）；另外四格才该。
            assert_eq!(
                form.remember, !not_remembered,
                "{variant}：「记住密码」这个勾该不该跟着回来，判反了"
            );
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
        // 连接码还在，用户重新输入密码就能接着用。
        assert_eq!(form.code, good_code());
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
