//! 子命令。`run` 是纯函数：收参数与两个输出句柄，返回退出码。测试直接调它。

use crate::config::GatewayConfig;
use crate::datadir::DataDir;
use crate::identity::Identity;
use std::io::Write;
use std::net::SocketAddr;

pub const USAGE: &str = "\
用法：rmc-gateway <子命令> [选项]

  init --public-addr <IP:端口>   生成身份密钥与 config.toml（对外地址写进连接码）
  fingerprint                    打印本机指纹
  account add <名字> [--port N] [--note 文字]   开通账号，打印一次性口令与连接码
  account passwd <名字>                          重置口令，打印一次性新口令
  account revoke <名字>                          吊销账号（端口保留，不给别人复用）
  account list                                   列出所有账号与各自的连接码
  serve [--listen IP:端口] [--engineer-allow CIDR]... [--allow-root]
                                  启动运维服务器，直到 Ctrl+C
  status                          查询本机运维服务器是否在运行、有哪些在线隧道
  service print [--listen …] [--engineer-allow …]...
                                  打印一份 systemd 单元文本到标准输出（只打印，不装）

通用选项：
  --data-dir <目录>              数据目录（默认 $RMC_GATEWAY_DATA，否则 ~/.rmc-gateway）
  --listen <IP:端口>              监听地址（默认端口 22000；serve 用它真的绑；其余子命令只用来算
                                  「监听端口不能分给账号」）
  --engineer-allow <CIDR>        反向端口只放行这些网段的工程师来源；可重复给多次；不给则不过滤
  --allow-root                   serve 允许以 root 运行（默认拒绝；容器里只有 root 才需要）
";

/// 无值开关（布尔选项）：出现即真，不吃下一个参数。跟 `--k v` 那种「有值」
/// 选项的解析规则不一样，`parse` 要单独查这张表才知道该不该吃值——否则
/// `serve --allow-root` 会把下一个参数错当成 `--allow-root` 的值吞掉。
const FLAGS: &[&str] = &["allow-root"];

pub(crate) struct Parsed {
    pub cmd: Vec<String>,
    pub opts: Vec<(String, String)>,
}

/// `--k v` 与 `--k=v` 两种写法；`FLAGS` 里的无值开关只认「出现」，值固定为
/// `"true"`，不吃下一个参数；不带 `--` 的按顺序进 cmd。
///
/// **修复轮 1/5，评审 Blocking，已修**：`--allow-root=false` 原来会落进
/// `split_once('=')` 那一支（它排在 `FLAGS` 检查之前，且不管 `k` 是不是
/// 无值开关都直接收值），存成 `("allow-root", "false")`；`cmd_serve` 只查
/// `p.opt("allow-root").is_some()`，`Some("false")` 一样是 `Some`——一个人
/// 想显式**关掉**「允许 root」而写了 `--allow-root=false`，结果反而**放行**
/// 了 root。这是一个安全开关上的静默相反行为，代价是一次拼写习惯上的误用
/// 就能以 root 把服务跑起来，不能只按「影响面小」打 Minor。
///
/// 改法：`FLAGS` 里的名字**不允许**带 `=`，一旦出现 `--<flag>=<任何值>`，
/// 直接拒绝成用法错误（退出码 2），错误信息说清「这是无值开关，不要带
/// `=`」——明确报错比静默猜测使用者想要哪个值安全；`--allow-root` 本身
/// （不带 `=`）继续按无值开关处理。
pub(crate) fn parse(args: &[String]) -> Result<Parsed, String> {
    let mut cmd = Vec::new();
    let mut opts = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(k) = a.strip_prefix("--") {
            if let Some((k, v)) = k.split_once('=') {
                if FLAGS.contains(&k) {
                    return Err(format!(
                        "--{k} 是一个无值开关，不要带 `=`：写 --{k} 本身就够了，\
                         不要写成 --{k}={v}（这样写会被误当成给它赋了一个字符串值，\
                         而不是真的关掉它）"
                    ));
                }
                opts.push((k.to_string(), v.to_string()));
            } else if FLAGS.contains(&k) {
                opts.push((k.to_string(), "true".to_string()));
            } else {
                let v = args.get(i + 1).ok_or_else(|| format!("--{k} 缺少值"))?;
                opts.push((k.to_string(), v.clone()));
                i += 1;
            }
        } else {
            cmd.push(a.clone());
        }
        i += 1;
    }
    Ok(Parsed { cmd, opts })
}

impl Parsed {
    pub fn opt(&self, k: &str) -> Option<&str> {
        self.opts
            .iter()
            .rev()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    }
    pub fn data_dir(&self) -> DataDir {
        match self.opt("data-dir") {
            Some(p) => DataDir::at(p.into()),
            None => DataDir::at(DataDir::default_path()),
        }
    }
}

pub fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let p = match parse(args) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(err, "{e}\n{USAGE}");
            return 2;
        }
    };
    match p
        .cmd
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["init"] => cmd_init(&p, out, err),
        ["fingerprint"] => cmd_fingerprint(&p, out, err),
        ["account", "add", name] => cmd_account_add(&p, name, out, err),
        ["account", "passwd", name] => cmd_account_passwd(&p, name, out, err),
        ["account", "revoke", name] => cmd_account_revoke(&p, name, out, err),
        ["account", "list"] => cmd_account_list(&p, out, err),
        ["serve"] => cmd_serve(&p, out, err),
        ["status"] => cmd_status(&p, out, err),
        ["service", "print"] => cmd_service_print(&p, out, err),
        _ => {
            let _ = write!(err, "{USAGE}");
            2
        }
    }
}

fn cmd_init(p: &Parsed, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let addr: SocketAddr = match p.opt("public-addr").map(str::parse) {
        Some(Ok(a)) => a,
        Some(Err(e)) => {
            let _ = writeln!(err, "--public-addr 不是 IP:端口：{e}");
            return 2;
        }
        None => {
            let _ = writeln!(
                err,
                "init 需要 --public-addr <IP:端口>（写进连接码的对外地址）"
            );
            return 2;
        }
    };
    // R——评审 Important 4：原来先 `dir.create()` + `Identity::create_in()`
    // 落盘、最后才在 `GatewayConfig::save` 里 `validate()` 检查端口是不是 0。
    // `init --public-addr 1.2.3.4:0` 能解析成合法的 `SocketAddr`，会先把身份
    // 密钥写出去、config.toml 才因为端口 0 保存失败——用户改成合法端口重跑，
    // 会被身份文件「已存在，拒绝覆盖」挡回，只能手工删 `identity.key`。一次
    // 打错端口不该付这个恢复成本，所以校验要挪到**任何文件系统副作用之前**。
    let cfg = GatewayConfig::new(addr);
    if let Err(e) = cfg.validate() {
        let _ = writeln!(err, "--public-addr 不合法：{e}");
        return 2;
    }
    let dir = p.data_dir();
    if let Err(e) = dir.create() {
        let _ = writeln!(err, "建不了数据目录 {}：{e}", dir.root().display());
        return 1;
    }
    let id = match Identity::create_in(&dir) {
        Ok(i) => i,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return 1;
        }
    };
    if let Err(e) = cfg.save(&dir) {
        let _ = writeln!(err, "{e}");
        return 1;
    }
    let _ = writeln!(
        out,
        "数据目录：{}\n指纹：{}\n对外地址：{addr}\n下一步：rmc-gateway account add <账号>，然后 rmc-gateway serve",
        dir.root().display(),
        id.fingerprint()
    );
    0
}

fn cmd_fingerprint(p: &Parsed, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    match Identity::load_from(&p.data_dir()) {
        Ok(id) => {
            let _ = writeln!(out, "{}", id.fingerprint());
            0
        }
        Err(e) => {
            let _ = writeln!(err, "{e}");
            1
        }
    }
}

// ---------------------------------------------------------------- account 四个子命令

struct Loaded {
    dir: DataDir,
    cfg: GatewayConfig,
    id: Identity,
}

/// 装载数据目录、config.toml、身份密钥；三者缺一都说清楚「先运行 init」。
fn load(p: &Parsed, err: &mut dyn Write) -> Option<Loaded> {
    let dir = p.data_dir();
    let cfg = match GatewayConfig::load(&dir) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return None;
        }
    };
    let id = match Identity::load_from(&dir) {
        Ok(i) => i,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return None;
        }
    };
    Some(Loaded { dir, cfg, id })
}

/// 账号的连接码。`public_addr` 的端口在 `GatewayConfig::load`/`validate` 时
/// 已经校验过非 0（config.rs 的 `validate`），`ConnectionCode::new` 唯一会
/// 报错的条件在这里必定不成立——`expect` 够不着，理由同 `code.rs` 里
/// `ConnectionCode::server()` 那个 `expect`。
fn code_for(l: &Loaded, a: &crate::accounts::Account) -> rmc_core::code::ConnectionCode {
    rmc_core::code::ConnectionCode::new(
        a.name.clone(),
        l.cfg.public_addr.ip(),
        l.cfg.public_addr.port(),
        l.id.fingerprint(),
    )
    .expect("public_addr 的端口已在 config.load 时校验非 0")
}

fn listen_port(p: &Parsed) -> u16 {
    p.opt("listen")
        .and_then(|s| s.parse::<SocketAddr>().ok())
        .map(|a| a.port())
        .unwrap_or(crate::config::DEFAULT_LISTEN_PORT)
}

fn cmd_account_add(p: &Parsed, name: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(l) = load(p, err) else { return 1 };
    let name = match rmc_core::code::AccountName::parse(name) {
        Ok(n) => n,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return 2;
        }
    };
    let port = match p.opt("port").map(str::parse::<u16>) {
        Some(Ok(v)) => Some(v),
        Some(Err(_)) => {
            let _ = writeln!(err, "--port 不是端口号");
            return 2;
        }
        None => None,
    };
    let store = crate::accounts::AccountStore::open(&l.dir, &l.cfg, listen_port(p));
    match store.add(&name, port, p.opt("note").unwrap_or("")) {
        Ok((a, pw)) => {
            record_account_changed(&l.dir, name.as_str(), "add");
            let _ = writeln!(out, "账号 {} 已开通，端口 {}。", a.name, a.port);
            let _ = writeln!(out, "连接码：  {}", code_for(&l, &a));
            let _ = writeln!(out, "初始口令：{}      （只显示这一次）", pw.as_str());
            let _ = writeln!(
                out,
                "远程工程师：ssh -p {} root@{}",
                a.port,
                l.cfg.public_addr.ip()
            );
            0
        }
        Err(e) => {
            let _ = writeln!(err, "{e}");
            1
        }
    }
}

fn cmd_account_passwd(p: &Parsed, name: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(l) = load(p, err) else { return 1 };
    let name = match rmc_core::code::AccountName::parse(name) {
        Ok(n) => n,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return 2;
        }
    };
    let store = crate::accounts::AccountStore::open(&l.dir, &l.cfg, listen_port(p));
    match store.reset_password(&name) {
        Ok(pw) => {
            record_account_changed(&l.dir, name.as_str(), "passwd");
            let _ = writeln!(
                out,
                "账号 {name} 新口令：{}      （只显示这一次）",
                pw.as_str()
            );
            0
        }
        Err(e) => {
            let _ = writeln!(err, "{e}");
            1
        }
    }
}

fn cmd_account_revoke(p: &Parsed, name: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(l) = load(p, err) else { return 1 };
    let name = match rmc_core::code::AccountName::parse(name) {
        Ok(n) => n,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return 2;
        }
    };
    let store = crate::accounts::AccountStore::open(&l.dir, &l.cfg, listen_port(p));
    match store.revoke(&name) {
        Ok(()) => {
            record_account_changed(&l.dir, name.as_str(), "revoke");
            let port = store
                .list()
                .ok()
                .and_then(|list| list.into_iter().find(|a| a.name == name))
                .map(|a| a.port);
            match port {
                Some(port) => {
                    let _ = writeln!(
                        out,
                        "账号 {name} 已吊销，最迟 10 秒内踢掉在线会话；端口 {port} 保留"
                    );
                }
                None => {
                    let _ = writeln!(out, "账号 {name} 已吊销，最迟 10 秒内踢掉在线会话");
                }
            }
            0
        }
        Err(e) => {
            let _ = writeln!(err, "{e}");
            1
        }
    }
}

fn cmd_account_list(p: &Parsed, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(l) = load(p, err) else { return 1 };
    let store = crate::accounts::AccountStore::open(&l.dir, &l.cfg, listen_port(p));
    match store.list() {
        Ok(accounts) => {
            for a in &accounts {
                let status = if a.enabled { "启用" } else { "已吊销" };
                let _ = writeln!(out, "{}  {}  {}  {}", a.name, a.port, status, a.note);
                let _ = writeln!(out, "连接码：  {}", code_for(&l, a));
            }
            0
        }
        Err(e) => {
            let _ = writeln!(err, "{e}");
            1
        }
    }
}

/// account 三个改写子命令成功后记一条 `AccountChanged` 审计事件。写审计
/// 日志失败不影响 CLI 本身的成功——这是本来就该发生的事的旁路记录，不是
/// 前提条件；`AuditLog::open` 失败（比如权限问题）只值得一条日志提示，
/// 不该让整条命令的退出码从 0 变成非 0。
fn record_account_changed(dir: &DataDir, account: &str, action: &str) {
    match crate::audit::AuditLog::open(dir) {
        Ok(log) => log.record(crate::audit::AuditEvent::AccountChanged {
            account: account.to_string(),
            action: action.to_string(),
        }),
        Err(e) => tracing::warn!(error = %e, "记 AccountChanged 审计事件失败"),
    }
}

// ---------------------------------------------------------------- serve / status / service print

/// `serve` 拒绝以 root 运行的判定：纯函数，不做任何 IO，方便单独测试。
///
/// **为什么拒绝，不只是「拒绝」**：本程序监听的默认端口是 22000、反向端口
/// 22001-22999，都不是需要特权的端口（< 1024），没有任何理由需要 root——
/// 唯一的效果是把这个进程一旦出现漏洞（不管是这个程序自己的，还是它依赖的
/// 哪个包的）能造成的后果放大到整台机器。运维应该换一个普通用户来跑，
/// `service print` 生成的 systemd 单元就是这么做的（`User=` 那一行）；
/// 只有容器里确实只有 root 用户可用这一种场景，才该加 `--allow-root` 放行。
pub fn refuse_root(is_root: bool, allow_root: bool) -> Option<String> {
    if is_root && !allow_root {
        Some(
            "拒绝以 root 运行：本程序监听的不是特权端口（默认 22000，反向端口 \
             22001-22999 都在 1024 以上），没有任何理由需要 root 权限——那只会把\
             一旦出现漏洞能造成的后果放大到整台机器。请换一个普通用户运行（推荐用 \
             `rmc-gateway service print` 生成的 systemd 单元，它就是这么做的）。\
             只有容器里确实只有 root 用户可用时，才加 --allow-root 放行。"
                .into(),
        )
    } else {
        None
    }
}

/// `serve` 早检查专用：身份密钥文件本身能不能打开，按 `io::ErrorKind`
/// 分诊出准确的提示。返回 `Some(退出码)` 表示已经写好错误、调用方直接
/// `return`；`None` 表示这一步没发现问题，继续往下走。
///
/// **修复轮 2/5，评审 Blocking，新增**：见 `cmd_serve` 里这次调用点上方
/// 那段长注释——不能复用 `Identity::load_from` 的错误文案，它对任何
/// io 错误都无差别地建议「先运行 init」，权限损坏时这条建议是错的、
/// 而且会被拒绝。
fn check_identity_key_present(dir: &DataDir, err: &mut dyn Write) -> Option<i32> {
    match std::fs::File::open(dir.identity_key()) {
        Ok(_) => None,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let _ = writeln!(
                err,
                "数据目录 {} 下没有身份密钥；先运行 init",
                dir.root().display()
            );
            Some(1)
        }
        Err(e) => {
            let _ = writeln!(
                err,
                "打不开身份密钥 {}：{e}（不是「文件不存在」，检查这份文件与所在目录的属主/权限，\
                 不要再跑 init——身份文件已经存在，init 会拒绝覆盖它）",
                dir.identity_key().display()
            );
            Some(1)
        }
    }
}

fn cmd_serve(p: &Parsed, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if let Some(why) = refuse_root(
        crate::datadir::running_as_root(),
        p.opt("allow-root").is_some(),
    ) {
        let _ = writeln!(err, "{why}");
        return 1;
    }
    let dir = p.data_dir();
    // **修复轮 1/5，评审 Important，已修，随后被修复轮 2/5 的复审发现回归、
    // 已重做**：`serve` 是第一个用户真会敲的命令。数据目录从来没被 `init`
    // 建过时，下面 `owned_by_current_user` 的探针（往目录里建一个临时
    // 文件）会因为目录不存在而失败，原来直接把那条裸 io 错误
    // （"No such file or directory (os error 2)" 这种）甩给用户——第一次
    // 用就撞上一条读不懂的系统错误，体验很差。
    //
    // 修复轮 1/5当时的做法是先调 `Identity::load_from(&dir)`，复用它自己
    // 已经带了「先运行 init」这句提示的错误文案（`identity.rs::load_from`）。
    // **这一步引入了一条回归，复审实测复现过**：`identity.rs::load_from`
    // 对**任何** io 错误（不只是"文件不存在"）都无差别地套上「先运行
    // init」——`init` 明明跑过、只是事后 `chmod 000 identity.key`（权限
    // 损坏），或者数据目录由用户 A 建、用户 B 拿去跑 `serve`（属主不对，
    // 连穿透目录都做不到），这两种场景下 `Identity::load_from` 一样会说
    // 「读不到 .../identity.key：Permission denied (os error 13)；先运行
    // init」——这不只是不够准确，是**建议了一个会被拒绝的错误动作**：
    // 再跑一次 `init` 会因为身份文件已存在被「拒绝覆盖」挡回，用户没有
    // 从这句提示里得到任何能真正解决问题的信息。
    //
    // 改法：**不复用 `Identity::load_from` 的错误文案**，改成这里自己先
    // 探一下身份密钥文件本身「能不能打开」，按 `io::ErrorKind` 分诊：
    // `NotFound`（目录或文件真的不存在）才是「从未 init」，说「先运行
    // init」；别的任何 io 错误（权限损坏是最常见的一种）都不建议这个
    // 动作，转而指向属主/权限——这正是 `owned_by_current_user()` 下面
    // 那支 `Err` 分支本来就在做的诊断，两者的措辞刻意保持一致。
    // `std::fs::File::open` 只探测这一个文件能不能读，不做完整的身份
    // 校验（种子格式、指纹计算等）——那些校验仍然只在真正需要用到身份
    // 密钥的地方（`Server::bind` 内部）做一次，这里不重复。
    if let Some(code) = check_identity_key_present(&dir, err) {
        return code;
    }
    match dir.owned_by_current_user() {
        Ok(true) => {}
        Ok(false) => {
            let _ = writeln!(
                err,
                "数据目录 {} 的属主不是当前用户；serve 与 account 子命令要用同一个用户运行",
                dir.root().display()
            );
            return 1;
        }
        Err(e) => {
            let _ = writeln!(err, "检查数据目录失败：{e}");
            return 1;
        }
    }
    let listen: SocketAddr = match p.opt("listen").unwrap_or("0.0.0.0:22000").parse() {
        Ok(a) => a,
        Err(e) => {
            let _ = writeln!(err, "--listen 不是 IP:端口：{e}");
            return 2;
        }
    };
    let mut engineer_allow = Vec::new();
    for (k, v) in &p.opts {
        if k == "engineer-allow" {
            match crate::cidr::Cidr::parse(v) {
                Ok(c) => engineer_allow.push(c),
                Err(e) => {
                    let _ = writeln!(err, "--engineer-allow：{e}");
                    return 2;
                }
            }
        }
    }
    // 白名单在反向端口 accept 之后判断（见 `server.rs::reverse_accept_loop`），
    // 不改绑定地址：`--engineer-allow` 收窄的是「谁能连反向端口」，不是
    // 「反向端口绑在哪个地址上」——生产环境反向端口本来就要绑 0.0.0.0，
    // 白名单只是在那之上再收窄一层来源判断。
    let cfg = crate::server::ServerConfig {
        listen,
        data: dir.clone(),
        reverse_bind: "0.0.0.0".parse().expect("字面量合法的 IP"),
        engineer_allow,
        timings: crate::server::Timings::default(),
        limits: crate::throttle::Limits::default(),
    };
    let _ = writeln!(out, "数据目录 {}，监听 {listen}", dir.root().display());
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(err, "建不出运行时：{e}");
            return 1;
        }
    };
    match rt.block_on(crate::server::serve_until(cfg, async {
        let _ = tokio::signal::ctrl_c().await;
    })) {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            1
        }
    }
}

fn cmd_status(p: &Parsed, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let dir = p.data_dir();
    match crate::status::read(&dir) {
        Ok(Some(st)) if crate::status::is_live(&st, crate::status::now_unix()) => {
            let _ = writeln!(
                out,
                "运行中（pid {}），监听 {}，指纹 {}",
                st.pid, st.listen, st.fingerprint
            );
            if st.tunnels.is_empty() {
                let _ = writeln!(out, "没有在线隧道");
            }
            for t in &st.tunnels {
                let _ = writeln!(
                    out,
                    "{}  端口 {}  来自 {}  自 {}  工程师连接 {}",
                    t.account, t.port, t.peer, t.since, t.engineers
                );
            }
            0
        }
        // 有 status.json，但超过 `STALE_AFTER_SECS` 没更新——不能读成
        // 「运行中」：进程可能已经崩了、被 kill -9 了，或者机器重启后
        // 数据目录是从备份恢复的、pid 早就不指向这个进程了。
        Ok(Some(st)) => {
            let _ = writeln!(
                out,
                "没有在跑（最后一次状态更新 {}，pid {}）",
                crate::clock::rfc3339(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(st.updated_unix)
                ),
                st.pid
            );
            3
        }
        Ok(None) => {
            let _ = writeln!(
                out,
                "没有在跑（数据目录 {} 下没有状态文件）",
                dir.root().display()
            );
            3
        }
        Err(e) => {
            let _ = writeln!(err, "{e}");
            1
        }
    }
}

/// systemd 的 `ExecStart=`/`ReadWritePaths=` 都按空白切分成一串 token
/// （`systemd.syntax(7)`「quoting」那一节），跟 shell 的分词规则很像但不
/// 是同一套实现；一个 token 内部要是含空白，就必须用双引号包起来，双引号
/// 与反斜杠本身也要转义，否则空白会被当成 token 分隔符。
///
/// **修复轮 1/5，评审 Blocking，已修**：这里原来直接把路径/选项值拼进
/// 格式化字符串，一个字符都没转义。数据目录带空格（比如 `--data-dir
/// "/srv/rmc gateway"`，或者二进制装在带空格的路径下）时，systemd 会把
/// `--data-dir` 与 `ReadWritePaths=` 里的路径从空格处切成两段——服务照样
/// 能起来，但 `--data-dir` 实际吃到的只是空格前那一半，指向一个错的（或
/// 者不存在的）目录，而且**不报错**，运维很难查到这是路径拼接没加引号
/// 造成的。
/// **修复轮 2/5，评审同类失败形态，已修**：systemd 对 `ExecStart=` 这类
/// 字段还会做一遍「specifier 展开」——字面 `$FOO`/`${FOO}` 会被替换成同名
/// 环境变量的值（没设置就是空串），这一步跟按空白分词/加引号是两件事、
/// 先后独立发生，跟这个值要不要用双引号包起来无关。含 `$` 的路径不会
/// 报错，只会被**静默**展开成别的（通常更短、更残缺的）值——跟这个函数
/// 已经在处理的"空格被切开"是同一种"静默走偏、不报错"的失败形态，只是
/// 触发条件更少见。改法：先把字面 `$` 换成 `$$`（systemd 转义 `$` 的
/// 写法），再走原来的空白/引号判断。`ReadWritePaths=` 是否也做 specifier
/// 展开没有十足把握确认，但它也经过这个函数——多转一次没有坏处，两处
/// 都一起处理了。
fn quote_systemd_arg(s: &str) -> String {
    let escaped_dollar = s.replace('$', "$$");
    if escaped_dollar
        .chars()
        .any(|c| c.is_whitespace() || c == '"' || c == '\\')
    {
        let escaped = escaped_dollar.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        escaped_dollar
    }
}

/// `User=` 是否是一个「看起来像合法用户名」的值：只允许小写字母、数字、
/// `_`、`-`，且以字母或 `_` 开头，长度不超过 32——这比真正的 passwd 规则
/// 更严一点，但足够堵死空白与任何控制字符（尤其是换行）。
///
/// **修复轮 2/5，评审 Blocking，新增**：`User=` 的值来自 `$USER`/
/// `$LOGNAME` 环境变量，**不是** passwd 库校验过的用户名——环境变量可以
/// 被设成任意字节，实测 `USER="a b" rmc-gateway service print` 会把
/// `User=a b` 原样写进单元文本。`User=` 是普通的 `Key=Value` 配置项，
/// **不走** `ExecStart=` 那套按空白分词、能用双引号包起来的语法——给它
/// 套 `quote_systemd_arg` 反而会把字面双引号写进用户名值，变成一个包含
/// 引号字符的非法用户名，比现在更糟。真正的风险不是空格，是**换行
/// 注入**：`$USER` 里含 `\n` 会在生成的单元文本里插进一整行新内容，
/// 理论上可以借此注入任意 systemd 指令。所以这里不做转义，做校验/清洗：
/// 值不像一个合法用户名就整个丢弃，回退到默认值 `"rmc-gateway"`，调用方
/// 据此在打印出的单元文本里加一行警告注释。**函数不把原始值传回去**——
/// 一个含换行的值本身就能在"注释"这个上下文里插入新行，注释挡不住这种
/// 注入，唯一安全的做法是压根不回显它。
fn sanitize_unit_user(raw: &str) -> (String, bool) {
    let looks_like_a_username = !raw.is_empty()
        && raw.len() <= 32
        && raw
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && raw
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if looks_like_a_username {
        (raw.to_string(), false)
    } else {
        ("rmc-gateway".to_string(), true)
    }
}

fn cmd_service_print(p: &Parsed, out: &mut dyn Write, _err: &mut dyn Write) -> i32 {
    let user_env = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "rmc-gateway".into());
    let (user, user_was_sanitized) = sanitize_unit_user(&user_env);
    let user_warning = if user_was_sanitized {
        "# 警告：USER/LOGNAME 环境变量的值不像一个合法用户名（出于安全考虑，\n\
         # 原始值不会打印在这里），已回退成 rmc-gateway；请自行确认下面这一行\n\
         # User= 是不是你想要的账户，必要时手工改掉。\n"
    } else {
        ""
    };
    let exe = quote_systemd_arg(
        &std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "/usr/local/bin/rmc-gateway".into()),
    );
    let dir = p.data_dir();
    let dir_display = dir.root().display().to_string();
    let mut args = format!("serve --data-dir {}", quote_systemd_arg(&dir_display));
    if let Some(l) = p.opt("listen") {
        args.push_str(&format!(" --listen {}", quote_systemd_arg(l)));
    }
    for (k, v) in &p.opts {
        if k == "engineer-allow" {
            args.push_str(&format!(" --engineer-allow {}", quote_systemd_arg(v)));
        }
    }
    let read_write_paths = quote_systemd_arg(&dir_display);
    // **只打印文本，不动系统**：本程序自己不建用户、不写 /etc、不调
    // systemctl。装不装这个单元、`useradd` 那个专用用户，都是管理员自己
    // 决定与执行的事——这里的注释与下面 systemd 单元里的注释是给管理员
    // 看的，不是给这个程序自己看的。
    let _ = write!(
        out,
        "\
# 安装：
#   rmc-gateway service print > rmc-gateway.service
#   sudo install -m 644 rmc-gateway.service /etc/systemd/system/
#   sudo systemctl daemon-reload && sudo systemctl enable --now rmc-gateway
# 本程序自己不做任何需要特权的事；装不装这个单元由管理员决定。
{user_warning}[Unit]
Description=Remote Maintenance Server (rmc-gateway)
After=network-online.target
Wants=network-online.target

[Service]
User={user}
ExecStart={exe} {args}
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={read_write_paths}

[Install]
WantedBy=multi-user.target
"
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_in(dir: &std::path::Path, args: &[&str]) -> (i32, String, String) {
        let mut a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        a.push("--data-dir".into());
        a.push(dir.to_string_lossy().into_owned());
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let code = run(&a, &mut o, &mut e);
        (
            code,
            String::from_utf8(o).unwrap(),
            String::from_utf8(e).unwrap(),
        )
    }

    #[test]
    fn init_creates_identity_and_config_and_prints_the_fingerprint() {
        let tmp = tempfile::tempdir().unwrap();
        let (code, out, err) = run_in(tmp.path(), &["init", "--public-addr", "203.0.113.10:22000"]);
        assert_eq!(code, 0, "{err}");
        assert!(tmp.path().join("identity.key").exists());
        assert!(tmp.path().join("config.toml").exists());
        let (code2, fp, _) = run_in(tmp.path(), &["fingerprint"]);
        assert_eq!(code2, 0);
        assert!(
            out.contains(fp.trim()),
            "init 打印的指纹要跟 fingerprint 一致：{out} / {fp}"
        );
        assert_eq!(fp.trim().len(), 43);
    }

    #[test]
    fn init_twice_refuses_and_keeps_the_first_identity() {
        let tmp = tempfile::tempdir().unwrap();
        run_in(tmp.path(), &["init", "--public-addr", "203.0.113.10:22000"]);
        let (_, fp1, _) = run_in(tmp.path(), &["fingerprint"]);
        let (code, _, err) = run_in(tmp.path(), &["init", "--public-addr", "203.0.113.11:22000"]);
        assert_eq!(code, 1);
        assert!(err.contains("拒绝覆盖"), "{err}");
        let (_, fp2, _) = run_in(tmp.path(), &["fingerprint"]);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn init_without_public_addr_is_a_usage_error() {
        let tmp = tempfile::tempdir().unwrap();
        let (code, _, err) = run_in(tmp.path(), &["init"]);
        assert_eq!(code, 2);
        assert!(err.contains("public-addr"), "{err}");
    }

    /// R——评审 Important 4：端口 0 在 `SocketAddr::parse` 那一步是合法的，
    /// 真正的校验在 `GatewayConfig::validate`；这条测试盯的是"校验必须挪到任何
    /// 文件系统副作用之前"——不只是最终退出码对，身份密钥与 config.toml 都不能
    /// 落地，否则用户改对端口重跑会被"已存在，拒绝覆盖"挡住。
    /// 改红：把 `cmd_init` 里 `cfg.validate()` 那次前置检查删掉（退回到只在
    /// `cfg.save` 内部才校验）——`identity.key` 会先被写出来，
    /// `!... .exists()` 那句红。
    #[test]
    fn init_with_port_zero_is_a_usage_error_and_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (code, _, err) = run_in(tmp.path(), &["init", "--public-addr", "1.2.3.4:0"]);
        assert_eq!(code, 2, "{err}");
        assert!(err.contains("不合法"), "{err}");
        // R——复审顺手补的一条：原来只具名核对 identity.key/config.toml 两个
        // 文件不存在；换成核对整个目录一个文件都没有，断言力度跟测试名字里
        // 「writes_nothing」对得上——万一以后哪个实现改动往目录里写了别的
        // 文件（不是这两个名字），具名检查看不出来，`read_dir` 能。
        let names: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(names.is_empty(), "不该写任何文件：{names:?}");
    }

    #[test]
    fn unknown_subcommand_prints_usage() {
        let (code, _, err) = run_in(std::path::Path::new("."), &["frobnicate"]);
        assert_eq!(code, 2);
        assert!(err.contains("用法"));
    }

    #[test]
    fn account_add_prints_a_parsable_connection_code_and_a_password_once() {
        let tmp = tempfile::tempdir().unwrap();
        run_in(tmp.path(), &["init", "--public-addr", "203.0.113.10:22000"]);
        let (code, out, err) = run_in(tmp.path(), &["account", "add", "zhang", "--note", "张三"]);
        assert_eq!(code, 0, "{err}");
        let line = out
            .lines()
            .find(|l| l.starts_with("连接码："))
            .expect("要有连接码");
        let cc = line.trim_start_matches("连接码：").trim();
        let parsed = rmc_core::code::ConnectionCode::parse(cc).expect("连接码要能被客户端解析");
        assert_eq!(parsed.account().as_str(), "zhang");
        assert_eq!(parsed.port(), 22000);
        let (_, fp, _) = run_in(tmp.path(), &["fingerprint"]);
        assert_eq!(parsed.fingerprint().to_string(), fp.trim());
        assert!(out.contains("初始口令："));
        // list 里重取的连接码一字不差
        let (_, listed, _) = run_in(tmp.path(), &["account", "list"]);
        assert!(listed.contains(cc), "{listed}");
        assert!(!listed.contains("初始口令"), "list 不能再打印口令");
    }

    #[test]
    fn account_commands_before_init_fail_with_a_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let (code, _, err) = run_in(tmp.path(), &["account", "add", "zhang"]);
        assert_eq!(code, 1);
        assert!(err.contains("init"), "{err}");
    }

    /// **修复轮 1/5，评审 Important，补的「改红」**：brief 原文没给这条测试
    /// 配注释，评审逐条核实覆盖面后要求补齐。
    ///
    /// 改红：把 `refuse_root` 里 `if is_root && !allow_root` 的 `!allow_root`
    /// 那个 `!` 删掉（变成 `if is_root && allow_root`）——`refuse_root(true,
    /// false)` 这时候算出 `true && false = false`，函数返回 `None`，第一句
    /// `assert!(refuse_root(true, false).is_some())` 红。
    #[test]
    fn refuse_root_is_a_pure_rule() {
        assert!(refuse_root(true, false).is_some());
        assert!(refuse_root(true, true).is_none());
        assert!(refuse_root(false, false).is_none());
    }

    /// 改红：把 `parse` 里 `FLAGS.contains(&k)` 那一支删掉（退回到
    /// 「所有 `--k` 都吃下一个参数当值」）——`serve --allow-root` 会把
    /// `--allow-root` 的值错吃成下一个参数，这条测试用 `account list`
    /// 顶替 `serve` 的位置来验证同一件事：无值开关不该吃值。
    #[test]
    fn allow_root_is_a_value_less_flag_and_does_not_eat_the_next_argument() {
        let p = parse(&[
            "serve".to_string(),
            "--allow-root".to_string(),
            "--listen".to_string(),
            "0.0.0.0:22000".to_string(),
        ])
        .unwrap();
        assert_eq!(p.opt("allow-root"), Some("true"));
        assert_eq!(p.opt("listen"), Some("0.0.0.0:22000"));
    }

    /// **修复轮 1/5，评审 Important，补的「改红」**：同上，brief 没配，
    /// 评审要求补齐。
    ///
    /// 改红：把 `cmd_status` 里 `Ok(None) => { ...; 3 }` 那一支的退出码
    /// `3` 改成 `0`——`assert_eq!(code, 3)` 红。
    #[test]
    fn status_before_serve_says_not_running() {
        let tmp = tempfile::tempdir().unwrap();
        let (code, out, _) = run_in(tmp.path(), &["status"]);
        assert_eq!(code, 3);
        assert!(out.contains("没有在跑"), "{out}");
    }

    /// **修复轮 1/5，评审 Important，补的「改红」**：同上，brief 没配，
    /// 评审要求补齐。
    ///
    /// 改红：把 `cmd_service_print` 里 `for (k, v) in &p.opts { if k ==
    /// "engineer-allow" { ... } }` 那一段整段删掉——输出里不再出现
    /// `--engineer-allow 10.0.0.0/8` 这个片段，`for needle in [...]`
    /// 循环里那一句 `assert!(out.contains(needle), ...)` 红（命中的是
    /// `"--engineer-allow 10.0.0.0/8"` 这个 needle）。
    #[test]
    fn service_print_carries_the_data_dir_listen_and_allow_list() {
        let tmp = tempfile::tempdir().unwrap();
        let (code, out, _) = run_in(
            tmp.path(),
            &[
                "service",
                "print",
                "--listen",
                "0.0.0.0:22000",
                "--engineer-allow",
                "10.0.0.0/8",
            ],
        );
        assert_eq!(code, 0);
        for needle in [
            "[Service]",
            "User=",
            "ExecStart=",
            "serve --data-dir",
            "--listen 0.0.0.0:22000",
            "--engineer-allow 10.0.0.0/8",
            "NoNewPrivileges=yes",
            "ReadWritePaths=",
        ] {
            assert!(out.contains(needle), "缺 {needle}：\n{out}");
        }
        assert!(out.contains(&tmp.path().display().to_string()));
    }

    /// serve 真的把服务端拉起来、写了 status.json、收到 stop 后干净退出。
    ///
    /// 改红：把 `Running::shutdown` 末尾那句
    /// `std::fs::remove_file(self.shared.data.status())` 删掉——最后一句
    /// `assert!(crate::status::read(&d).unwrap().is_none())` 红，
    /// `serve_until` 收到 stop 之后 status.json 会留在原地，`status`
    /// 子命令要等满 30 秒的 `STALE_AFTER_SECS` 才会说「没在跑」。
    #[tokio::test]
    async fn serve_until_runs_and_stops_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let mut a = vec![
            "init".to_string(),
            "--public-addr".into(),
            "127.0.0.1:22000".into(),
            "--data-dir".into(),
            tmp.path().display().to_string(),
        ];
        let (mut o, mut e) = (Vec::new(), Vec::new());
        assert_eq!(run(&a, &mut o, &mut e), 0);
        a.clear();
        let d = crate::datadir::DataDir::at(tmp.path().to_path_buf());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let cfg = crate::server::ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            data: d.clone(),
            reverse_bind: "127.0.0.1".parse().unwrap(),
            engineer_allow: vec![],
            timings: crate::server::Timings::fast(),
            limits: crate::throttle::Limits::default(),
        };
        let task = tokio::spawn(crate::server::serve_until(cfg, async {
            let _ = rx.await;
        }));
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            crate::status::read(&d).unwrap().is_some(),
            "serve 起来后要有 status.json"
        );
        tx.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert!(crate::status::read(&d).unwrap().is_none());
    }

    /// `account add/passwd/revoke` 各记一条 `AccountChanged` 审计事件，
    /// `action` 字段跟子命令名对得上。
    ///
    /// 改红：把 `cmd_account_add` 里 `record_account_changed(&l.dir,
    /// name.as_str(), "add")` 那一行删掉——`add` 这个动作在审计日志里
    /// 消失，第一句 `assert_eq!(actions, vec!["add", "passwd", "revoke"])`
    /// 红（实际只剩 `["passwd", "revoke"]`）。
    #[test]
    fn account_add_passwd_revoke_each_record_an_account_changed_audit_event() {
        let tmp = tempfile::tempdir().unwrap();
        run_in(tmp.path(), &["init", "--public-addr", "203.0.113.10:22000"]);
        run_in(tmp.path(), &["account", "add", "zhang"]);
        run_in(tmp.path(), &["account", "passwd", "zhang"]);
        run_in(tmp.path(), &["account", "revoke", "zhang"]);
        let d = crate::datadir::DataDir::at(tmp.path().to_path_buf());
        let log = crate::audit::AuditLog::open(&d).unwrap();
        let text = std::fs::read_to_string(log.path_for(std::time::SystemTime::now())).unwrap();
        let actions: Vec<String> = text
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["event"] == "account_changed")
            .map(|v| v["action"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(actions, vec!["add", "passwd", "revoke"]);
    }

    /// **修复轮 1/5，评审 Blocking，新增**：`--allow-root=false` 这种写法
    /// 曾经会被静默接受成"允许 root"（`split_once('=')` 那一支不管 `k`
    /// 是不是无值开关都直接收值，`cmd_serve` 只看 `is_some()`），是安全
    /// 开关上的静默相反行为。现在改成一律拒绝成用法错误。
    ///
    /// 改红：把 `parse` 里新加的 `if FLAGS.contains(&k) { return
    /// Err(...) }` 那一支删掉（退回到修复前的行为）——`parse(...)` 不再
    /// 报错，`assert!(parse(...).is_err())` 红；即使只看值，
    /// `p.opt("allow-root")` 会变成 `Some("false")`，跟"应该报错、不该有
    /// 这个值"这件事本身就矛盾。
    #[test]
    fn allow_root_with_equals_is_a_usage_error_not_a_silent_value() {
        let err = match parse(&["serve".to_string(), "--allow-root=false".to_string()]) {
            Err(e) => e,
            Ok(_) => panic!("--allow-root=<任何值> 都该被拒绝，不该被当成一个正常选项接受"),
        };
        assert!(err.contains("allow-root"), "{err}");
        assert!(err.contains('='), "{err}");
    }

    /// **修复轮 1/5，评审 Important，新增**：`serve` 是第一个用户真会敲的
    /// 命令，从没 `init` 过的数据目录不该甩给用户一条读不懂的裸 io 错误。
    ///
    /// **这条测试专门用一个连目录本身都没建过的路径**（`base.path().join(
    /// "brand-new")`，只拼路径字符串，从不 `create_dir`），不是随手
    /// `tempfile::tempdir()` 给的那种"目录已经存在，只是没跑 init"的路径
    /// ——这个区分是实测出来的，不是随便选的：如果目录已经存在，
    /// `dir.owned_by_current_user()` 的探针（往目录里建一个临时文件）
    /// 本身就会成功，不管有没有加 `Identity::load_from` 那道早检查，
    /// 执行都会往下走到 `Server::bind` 内部才因为读不到 `identity.key`
    /// 失败——错误文本里同样带"先运行 init"，两条路径殊途同归，那种
    /// 写法测不出「加了早检查以后到底改变了什么」。**只有目录本身就不
    /// 存在**这种场景才能分开两条路径：不加早检查会先撞上
    /// `owned_by_current_user` 的裸 io 错误（"检查数据目录失败：{e}"，
    /// 不含 "init"）。
    ///
    /// **「改红」实测记录，如实写下走过的两次弯路**（第二次是我自己的
    /// 测试写错，不是"照 brief 字面注入"那种假支票，但同样是"字面上像
    /// 改红、实测却全绿"，按同一条纪律处理）：
    ///
    /// 1. 最初这条测试用的是 `tempfile::tempdir().unwrap()` 给的、已经
    ///    存在的目录，字面删掉 `cmd_serve` 里那段 `if let Err(e) =
    ///    Identity::load_from(&dir) { ...; return 1; }`，实测**全绿**——
    ///    跟上一段分析的原因一致：`owned_by_current_user()` 在已存在的
    ///    目录上直接成功，执行流继续往下走进
    ///    `rt.block_on(serve_until(...))`，`Server::bind` 内部的
    ///    `Identity::load_from(&cfg.data)` 一样失败、一样把同一句"先运行
    ///    init"的错误文本冒泡回 `cmd_serve` 的 `Err(e)` 分支——最终看到的
    ///    `code`/`err` 跟没删这段代码时一模一样，这是一张假支票。
    /// 2. 改用"目录本身不存在"的路径后，第一版把目录名字写成
    ///    `"never-initialized"`——删掉早检查再跑，`assert!(err.contains(
    ///    "init"))` 仍然**全绿**，用 `eprintln!` 打出 `err` 实际内容才
    ///    发现：`err` 是裸 io 错误"检查数据目录失败：No such file or
    ///    directory ... at path .../never-initialized/.tmpXXXX"，根本不含
    ///    程序打印的"先运行 init"提示——但 `err.contains("init")` 照样
    ///    为真，因为**目录名字自己**"never-**init**ialized"里字面包含
    ///    子串 "init"！断言测的是路径字符串里偶然出现的四个字符，不是
    ///    程序真的打印了那句提示。这是我自己出的一张假支票，改法是换一个
    ///    不含 "init" 子串的目录名（`"brand-new"`），断言才是真的在测
    ///    程序输出而不是测目录名拼字。
    ///
    /// 改红（用上面这个不含 "init" 子串的目录名重新验证过，确认真红）：
    /// 把 `cmd_serve` 里 `if let Err(e) = Identity::load_from(&dir) {
    /// ...; return 1; }` 那一段删掉——`serve` 会往下走到
    /// `dir.owned_by_current_user()`，对一个不存在的目录探针建临时文件会
    /// 失败，落进 `Err(e) => "检查数据目录失败：{e}"` 那一支，错误文本里
    /// 不会再出现 "init" 这个词，`assert!(err.contains("init"))` 红。
    #[test]
    fn serve_before_init_says_run_init_first() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("brand-new");
        let (code, _, err) = run_in(&dir, &["serve"]);
        assert_eq!(code, 1, "{err}");
        assert!(err.contains("init"), "{err}");
    }

    /// **修复轮 1/5，评审 Blocking，新增**：`service print` 原来直接把
    /// 路径拼进 `ExecStart=`/`ReadWritePaths=`，一个字符都不转义。数据
    /// 目录带空格时 systemd 会把它从空格处切成两个 token——服务能起来，
    /// 但指向的是错的半截路径，而且不报错。
    ///
    /// 改红：把 `quote_systemd_arg` 在拼 `args`（`--data-dir` 那一句）与
    /// `read_write_paths` 处的调用都换成不加引号的裸 `dir_display`——
    /// 两句 `contains(&quoted)` 断言都会红：输出里出现的是没加引号、
    /// 从空格处能被 systemd 切开的裸路径，不是整段被双引号包住的路径。
    #[test]
    fn service_print_quotes_a_data_dir_containing_whitespace_for_systemd() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("dir with space");
        std::fs::create_dir_all(&dir).unwrap();
        let args = vec![
            "service".to_string(),
            "print".to_string(),
            "--data-dir".to_string(),
            dir.display().to_string(),
        ];
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let code = run(&args, &mut o, &mut e);
        assert_eq!(code, 0);
        let out = String::from_utf8(o).unwrap();
        let quoted = format!("\"{}\"", dir.display());
        assert!(
            out.contains(&format!("--data-dir {quoted}")),
            "带空格的数据目录要被双引号包住，不能被 systemd 从空格处切开：\n{out}"
        );
        assert!(
            out.contains(&format!("ReadWritePaths={quoted}")),
            "ReadWritePaths 同样要被引起来：\n{out}"
        );
    }

    /// **修复轮 2/5，评审 Blocking，新增（修复轮 1/5 引入的回归）**：
    /// `init` 明明跑过、只是身份密钥文件权限损坏（比如 `chmod 000`），
    /// 不该被误诊成「从未 init」——那条建议还会被拒绝（身份文件已存在，
    /// `init` 会拒绝覆盖它，用户没有从这句提示里得到任何能解决问题的
    /// 信息）。这条测试就是复审给的复现步骤本身：`init` 成功之后把
    /// `identity.key` 权限拿掉再 `serve`。
    ///
    /// 改红：把 `check_identity_key_present` 里
    /// `Err(e) if e.kind() == std::io::ErrorKind::NotFound` 这个分诊
    /// 条件删掉（退回到不分诊、直接把任何 io 错误都导向同一句提示的
    /// 行为）——错误文本会变回「...；先运行 init」，
    /// `assert!(!err.contains("先运行 init"))` 红。
    #[cfg(unix)]
    #[test]
    fn serve_with_a_permission_broken_identity_key_does_not_suggest_running_init_again() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let (code, _, err) = run_in(tmp.path(), &["init", "--public-addr", "203.0.113.10:22000"]);
        assert_eq!(code, 0, "{err}");
        let key = tmp.path().join("identity.key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o000)).unwrap();
        let (code, _, err) = run_in(tmp.path(), &["serve"]);
        // 不管测试跑没跑完，先把权限还原，免得 `tempdir` 在 `Drop` 时
        // 清理这个 0o000 的文件遇到麻烦。
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(code, 1, "{err}");
        assert!(
            !err.contains("先运行 init"),
            "权限损坏不该被误诊成「从未 init」：{err}"
        );
        assert!(
            err.contains("属主") || err.contains("权限"),
            "错误应该指向属主/权限这个真实原因：{err}"
        );
    }

    /// **修复轮 2/5，评审 Blocking，新增**：`$USER`/`$LOGNAME` 不是
    /// passwd 库校验过的用户名，可以被设成任意字节；这条测试直接钉住
    /// `sanitize_unit_user` 这个纯函数的判定逻辑，不依赖修改进程环境变量
    /// （那样会在并行跑测试时有极小概率互相干扰）——`USER="a b"` 这个
    /// 端到端场景在报告里贴了手工验证的实际输出。
    ///
    /// 改红：把 `sanitize_unit_user` 里 `looks_like_a_username` 的判断
    /// 整个换成 `true`（等价于什么都不清洗、直接放行任何值）——
    /// `sanitize_unit_user("a b")` 会原样返回 `("a b".to_string(),
    /// false)`，第一句 `assert_eq!(u, "rmc-gateway")` 红。
    #[test]
    fn sanitize_unit_user_rejects_whitespace_and_control_characters() {
        let (u, sanitized) = sanitize_unit_user("a b");
        assert_eq!(u, "rmc-gateway");
        assert!(sanitized);

        let (u, sanitized) = sanitize_unit_user("a\nUser=root");
        assert_eq!(u, "rmc-gateway");
        assert!(sanitized, "换行注入也必须被拒绝，不能只挡空格");

        let (u, sanitized) = sanitize_unit_user("");
        assert_eq!(u, "rmc-gateway");
        assert!(sanitized);

        let (u, sanitized) = sanitize_unit_user("zhang-3");
        assert_eq!(u, "zhang-3");
        assert!(!sanitized, "合法用户名不该被回退");
    }

    /// **修复轮 2/5，评审同类失败形态，已修，新增**：含 `$` 的路径会被
    /// systemd 的 specifier 展开静默替换成别的值而不报错——跟"空格被
    /// 切开"是同一种"静默走偏、不报错"的失败形态。
    ///
    /// 改红：把 `quote_systemd_arg` 里 `s.replace('$', "$$")` 那一行删掉
    /// （直接用 `s` 本身）——输出里的 `$` 不再被转义成 `$$`，
    /// `assert!(out.contains(...))` 那两句都红（因为它们要找的是转义后的
    /// `$$`形态，原样的 `$` 不会出现在预期的位置上）。
    #[test]
    fn service_print_escapes_dollar_signs_in_the_data_dir_for_systemd() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("has$dollar");
        std::fs::create_dir_all(&dir).unwrap();
        let args = vec![
            "service".to_string(),
            "print".to_string(),
            "--data-dir".to_string(),
            dir.display().to_string(),
        ];
        let (mut o, mut e) = (Vec::new(), Vec::new());
        let code = run(&args, &mut o, &mut e);
        assert_eq!(code, 0);
        let out = String::from_utf8(o).unwrap();
        let expected_escaped = dir.display().to_string().replace('$', "$$");
        assert!(
            out.contains(&format!("--data-dir {expected_escaped}")),
            "$ 应该被转成 $$，防止 systemd 静默展开成别的值：\n{out}"
        );
        assert!(
            out.contains(&format!("ReadWritePaths={expected_escaped}")),
            "ReadWritePaths 同样要转义：\n{out}"
        );
    }
}
