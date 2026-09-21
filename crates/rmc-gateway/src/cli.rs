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
pub(crate) fn parse(args: &[String]) -> Result<Parsed, String> {
    let mut cmd = Vec::new();
    let mut opts = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(k) = a.strip_prefix("--") {
            if let Some((k, v)) = k.split_once('=') {
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

fn cmd_serve(p: &Parsed, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if let Some(why) = refuse_root(
        crate::datadir::running_as_root(),
        p.opt("allow-root").is_some(),
    ) {
        let _ = writeln!(err, "{why}");
        return 1;
    }
    let dir = p.data_dir();
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

fn cmd_service_print(p: &Parsed, out: &mut dyn Write, _err: &mut dyn Write) -> i32 {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "rmc-gateway".into());
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "/usr/local/bin/rmc-gateway".into());
    let dir = p.data_dir();
    let mut args = format!("serve --data-dir {}", dir.root().display());
    if let Some(l) = p.opt("listen") {
        args.push_str(&format!(" --listen {l}"));
    }
    for (k, v) in &p.opts {
        if k == "engineer-allow" {
            args.push_str(&format!(" --engineer-allow {v}"));
        }
    }
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
[Unit]
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
ReadWritePaths={dir}

[Install]
WantedBy=multi-user.target
",
        dir = dir.root().display()
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

    #[test]
    fn status_before_serve_says_not_running() {
        let tmp = tempfile::tempdir().unwrap();
        let (code, out, _) = run_in(tmp.path(), &["status"]);
        assert_eq!(code, 3);
        assert!(out.contains("没有在跑"), "{out}");
    }

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
}
