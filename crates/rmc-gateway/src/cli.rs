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

通用选项：
  --data-dir <目录>              数据目录（默认 $RMC_GATEWAY_DATA，否则 ~/.rmc-gateway）
  --listen <IP:端口>              监听地址（默认端口 22000；只用来算「监听端口不能分给账号」）
";

pub(crate) struct Parsed {
    pub cmd: Vec<String>,
    pub opts: Vec<(String, String)>,
}

/// `--k v` 与 `--k=v` 两种写法；不带 `--` 的按顺序进 cmd。
pub(crate) fn parse(args: &[String]) -> Result<Parsed, String> {
    let mut cmd = Vec::new();
    let mut opts = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(k) = a.strip_prefix("--") {
            if let Some((k, v)) = k.split_once('=') {
                opts.push((k.to_string(), v.to_string()));
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
}
