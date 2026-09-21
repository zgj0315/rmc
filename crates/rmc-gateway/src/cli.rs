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

通用选项：
  --data-dir <目录>              数据目录（默认 $RMC_GATEWAY_DATA，否则 ~/.rmc-gateway）
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
    if let Err(e) = GatewayConfig::new(addr).save(&dir) {
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

    #[test]
    fn unknown_subcommand_prints_usage() {
        let (code, _, err) = run_in(std::path::Path::new("."), &["frobnicate"]);
        assert_eq!(code, 2);
        assert!(err.contains("用法"));
    }
}
