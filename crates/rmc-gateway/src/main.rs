#![forbid(unsafe_code)]
//! 薄壳：装订 tracing 订阅者（写 stderr，systemd 的 journal 里能直接看，
//! 审计事件也走 `tracing::info!(target: "audit", ...)`，见 `audit.rs`），
//! 剩下全部交给 `cli::run`。
fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive(
                "info"
                    .parse()
                    .expect("字面量 \"info\" 是合法的 tracing 过滤指令"),
            ),
        )
        .with_writer(std::io::stderr)
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = rmc_gateway::cli::run(&args, &mut std::io::stdout(), &mut std::io::stderr());
    std::process::exit(code);
}
