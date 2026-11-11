//! Songbird load generator. Built in Prompt 2 (milestone M4) together with `crates/client`; this
//! placeholder keeps the workspace layout and CI shape stable until then.
#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    #[allow(clippy::print_stderr, reason = "CLI output")]
    {
        eprintln!("songbird-loadgen: not built yet (Prompt 2)");
    }
    std::process::ExitCode::from(2)
}
