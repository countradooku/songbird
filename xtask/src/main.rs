//! Repeatable project commands. Run `cargo xtask help`.
//!
//! CI calls exactly these commands, so a green `cargo xtask ci` locally means a green pipeline
//! (modulo tools only installed in CI, which are reported, never silently skipped).
#![forbid(unsafe_code)]
#![allow(
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::exit,
    reason = "a developer CLI: output and exit codes are its interface"
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

mod secret_scope;
mod workflows;

type Result<T = ()> = std::result::Result<T, String>;

const HELP: &str = "\
cargo xtask <command>

  ci [fast|deep]        quality bar from the constitution (default: fast)
                          fast: workflows, fmt, clippy -D warnings, nextest, doctests, rustdoc,
                                deny, audit, vet, smoke
                          deep: fast + fuzz (10 min/target), ASan, TSan, Miri, benchmarks
  workflows             CI policy for .github/workflows (D-0045): standard GitHub-hosted
                          runners only, release and deploy on tags or by hand only, secrets
                          only there, pinned actions, read-only token, concurrency
  secret-scope          push provider credentials and the push key are named in deploy/ and
                          config/ only by the push task and secrets-init (D-0097)
  smoke                 start every service, check /readyz and /metrics, SIGTERM, expect exit 0
  sanitize              workspace tests under ASan and TSan (nightly, -Zbuild-std)
  miri                  Miri on the pure crates (nightly)
  bench [ARGS...]       cargo bench --workspace (extra args go to the bench harness)
  fuzz [--secs N] [T..] run fuzz targets (nightly + cargo-fuzz), default 60 s each, all targets
  release [--target T] [--verify]
                        reproducible release build, SHA256SUMS and CycloneDX SBOM in
                        target/dist/; --verify builds twice in different directories and
                        fails unless every binary is bit-identical
  dev-env [--force]     write .env with fresh random secrets for docker compose (local only)
  compose up|down|ps    docker compose for local development and CI integration tests
  autobahn              Autobahn WebSocket conformance suite against the delivery service's
                          WebSocket layer (docker or podman); fails on any unexpected result
";

const SERVICES: &[(&str, u16)] = &[
    ("delivery", 9101),
    ("api", 9102),
    ("push", 9103),
    ("worker", 9104),
    ("calls", 9105),
];
const RELEASE_BINS: &[&str] = &[
    "songbird-delivery",
    "songbird-api",
    "songbird-push",
    "songbird-worker",
    "songbird-calls",
    "songbird-proxy",
    "songbird-admin",
];

fn main() -> ExitCode {
    // CLI flags only; argv[0] is skipped and nothing is trusted from it.
    let args: Vec<String> = std::env::args().skip(1).collect(); // nosemgrep: rust.lang.security.args.args
    let root = workspace_root();
    if let Err(e) = std::env::set_current_dir(&root) {
        eprintln!("xtask: cannot enter {}: {e}", root.display());
        return ExitCode::FAILURE;
    }
    let (cmd, rest) = args
        .split_first()
        .map_or(("help", &[][..]), |(c, r)| (c.as_str(), r));
    let r = match cmd {
        "ci" => ci(rest.first().map_or("fast", String::as_str)),
        "workflows" => workflows::check(Path::new(".github/workflows")),
        "secret-scope" => secret_scope::check(Path::new(".")),
        "smoke" => smoke(),
        "sanitize" => sanitizers(),
        "miri" => miri(),
        "bench" => bench(rest),
        "fuzz" => fuzz(rest),
        "release" => release(rest),
        "dev-env" => dev_env(rest.iter().any(|a| a == "--force")),
        "compose" => compose(rest),
        "autobahn" => autobahn(),
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            Ok(())
        }
        other => Err(format!("unknown command `{other}`\n\n{HELP}")),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map_or(manifest.clone(), Path::to_path_buf)
}

fn step(title: &str) {
    eprintln!("\n==> {title}");
}

fn run(cmd: &mut Command) -> Result {
    let shown = format!("{cmd:?}");
    let st = cmd.status().map_err(|e| format!("{shown}: {e}"))?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("{shown} failed ({st})"))
    }
}

fn output(cmd: &mut Command) -> Result<String> {
    let shown = format!("{cmd:?}");
    let out = cmd
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("{shown}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{shown} failed ({})", out.status));
    }
    String::from_utf8(out.stdout).map_err(|_| format!("{shown}: output is not UTF-8"))
}

fn cargo() -> Command {
    Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
}

/// `cargo +nightly` through the rustup proxy (the `CARGO` the xtask runs under is the pinned
/// stable toolchain's binary, which does not understand `+toolchain`).
fn cargo_nightly() -> Command {
    let mut c = Command::new("cargo");
    c.arg("+nightly")
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("RUSTC")
        .env_remove("CARGO");
    c
}

fn has_cargo_tool(sub: &str) -> bool {
    cargo()
        .args([sub, "--version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn require_tool(sub: &str, install: &str) -> Result {
    if has_cargo_tool(sub) {
        Ok(())
    } else {
        Err(format!("cargo {sub} not installed: {install}"))
    }
}

// ---------------------------------------------------------------- ci

fn ci(level: &str) -> Result {
    let deep = match level {
        "fast" => false,
        "deep" => true,
        other => return Err(format!("ci level must be fast or deep, not `{other}`")),
    };
    step("workflow policy (hosted runners only, pins, read-only token, D-0045)");
    workflows::check(Path::new(".github/workflows"))?;
    step("push credentials only in the push service (D-0097)");
    secret_scope::check(Path::new("."))?;
    step("rustfmt");
    run(cargo().args(["fmt", "--all", "--", "--check"]))?;
    step("clippy (pedantic + selected restriction lints, -D warnings)");
    run(cargo().args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ]))?;
    step("tests (nextest)");
    require_tool("nextest", "cargo install --locked cargo-nextest")?;
    run(cargo().args([
        "nextest",
        "run",
        "--workspace",
        "--locked",
        "--profile",
        "ci",
    ]))?;
    step("doctests");
    run(cargo().args(["test", "--doc", "--workspace", "--locked"]))?;
    step("rustdoc (-D warnings)");
    run(cargo()
        .args(["doc", "--workspace", "--no-deps", "--locked"])
        .env("RUSTDOCFLAGS", "-D warnings"))?;
    step("cargo deny (advisories, bans, licences, sources)");
    require_tool("deny", "cargo install --locked cargo-deny")?;
    run(cargo().args(["deny", "--locked", "check"]))?;
    step("cargo audit");
    require_tool("audit", "cargo install --locked cargo-audit")?;
    run(cargo().args(["audit", "--deny", "warnings"]))?;
    step("cargo vet");
    require_tool("vet", "cargo install --locked cargo-vet")?;
    run(cargo().args(["vet", "--locked"]))?;
    step("smoke: every service starts, serves health and metrics, drains on SIGTERM");
    smoke()?;
    if deep {
        step("fuzz (10 minutes per target)");
        fuzz(&["--secs".into(), "600".into()])?;
        step("sanitizers");
        sanitizers()?;
        step("miri");
        miri()?;
        step("benchmarks");
        bench(&[])?;
    }
    eprintln!("\nci {level}: all checks passed");
    Ok(())
}

fn host_triple() -> Result<String> {
    let v = output(Command::new("rustc").arg("-vV"))?;
    v.lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| "cannot determine host triple".into())
}

fn sanitizers() -> Result {
    let target = host_triple()?;
    // Narrow, reviewed suppressions only (see the file); an absolute path because each test
    // binary runs in its own crate's directory.
    let supp = std::env::current_dir()
        .map_err(|e| e.to_string())?
        .join("xtask/tsan-suppressions.txt");
    if !supp.is_file() {
        return Err(format!("{} missing", supp.display()));
    }
    let tsan_options = format!("halt_on_error=1 suppressions=\"{}\"", supp.display());
    let mut failed = Vec::new();
    for san in ["address", "thread"] {
        eprintln!("--- -Zsanitizer={san}");
        // `songbird_sanitizer` swaps mimalloc for the system allocator: the sanitizer runtimes see
        // only allocations they intercept, and mimalloc's uninstrumented free lists read as races.
        let flags = format!("-Zsanitizer={san} --cfg songbird_sanitizer");
        let dir = format!("target/san-{san}");
        // Every sanitizer runs even when the one before it failed.
        if let Err(e) = run(cargo_nightly()
            .args([
                "test",
                "--workspace",
                "--lib",
                "--tests",
                // Report every failing test binary, not just the first one.
                "--no-fail-fast",
                "-Zbuild-std",
                "--target",
                &target,
            ])
            .env("RUSTFLAGS", &flags)
            .env("RUSTDOCFLAGS", &flags)
            .env("CARGO_TARGET_DIR", &dir)
            .env("TSAN_OPTIONS", &tsan_options))
        {
            eprintln!("{e}");
            failed.push(san);
        }
        // Each build-std tree is several gigabytes; two of them filled a hosted runner's disk
        // (nightly run 43402308599). CI checkouts start clean, so nothing is lost there.
        if std::env::var_os("CI").is_some() {
            match std::fs::remove_dir_all(&dir) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(format!("{dir}: {e}"));
                }
                _ => {}
            }
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("sanitizers failed: {}", failed.join(", ")))
    }
}

fn miri() -> Result {
    // The workspace forbids `unsafe`; Miri still runs the pure crate to catch UB in the dependency
    // code paths we exercise. File-system tests are `cfg_attr(miri, ignore)`; property tests run
    // a handful of cases (Miri is 100-1000x slower) so the nightly job stays within its timeout.
    run(cargo_nightly()
        .args(["miri", "test", "-p", "songbird-types"])
        .env("MIRIFLAGS", "-Zmiri-disable-isolation")
        .env("PROPTEST_CASES", "4"))?;
    // The one `unsafe` exception (D-0033): the test-only counting allocator.
    run(cargo_nightly().args(["miri", "test", "-p", "songbird-alloc-count"]))
}

// ---------------------------------------------------------------- smoke

fn http_get(port: u16, path: &str) -> Result<(u16, String)> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .map_err(|e| e.to_string())?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).map_err(|e| e.to_string())?;
    let status = buf
        .get(9..12)
        .and_then(|c| c.parse().ok())
        .ok_or("malformed response")?;
    let body = buf
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    Ok((status, body))
}

fn smoke() -> Result {
    run(cargo().args(["build", "--workspace", "--bins", "--locked"]))?;
    let mut failures = Vec::new();
    for (name, port) in SERVICES {
        let bin = PathBuf::from(format!("target/debug/songbird-{name}"));
        let mut child = Command::new(&bin)
            .args(["--config", &format!("config/dev/{name}.toml")])
            .stdout(Stdio::null())
            .spawn()
            .map_err(|e| format!("{}: {e}", bin.display()))?;
        let check = (|| -> Result {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if let Ok((200, _)) = http_get(*port, "/readyz") {
                    break;
                }
                if Instant::now() > deadline {
                    return Err("not ready within 15 s".into());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let (status, body) = http_get(*port, "/metrics")?;
            if status != 200 {
                return Err(format!("/metrics returned {status}"));
            }
            if !body.contains(&format!("songbird_build_info{{service=\"{name}\"")) {
                return Err("/metrics lacks build_info".into());
            }
            if !body.contains("songbird_telemetry_refused_callsites_total 0") {
                return Err(
                    "a log callsite was refused for a sensitive field (invariant 6)".into(),
                );
            }
            let bad = songbird_telemetry::metrics::audit_exposition(&body);
            if !bad.is_empty() {
                return Err(format!("sensitive metric or label names: {bad:?}"));
            }
            Ok(())
        })();
        // Graceful stop: SIGTERM, then expect exit status 0.
        let _ = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        let exit = loop {
            if let Ok(Some(st)) = child.try_wait() {
                break Some(st);
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let result = check.and_then(|()| match exit {
            Some(st) if st.success() => Ok(()),
            Some(st) => Err(format!("exited with {st} after SIGTERM")),
            None => Err("did not exit within 10 s of SIGTERM".into()),
        });
        match result {
            Ok(()) => eprintln!("  ok   {name}"),
            Err(e) => {
                eprintln!("  FAIL {name}: {e}");
                failures.push(*name);
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("smoke failed: {failures:?}"))
    }
}

// ---------------------------------------------------------------- bench / fuzz

fn bench(args: &[String]) -> Result {
    let mut c = cargo();
    c.args(["bench", "--workspace", "--locked"]);
    if !args.is_empty() {
        c.arg("--").args(args);
    }
    run(&mut c)
}

fn fuzz(args: &[String]) -> Result {
    let mut secs = 60u64;
    let mut targets = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--secs" {
            secs = it
                .next()
                .and_then(|s| s.parse().ok())
                .ok_or("--secs needs a number")?;
        } else {
            targets.push(a.clone());
        }
    }
    if targets.is_empty() {
        let dir = std::fs::read_dir("fuzz/fuzz_targets")
            .map_err(|e| format!("fuzz/fuzz_targets: {e}"))?;
        for e in dir.flatten() {
            if let Some(stem) = e.path().file_stem().and_then(|s| s.to_str()) {
                targets.push(stem.to_owned());
            }
        }
        targets.sort();
    }
    if !has_cargo_tool("fuzz") {
        return Err("cargo fuzz not installed: cargo install --locked cargo-fuzz".into());
    }
    // cargo-fuzz defaults `--target` to the triple it was itself compiled for, not the host's. A
    // prebuilt static binary (cargo-binstall fetches `x86_64-unknown-linux-musl`) would build for
    // musl, which has no std installed and refuses ASan. Name the host triple explicitly.
    let target = host_triple()?;
    for t in &targets {
        eprintln!("--- fuzz {t} ({secs} s)");
        let corpus = format!("fuzz/corpus/{t}");
        std::fs::create_dir_all(&corpus).map_err(|e| e.to_string())?;
        // ASan keeps every distinct allocation stack forever; the recursive decoders produce
        // distinct stacks without end, so full-depth stacks grew a 10-minute run past 2 GiB
        // (nightly run 43618568338, live heap 25 MB). Ten frames keep reports useful and RSS flat.
        run(cargo_nightly()
            .env("ASAN_OPTIONS", "malloc_context_size=10")
            .args([
                "fuzz",
                "run",
                "--fuzz-dir",
                "fuzz",
                "--target",
                &target,
                t,
                &corpus,
                "--",
                &format!("-max_total_time={secs}"),
                "-rss_limit_mb=2048",
            ]))?;
    }
    Ok(())
}

// ---------------------------------------------------------------- release

fn release(args: &[String]) -> Result {
    let mut target = None;
    let mut verify = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--target" => target = Some(it.next().ok_or("--target needs a triple")?.clone()),
            "--verify" => verify = true,
            other => return Err(format!("unknown release flag {other}")),
        }
    }
    let target = match target {
        Some(t) => t,
        None => host_triple()?,
    };
    let version = output(cargo().args(["pkgid", "-p", "songbird-delivery"]))?
        .trim()
        .rsplit(['@', '#'])
        .next()
        .unwrap_or("0.0.0")
        .to_owned();
    let dist = PathBuf::from(format!("target/dist/{version}/{target}"));
    let a = build_release(&target, "target/repro-a")?;
    if verify {
        let b = build_release(&target, "target/repro-b")?;
        let diffs: Vec<_> = a
            .iter()
            .filter(|(bin, h)| b.get(*bin) != Some(h))
            .map(|(bin, _)| bin.clone())
            .collect();
        if !diffs.is_empty() {
            return Err(format!(
                "not reproducible: {diffs:?} differ between two builds"
            ));
        }
        eprintln!(
            "reproducible: {} binaries bit-identical across two builds",
            a.len()
        );
    }
    std::fs::create_dir_all(&dist).map_err(|e| e.to_string())?;
    let mut sums = String::new();
    for (bin, hash) in &a {
        std::fs::copy(
            format!("target/repro-a/{target}/release/{bin}"),
            dist.join(bin),
        )
        .map_err(|e| format!("{bin}: {e}"))?;
        let _ = writeln!(sums, "{hash}  {bin}");
    }
    std::fs::write(dist.join("SHA256SUMS"), sums).map_err(|e| e.to_string())?;
    if has_cargo_tool("cyclonedx") {
        run(cargo().args([
            "cyclonedx",
            "--format",
            "json",
            "--spec-version",
            "1.5",
            "--all",
        ]))?;
        for bin in a.keys() {
            let crate_dir = crate_dir_of(bin);
            let sbom = format!("{crate_dir}/{bin}.cdx.json");
            std::fs::rename(&sbom, dist.join(format!("{bin}.cdx.json")))
                .map_err(|e| format!("SBOM for {bin} missing ({sbom}): {e}"))?;
        }
        // cargo-cyclonedx also writes SBOMs for library crates into the source tree; remove them.
        for dir in ["crates", "services", "tools", "xtask"] {
            remove_sboms(Path::new(dir));
        }
    } else if std::env::var_os("CI").is_some() {
        return Err("cargo cyclonedx not installed; an SBOM is required for every release".into());
    } else {
        eprintln!("warning: cargo-cyclonedx not installed, no SBOM written (required in CI)");
    }
    eprintln!("release artifacts in {}", dist.display());
    Ok(())
}

fn remove_sboms(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            remove_sboms(&p);
        } else if p.to_string_lossy().ends_with(".cdx.json") {
            let _ = std::fs::remove_file(&p);
        }
    }
}

fn crate_dir_of(bin: &str) -> String {
    let short = bin.trim_start_matches("songbird-");
    match short {
        "admin" | "loadgen" => format!("tools/{short}"),
        _ => format!("services/{short}"),
    }
}

fn build_release(target: &str, dir: &str) -> Result<BTreeMap<String, String>> {
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let cargo_home = std::env::var("CARGO_HOME")
        .unwrap_or_else(|_| format!("{}/.cargo", std::env::var("HOME").unwrap_or_default()));
    let epoch = output(Command::new("git").args(["log", "-1", "--format=%ct"]))?
        .trim()
        .to_owned();
    // Absolute paths are remapped so the build directory does not leak into the binary; the
    // toolchain is pinned by rust-toolchain.toml and dependencies by Cargo.lock (--locked).
    let rustflags = format!(
        "--remap-path-prefix={}=/songbird --remap-path-prefix={cargo_home}=/cargo -C strip=symbols",
        cwd.display()
    );
    let mut c = cargo();
    c.args(["build", "--release", "--locked", "--target", target])
        .env("CARGO_TARGET_DIR", dir)
        .env("SOURCE_DATE_EPOCH", &epoch)
        .env("RUSTFLAGS", rustflags)
        .env("CARGO_INCREMENTAL", "0");
    for b in RELEASE_BINS {
        c.args(["--bin", b]);
    }
    run(&mut c)?;
    let mut hashes = BTreeMap::new();
    for b in RELEASE_BINS {
        let p = format!("{dir}/{target}/release/{b}");
        hashes.insert((*b).to_owned(), sha256(&p)?);
    }
    Ok(hashes)
}

fn sha256(path: &str) -> Result<String> {
    let out = output(Command::new("shasum").args(["-a", "256", path]))
        .or_else(|_| output(Command::new("sha256sum").arg(path)))?;
    out.split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| format!("no hash for {path}"))
}

// ---------------------------------------------------------------- local environment

/// `bytes` from the operating system's CSPRNG (the `getrandom` crate: the `getrandom(2)` system
/// call on Linux, `ProcessPrng` on Windows), as hex.
fn random_hex(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| format!("system random source: {e}"))?;
    Ok(buf
        .iter()
        .fold(String::with_capacity(bytes * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        }))
}

fn dev_env(force: bool) -> Result {
    let path = Path::new(".env");
    if path.exists() && !force {
        // Secrets added after the file was made (Prompt 10: the WebDAV test server) are appended.
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        if text.lines().any(|l| l.starts_with("WEBDAV_PASSWORD=")) {
            eprintln!(".env exists; keeping it (use --force to regenerate)");
        } else {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(path)
                .map_err(|e| e.to_string())?;
            f.write_all(format!("WEBDAV_PASSWORD={}\n", random_hex(16)?).as_bytes())
                .map_err(|e| e.to_string())?;
            eprintln!(".env exists; added WEBDAV_PASSWORD");
        }
        return Ok(());
    }
    let text = format!(
        "# Local development secrets for docker compose. Generated by `cargo xtask dev-env`.\n\
         # Throwaway values for this machine only; .env is git-ignored. Never reuse them elsewhere.\n\
         SURREAL_USER=root\n\
         SURREAL_PASS={}\n\
         VALKEY_HOT_PASSWORD={}\n\
         VALKEY_JOBS_PASSWORD={}\n\
         RUSTFS_ACCESS_KEY=dev{}\n\
         RUSTFS_SECRET_KEY={}\n\
         LIVEKIT_API_KEY=dev{}\n\
         LIVEKIT_API_SECRET={}\n\
         IGGY_ROOT_USERNAME=iggy\n\
         IGGY_ROOT_PASSWORD={}\n\
         WEBDAV_PASSWORD={}\n",
        random_hex(16)?,
        random_hex(32)?,
        random_hex(32)?,
        random_hex(8)?,
        random_hex(32)?,
        random_hex(4)?,
        random_hex(32)?,
        random_hex(32)?,
        random_hex(16)?,
    );
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .map_err(|e| e.to_string())?;
    // Elsewhere (Windows) the file takes the directory's ACL: the user's own profile.
    eprintln!("wrote .env{}", if cfg!(unix) { " (mode 0600)" } else { "" });
    Ok(())
}

/// Development override for Podman (`deploy/compose/compose.podman.yaml`, D-0029).
const COMPOSE_PODMAN: &str = "deploy/compose/compose.podman.yaml";

/// Whether `program --version` runs and succeeds.
fn has_command(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The compose front end: `docker compose` where a `docker` command exists (Docker's, or Podman's
/// `docker` shim), else `podman compose` (Podman alone, as Podman Desktop installs it on Windows).
fn compose_program() -> &'static str {
    if has_command("docker") {
        "docker"
    } else {
        "podman"
    }
}

/// Whether the engine is Podman: there is no `docker` command, or `docker version` names the
/// Podman Engine. `SONGBIRD_COMPOSE_PODMAN=1` or `=0` forces the answer.
fn engine_is_podman() -> bool {
    match std::env::var("SONGBIRD_COMPOSE_PODMAN").as_deref() {
        Ok("1") => return true,
        Ok("0") => return false,
        _ => {}
    }
    compose_program() == "podman"
        || Command::new("docker")
            .arg("version")
            .stderr(Stdio::null())
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("Podman Engine"))
}

/// `docker compose` (or `podman compose`) with the compose file(s) and `.env`.
fn compose_cmd() -> Command {
    let mut c = Command::new(compose_program());
    c.args(["compose", "-f", "deploy/compose/compose.yaml"]);
    if engine_is_podman() {
        c.args(["-f", COMPOSE_PODMAN]);
    }
    c.args(["--env-file", ".env"]);
    c
}

fn compose(args: &[String]) -> Result {
    let r = compose_inner(args);
    if r.is_err() && compose_program() == "podman" {
        eprintln!(
            "hint: `podman compose` runs Docker Compose against the Podman machine's API; if it \
             cannot connect to it, `podman machine stop` then `podman machine start` restores it"
        );
    }
    r
}

fn compose_inner(args: &[String]) -> Result {
    match args.first().map(String::as_str) {
        Some("up") => {
            dev_env(false)?;
            if engine_is_podman() {
                eprintln!(
                    "podman detected: Iggy runs without SELinux labelling and unconfined seccomp \
                     (development only, {COMPOSE_PODMAN})"
                );
            }
            run(compose_cmd().args(["up", "-d", "--wait", "--wait-timeout", "180"]))
        }
        Some("down") => run(compose_cmd().args(["down", "-v"])),
        Some("ps") => run(compose_cmd().arg("ps")),
        _ => Err("usage: cargo xtask compose up|down|ps".into()),
    }
}

// ---------------------------------------------------------------- autobahn

/// `crossbario/autobahn-testsuite` (wstest 0.8.2), pinned by digest.
const AUTOBAHN_IMAGE: &str = "docker.io/crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074";

/// Cases whose messages (4–16 MiB) exceed the production limit (1 MiB, invariant 7): refused by
/// design in the production pass, and run in the second pass with the limit raised to 16 MiB.
const AUTOBAHN_OVERSIZE: &[&str] = &[
    "9.1.4", "9.1.5", "9.1.6", "9.2.4", "9.2.5", "9.2.6", "9.3.*", "9.4.*",
];

fn container_runtime() -> Result<&'static str> {
    ["docker", "podman"]
        .into_iter()
        .find(|rt| has_command(rt))
        .ok_or_else(|| "autobahn needs docker or podman".into())
}

/// Parses wstest's `index.json` into (case, behavior) pairs without a JSON dependency: the file
/// is machine-written with one `"<case>": {` per case followed by its `"behavior": "<value>"`.
fn autobahn_results(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("\": {") {
        let head = &rest[..i];
        let case = head.rsplit('"').next().unwrap_or_default().to_owned();
        rest = &rest[i + 4..];
        let is_case = !case.is_empty() && case.split('.').all(|p| p.parse::<u32>().is_ok());
        if !is_case {
            continue;
        }
        if let Some(j) = rest.find("\"behavior\": \"") {
            let v = &rest[j + 13..];
            let behavior = v.split('"').next().unwrap_or_default().to_owned();
            out.push((case, behavior));
        }
    }
    out
}

fn autobahn_pass(
    rt: &str,
    dir: &Path,
    name: &str,
    port: u16,
    max_bytes: Option<usize>,
    cases: &[&str],
    exclude: &[&str],
) -> Result<Vec<(String, String)>> {
    let quote = |v: &[&str]| {
        v.iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ")
    };
    // The container reaches the echo server on the host's loopback: through the host network
    // normally; under rootless Docker (the CI runner, D-0039) through the gateway address the
    // runner names in SONGBIRD_AUTOBAHN_HOST (slirp4netns: 10.0.2.2), on Docker's own network.
    let via_gateway = std::env::var("SONGBIRD_AUTOBAHN_HOST").ok();
    let target = via_gateway.as_deref().unwrap_or("127.0.0.1");
    let spec = format!(
        "{{\"outdir\": \"/ab/{name}\", \"servers\": [{{\"agent\": \"{name}\", \"url\": \"ws://{target}:{port}\"}}], \"cases\": [{}], \"exclude-cases\": [{}], \"exclude-agent-cases\": {{}}}}",
        quote(cases),
        quote(exclude)
    );
    std::fs::write(dir.join(format!("{name}.json")), spec).map_err(|e| e.to_string())?;
    let mut server = Command::new("target/release/songbird-delivery-autobahn");
    server.env("AUTOBAHN_LISTEN", format!("127.0.0.1:{port}"));
    if let Some(m) = max_bytes {
        server.env("AUTOBAHN_MAX_MESSAGE_BYTES", m.to_string());
    }
    let mut child = server
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("start echo server: {e}"))?;
    std::thread::sleep(Duration::from_millis(300));
    let abs = std::fs::canonicalize(dir).map_err(|e| e.to_string())?;
    let network = if via_gateway.is_some() {
        "bridge"
    } else {
        "host"
    };
    let r = run(Command::new(rt).args([
        "run",
        "--rm",
        "--network",
        network,
        "-v",
        &format!("{}:/ab:Z", abs.display()),
        AUTOBAHN_IMAGE,
        "wstest",
        "-m",
        "fuzzingclient",
        "-s",
        &format!("/ab/{name}.json"),
    ]));
    let _ = child.kill();
    let _ = child.wait();
    r?;
    let index = std::fs::read_to_string(dir.join(name).join("index.json"))
        .map_err(|e| format!("{name}/index.json: {e}"))?;
    Ok(autobahn_results(&index))
}

fn autobahn() -> Result {
    let rt = container_runtime()?;
    run(cargo().args([
        "build",
        "--release",
        "--locked",
        "-p",
        "songbird-delivery",
        "--bin",
        "songbird-delivery-autobahn",
    ]))?;
    let dir = PathBuf::from("target/autobahn");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut failures = Vec::new();
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();

    step("autobahn: production configuration (1 MiB messages), all cases");
    for (case, behavior) in autobahn_pass(
        rt,
        &dir,
        "production",
        9001,
        None,
        &["*"],
        AUTOBAHN_OVERSIZE,
    )? {
        *tally.entry(format!("production {behavior}")).or_default() += 1;
        let group = case.split('.').next().unwrap_or_default();
        let ok = match behavior.as_str() {
            "OK" | "INFORMATIONAL" => true,
            // permessage-deflate is deliberately not offered (ciphertext does not compress).
            "UNIMPLEMENTED" => group == "12" || group == "13",
            _ => false,
        };
        if !ok {
            failures.push(format!("production {case}: {behavior}"));
        }
    }

    step("autobahn: limit raised to 16 MiB, group 9 (large messages)");
    for (case, behavior) in autobahn_pass(
        rt,
        &dir,
        "large",
        9002,
        Some(16 * 1024 * 1024),
        &["9.*"],
        &[],
    )? {
        *tally.entry(format!("large {behavior}")).or_default() += 1;
        if behavior != "OK" {
            failures.push(format!("large {case}: {behavior}"));
        }
    }
    for (k, n) in &tally {
        eprintln!("  {k}: {n}");
    }
    eprintln!("  reports: target/autobahn/{{production,large}}/index.html");
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "autobahn: {} unexpected results:\n{}",
            failures.len(),
            failures.join("\n")
        ))
    }
}
