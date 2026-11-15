//! Policy for `.github/workflows` (D-0045), checked by `cargo xtask workflows` and as the first
//! step of `cargo xtask ci fast`, so a pull request cannot quietly put outside code on a machine we
//! own, bring back paid minutes, or weaken the CI token.
//!
//! The repository is public: anyone can open a pull request, and a pull request from a fork runs
//! the fork's copy of the workflows. Rules, per workflow file:
//! 1. Every job names a standard GitHub-hosted Ubuntu image, pinned (`ubuntu-24.04`, or its `-arm`
//!    variant): a fresh VM per job, free for a public repository. Never a self-hosted runner, a
//!    label list, an expression, `-latest`, or a larger runner (those are billed even here).
//! 2. The privileged workflows, `release.yml` and `deploy.yml` (write scopes, signing, production
//!    secrets), run only on a pushed tag or by hand, never on a branch push, a pull request or a
//!    schedule; they are the only workflows that may reference `secrets.`.
//! 3. No `pull_request_target` or `workflow_run`: both run with the base repository's token and
//!    secrets on code an outsider can influence.
//! 4. Every action is pinned to a full commit SHA (or is local, or a docker image by digest).
//! 5. The top-level token is `permissions: contents: read` and nothing more; jobs widen it only
//!    where they need to.
//! 6. Every workflow except `release.yml` has a top-level `concurrency` group.
//!
//! The parser is deliberately line-based and strict: it understands the block style these files
//! use and rejects forms it does not (an inline `on:` list, a job without `runs-on`), instead of
//! guessing.

use std::path::Path;

type Result<T = ()> = std::result::Result<T, String>;

/// Workflows with write scopes or secrets.
const PRIVILEGED: &[&str] = &["release.yml", "deploy.yml"];

/// The only triggers a privileged workflow may have: a pushed tag, or a manual start.
const PRIVILEGED_TRIGGERS: &[&str] = &["push", "workflow_dispatch"];

/// Checks every workflow under `dir`; the error lists every violation found.
pub(crate) fn check(dir: &Path) -> Result {
    let mut names = std::fs::read_dir(dir)
        .map_err(|e| format!("read {}: {e}", dir.display()))?
        .filter_map(std::result::Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| {
            Path::new(n)
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("yml") || x.eq_ignore_ascii_case("yaml"))
        })
        .collect::<Vec<_>>();
    names.sort();
    if names.is_empty() {
        return Err(format!("no workflows found in {}", dir.display()));
    }
    let mut problems = Vec::new();
    for name in &names {
        let text = std::fs::read_to_string(dir.join(name)).map_err(|e| format!("{name}: {e}"))?;
        problems.extend(check_file(name, &text));
    }
    if problems.is_empty() {
        eprintln!(
            "workflows: {} files follow the CI policy (D-0045)",
            names.len()
        );
        Ok(())
    } else {
        Err(format!(
            "workflow policy (D-0045) violated:\n  {}",
            problems.join("\n  ")
        ))
    }
}

/// The line, or empty when it is a comment line.
fn code(line: &str) -> &str {
    if line.trim_start().starts_with('#') {
        ""
    } else {
        line
    }
}

/// Lines of a top-level block (`key:` at column 0) up to the next column-0 key.
fn block<'a>(lines: &[&'a str], key: &str) -> Option<Vec<&'a str>> {
    let start = lines.iter().position(|l| code(l).trim_end() == key)?;
    Some(
        lines
            .iter()
            .skip(start + 1)
            .copied()
            .map(code)
            .take_while(|l| l.is_empty() || l.starts_with(' '))
            .collect(),
    )
}

fn is_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// `  name:` (exactly two spaces, then a key with nothing after the colon) → `name`.
fn child_key(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("  ").filter(|r| !r.starts_with(' '))?;
    let key = rest.trim_end().strip_suffix(':')?;
    is_key(key).then_some(key)
}

/// `  name: value` or `  name:` at two spaces → `name`.
fn child_key_any(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("  ").filter(|r| !r.starts_with(' '))?;
    let (key, _) = rest.split_once(':')?;
    is_key(key).then_some(key)
}

fn pinned(target: &str) -> bool {
    if target.starts_with("./") {
        return true;
    }
    if let Some(image) = target.strip_prefix("docker://") {
        return image
            .split_once("@sha256:")
            .is_some_and(|(_, d)| d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()));
    }
    target.split_once('@').is_some_and(|(repo, sha)| {
        repo.contains('/')
            && sha.len() == 40
            && sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// `ubuntu-NN.NN` or `ubuntu-NN.NN-arm`: a standard hosted runner on a pinned image.
fn standard_hosted(label: &str) -> bool {
    let Some(rest) = label.strip_prefix("ubuntu-") else {
        return false;
    };
    let version = rest.strip_suffix("-arm").unwrap_or(rest);
    let b = version.as_bytes();
    b.len() == 5
        && b.iter().enumerate().all(|(i, c)| match i {
            2 => *c == b'.',
            _ => c.is_ascii_digit(),
        })
}

/// Every violation in one workflow file (empty when it follows the policy).
pub(crate) fn check_file(name: &str, text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut problems = Vec::new();
    let privileged = PRIVILEGED.contains(&name);
    check_triggers(privileged, &lines, &mut problems);
    check_permissions(&lines, &mut problems);
    if name != "release.yml" && !lines.iter().any(|l| code(l).starts_with("concurrency:")) {
        problems
            .push("no top-level `concurrency` group (superseded runs must be cancelled)".into());
    }
    check_pins(&lines, &mut problems);
    if !privileged {
        for (i, l) in lines.iter().enumerate() {
            if code(l).contains("secrets.") {
                problems.push(format!(
                    "line {}: secrets are referenced only in release.yml and deploy.yml",
                    i + 1
                ));
            }
        }
    }
    check_jobs(&lines, &mut problems);
    problems
        .into_iter()
        .map(|p| format!("{name}: {p}"))
        .collect()
}

/// Checks the forbidden triggers and what a privileged workflow may use.
fn check_triggers(privileged: bool, lines: &[&str], problems: &mut Vec<String>) {
    let Some(on) = block(lines, "on:") else {
        problems.push(if lines.iter().any(|l| code(l).starts_with("on:")) {
            "write `on:` as a block, one trigger per line".into()
        } else {
            "no `on:` block".into()
        });
        return;
    };
    for t in ["pull_request_target", "workflow_run"] {
        if lines.iter().any(|l| code(l).contains(t)) {
            problems.push(format!(
                "`{t}` is forbidden (base-repository token on outside code)"
            ));
        }
    }
    if privileged {
        let triggers: Vec<&str> = on.iter().filter_map(|l| child_key_any(l)).collect();
        for t in triggers.iter().filter(|t| !PRIVILEGED_TRIGGERS.contains(t)) {
            problems.push(format!(
                "a privileged workflow may not trigger on `{t}`; only {PRIVILEGED_TRIGGERS:?}"
            ));
        }
        let filter = |k: &str| on.iter().any(|l| l.trim_start().starts_with(k));
        if triggers.contains(&"push") && (filter("branches") || !filter("tags")) {
            problems.push(
                "a privileged workflow may run on pushed tags only, never on branches".into(),
            );
        }
    }
}

fn check_permissions(lines: &[&str], problems: &mut Vec<String>) {
    let Some(p) = block(lines, "permissions:") else {
        problems.push("no top-level `permissions: contents: read`".into());
        return;
    };
    let entries: Vec<&str> = p
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    if entries != ["contents: read"] {
        problems.push(format!(
            "top-level permissions must be exactly `contents: read`, found {entries:?}"
        ));
    }
}

fn check_pins(lines: &[&str], problems: &mut Vec<String>) {
    for (i, l) in lines.iter().enumerate() {
        let t = code(l).trim_start().trim_start_matches("- ");
        if let Some(v) = t.strip_prefix("uses:") {
            let target = v
                .split(" #")
                .next()
                .unwrap_or_default()
                .trim()
                .trim_matches(['"', '\'']);
            if !pinned(target) {
                problems.push(format!(
                    "line {}: `{target}` is not pinned to a full commit SHA",
                    i + 1
                ));
            }
        }
    }
}

fn check_jobs(lines: &[&str], problems: &mut Vec<String>) {
    let Some(body) = block(lines, "jobs:") else {
        problems.push("no `jobs:` block".into());
        return;
    };
    // (job, has runs-on)
    let finish = |job: Option<(&str, bool)>, problems: &mut Vec<String>| {
        if let Some((job, false)) = job {
            problems.push(format!("job `{job}` has no `runs-on`"));
        }
    };
    let mut current: Option<(&str, bool)> = None;
    for l in &body {
        if let Some(job) = child_key(l) {
            finish(current.take(), problems);
            current = Some((job, false));
            continue;
        }
        // Job-level keys only: exactly four spaces of indentation.
        let Some((job, runs_on)) = current.as_mut() else {
            continue;
        };
        let Some(t) = l.strip_prefix("    ").filter(|t| !t.starts_with(' ')) else {
            continue;
        };
        if let Some(v) = t.trim_end().strip_prefix("runs-on:") {
            *runs_on = true;
            let v = v.trim();
            if !standard_hosted(v) {
                problems.push(format!(
                    "job `{job}`: runs-on `{v}`: only a standard GitHub-hosted image such as \
                     `ubuntu-24.04` (never self-hosted, a label list, an expression, `-latest` \
                     or a larger runner)"
                ));
            }
        }
    }
    finish(current.take(), problems);
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "\
name: ci
on:
  pull_request:
    paths-ignore: [\"docs/**\"]
  push:
    branches: [main]
permissions:
  contents: read
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true
jobs:
  a:
    runs-on: ubuntu-24.04
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: ./local
  b:
    runs-on: ubuntu-24.04-arm
    steps:
      - run: true
";

    fn problems(name: &str, text: &str) -> Vec<String> {
        check_file(name, text)
    }

    fn fails(name: &str, text: &str, needle: &str) {
        let p = problems(name, text);
        assert!(p.iter().any(|m| m.contains(needle)), "{needle}: {p:?}");
    }

    #[test]
    fn a_compliant_workflow_passes() {
        assert_eq!(problems("ci.yml", GOOD), Vec::<String>::new());
    }

    #[test]
    fn self_hosted_label_lists_expressions_latest_and_larger_runners_fail() {
        for runner in [
            "[self-hosted, songbird]",
            "self-hosted",
            "[ubuntu-24.04]",
            "${{ matrix.os }}",
            "ubuntu-latest",
            "ubuntu-24.04-8core",
            "ubuntu-24.04-arm64",
            "macos-15",
        ] {
            let text = GOOD.replacen(
                "runs-on: ubuntu-24.04\n",
                &format!("runs-on: {runner}\n"),
                1,
            );
            fails("ci.yml", &text, "standard GitHub-hosted");
        }
    }

    #[test]
    fn standard_images_are_recognised() {
        assert!(standard_hosted("ubuntu-24.04"));
        assert!(standard_hosted("ubuntu-22.04-arm"));
        assert!(!standard_hosted("ubuntu-2404"));
        assert!(!standard_hosted("ubuntu-24.04.1"));
        assert!(!standard_hosted("ubuntu-"));
    }

    #[test]
    fn pull_request_target_and_workflow_run_fail() {
        for t in ["pull_request_target", "workflow_run"] {
            let text = GOOD.replacen("  push:\n", &format!("  {t}:\n  push:\n"), 1);
            fails("ci.yml", &text, t);
        }
    }

    #[test]
    fn secrets_outside_release_and_deploy_fail() {
        let text = GOOD.replacen(
            "      - run: true\n",
            "      - run: true\n        env:\n          T: ${{ secrets.TOKEN }}\n",
            1,
        );
        fails("ci.yml", &text, "secrets are referenced only");
        fails("nightly.yml", &text, "secrets are referenced only");
    }

    #[test]
    fn an_action_pinned_by_tag_or_short_sha_fails() {
        for pin in ["v7.0.1", "3d3c42e", "main"] {
            let text = GOOD.replacen("3d3c42e5aac5ba805825da76410c181273ba90b1", pin, 1);
            fails("ci.yml", &text, "not pinned");
        }
    }

    #[test]
    fn docker_actions_need_a_digest() {
        let ok = GOOD.replacen(
            "./local",
            "docker://alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            1,
        );
        assert_eq!(problems("ci.yml", &ok), Vec::<String>::new());
        fails(
            "ci.yml",
            &GOOD.replacen("./local", "docker://alpine:3", 1),
            "not pinned",
        );
    }

    #[test]
    fn broader_top_level_permissions_fail() {
        fails(
            "ci.yml",
            &GOOD.replacen("  contents: read\n", "  contents: write\n", 1),
            "permissions",
        );
        fails(
            "ci.yml",
            &GOOD.replacen(
                "  contents: read\n",
                "  contents: read\n  packages: write\n",
                1,
            ),
            "permissions",
        );
        fails(
            "ci.yml",
            &GOOD.replacen("permissions:\n  contents: read\n", "", 1),
            "permissions",
        );
    }

    #[test]
    fn a_missing_concurrency_group_fails() {
        let text = GOOD.replacen(
            "concurrency:\n  group: ci-${{ github.ref }}\n  cancel-in-progress: true\n",
            "",
            1,
        );
        fails("ci.yml", &text, "concurrency");
    }

    #[test]
    fn a_job_without_runs_on_fails() {
        let text = GOOD.replacen("    runs-on: ubuntu-24.04-arm\n", "", 1);
        fails("ci.yml", &text, "job `b` has no `runs-on`");
    }

    #[test]
    fn an_inline_on_list_is_rejected() {
        let text = GOOD.replacen(
            "on:\n  pull_request:\n    paths-ignore: [\"docs/**\"]\n  push:\n    branches: [main]\n",
            "on: [pull_request]\n",
            1,
        );
        fails("ci.yml", &text, "block");
    }

    const RELEASE: &str = "\
name: release
on:
  push:
    tags: [\"v*\"]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-24.04
    permissions:
      contents: write
    steps:
      - run: gh release create
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
";

    #[test]
    fn release_runs_on_tags_and_may_use_secrets() {
        assert_eq!(problems("release.yml", RELEASE), Vec::<String>::new());
    }

    #[test]
    fn privileged_workflows_on_pull_requests_branches_or_schedule_fail() {
        fails(
            "release.yml",
            &RELEASE.replacen("  push:\n", "  pull_request:\n  push:\n", 1),
            "pull_request",
        );
        fails(
            "release.yml",
            &RELEASE.replacen("tags: [\"v*\"]", "branches: [main]", 1),
            "tags only",
        );
        fails(
            "release.yml",
            &RELEASE.replacen("    tags: [\"v*\"]\n", "", 1),
            "tags only",
        );
        fails(
            "deploy.yml",
            &RELEASE.replacen(
                "  push:\n    tags: [\"v*\"]\n",
                "  schedule:\n    - cron: \"1 2 * * *\"\n",
                1,
            ),
            "schedule",
        );
    }

    #[test]
    fn the_repository_workflows_follow_the_policy() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows");
        check(&dir).unwrap();
    }
}
