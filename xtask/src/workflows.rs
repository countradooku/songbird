//! Policy for `.github/workflows` (D-0045), checked by `cargo xtask workflows` and as the first
//! step of `cargo xtask ci fast`, so a pull request cannot quietly bring back paid minutes or
//! weaken the CI security posture.
//!
//! Rules, per workflow file:
//! 1. Every job names its runner. Only `release.yml` and `deploy.yml` may use a GitHub-hosted
//!    runner (they sign releases and hold production secrets, which never reach the shared
//!    self-hosted host), and those two run only on a pushed tag or by hand. Every other job runs
//!    on `[self-hosted, ...]`.
//! 2. A workflow triggered by `pull_request` carries the same-repository guard on every job, so
//!    code from a fork never runs on a self-hosted runner (the repository setting that disables
//!    fork workflows is the primary control; the guard is the second line).
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

/// The exact `if:` every job of a `pull_request` workflow carries.
pub(crate) const FORK_GUARD: &str = "if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository";

/// The only workflows allowed on GitHub-hosted runners.
const HOSTED_ALLOWED: &[&str] = &["release.yml", "deploy.yml"];

/// The only triggers a hosted workflow may have: the owner pushing a tag, or starting it by hand.
const HOSTED_TRIGGERS: &[&str] = &["push", "workflow_dispatch"];

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

/// `  name:` (exactly two spaces, then a key with nothing after the colon) → `name`.
fn child_key(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("  ")?;
    if rest.starts_with(' ') {
        return None;
    }
    let key = rest.trim_end().strip_suffix(':')?;
    (!key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
    .then_some(key)
}

/// `  name: value` or `  name:` at two spaces → `name`.
fn child_key_any(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("  ")?;
    if rest.starts_with(' ') {
        return None;
    }
    let (key, _) = rest.split_once(':')?;
    (!key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
    .then_some(key)
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

/// Every violation in one workflow file (empty when it follows the policy).
pub(crate) fn check_file(name: &str, text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut problems = Vec::new();
    let triggers = check_triggers(name, &lines, &mut problems);
    check_permissions(&lines, &mut problems);
    if name != "release.yml" && !lines.iter().any(|l| code(l).starts_with("concurrency:")) {
        problems
            .push("no top-level `concurrency` group (superseded runs must be cancelled)".into());
    }
    check_pins(&lines, &mut problems);
    check_jobs(
        name,
        &lines,
        triggers.contains(&"pull_request"),
        &mut problems,
    );
    problems
        .into_iter()
        .map(|p| format!("{name}: {p}"))
        .collect()
}

/// The workflow's triggers; checks the forbidden ones and what a hosted workflow may use.
fn check_triggers<'a>(name: &str, lines: &[&'a str], problems: &mut Vec<String>) -> Vec<&'a str> {
    let Some(on) = block(lines, "on:") else {
        problems.push(if lines.iter().any(|l| code(l).starts_with("on:")) {
            "write `on:` as a block, one trigger per line".into()
        } else {
            "no `on:` block".into()
        });
        return Vec::new();
    };
    let triggers: Vec<&str> = on.iter().filter_map(|l| child_key_any(l)).collect();
    for t in ["pull_request_target", "workflow_run"] {
        if lines.iter().any(|l| code(l).contains(t)) {
            problems.push(format!(
                "`{t}` is forbidden (base-repository token on outside code)"
            ));
        }
    }
    if HOSTED_ALLOWED.contains(&name) {
        for t in triggers.iter().filter(|t| !HOSTED_TRIGGERS.contains(t)) {
            problems.push(format!(
                "a GitHub-hosted workflow may not trigger on `{t}` (paid minutes); only {HOSTED_TRIGGERS:?}"
            ));
        }
        let filter = |k: &str| on.iter().any(|l| l.trim_start().starts_with(k));
        if triggers.contains(&"push") && (filter("branches") || !filter("tags")) {
            problems.push(
                "a GitHub-hosted workflow may run on pushed tags only, never on branches".into(),
            );
        }
    }
    triggers
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

/// One job as the line scanner sees it.
struct Job<'a> {
    name: &'a str,
    runs_on: bool,
    guard: bool,
}

fn check_jobs(name: &str, lines: &[&str], on_pr: bool, problems: &mut Vec<String>) {
    let Some(body) = block(lines, "jobs:") else {
        problems.push("no `jobs:` block".into());
        return;
    };
    let hosted_allowed = HOSTED_ALLOWED.contains(&name);
    let finish = |job: Option<Job<'_>>, problems: &mut Vec<String>| {
        let Some(job) = job else { return };
        if !job.runs_on {
            problems.push(format!("job `{}` has no `runs-on`", job.name));
        }
        if on_pr && !job.guard {
            problems.push(format!(
                "job `{}` runs on pull_request without the same-repository guard `{FORK_GUARD}`",
                job.name
            ));
        }
    };
    let mut current: Option<Job<'_>> = None;
    for l in &body {
        if let Some(job) = child_key(l) {
            finish(current.take(), problems);
            current = Some(Job {
                name: job,
                runs_on: false,
                guard: false,
            });
            continue;
        }
        // Job-level keys only: exactly four spaces of indentation.
        let Some(job) = current.as_mut() else {
            continue;
        };
        let Some(t) = l.strip_prefix("    ").filter(|t| !t.starts_with(' ')) else {
            continue;
        };
        let t = t.trim_end();
        if let Some(v) = t.strip_prefix("runs-on:") {
            job.runs_on = true;
            let v = v.trim();
            if !(v.starts_with("[self-hosted,") || v == "self-hosted" || hosted_allowed) {
                problems.push(format!(
                    "job `{}`: runs-on `{v}`: only release.yml and deploy.yml may use GitHub-hosted runners",
                    job.name
                ));
            }
        }
        if t == FORK_GUARD {
            job.guard = true;
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
    runs-on: [self-hosted, songbird]
    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: ./local
  b:
    runs-on: [self-hosted, songbird-stack]
    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
    steps:
      - run: true
";

    fn problems(name: &str, text: &str) -> Vec<String> {
        check_file(name, text)
    }

    #[test]
    fn a_compliant_workflow_passes() {
        assert_eq!(problems("ci.yml", GOOD), Vec::<String>::new());
    }

    #[test]
    fn a_hosted_runner_outside_release_and_deploy_fails() {
        let p = problems(
            "ci.yml",
            &GOOD.replacen("[self-hosted, songbird]", "ubuntu-24.04", 1),
        );
        assert!(p.iter().any(|m| m.contains("GitHub-hosted")), "{p:?}");
    }

    #[test]
    fn a_runner_from_an_expression_fails() {
        let p = problems(
            "nightly.yml",
            &GOOD.replacen("[self-hosted, songbird]", "${{ matrix.os }}", 1),
        );
        assert!(p.iter().any(|m| m.contains("GitHub-hosted")), "{p:?}");
    }

    #[test]
    fn a_pull_request_job_without_the_fork_guard_fails() {
        let text = GOOD.replacen(&format!("    {FORK_GUARD}\n"), "", 1);
        let p = problems("ci.yml", &text);
        assert!(
            p.iter()
                .any(|m| m.contains("job `a`") && m.contains("guard")),
            "{p:?}"
        );
    }

    #[test]
    fn a_weakened_fork_guard_fails() {
        let text = GOOD.replacen("== github.repository", "!= ''", 1);
        let p = problems("ci.yml", &text);
        assert!(p.iter().any(|m| m.contains("guard")), "{p:?}");
    }

    #[test]
    fn the_guard_is_not_required_without_pull_request() {
        let text = GOOD
            .replace(
                "  pull_request:\n    paths-ignore: [\"docs/**\"]\n",
                "  schedule:\n    - cron: \"1 2 * * *\"\n",
            )
            .replace(&format!("    {FORK_GUARD}\n"), "");
        assert_eq!(problems("codeql.yml", &text), Vec::<String>::new());
    }

    #[test]
    fn pull_request_target_and_workflow_run_fail() {
        for t in ["pull_request_target", "workflow_run"] {
            let text = GOOD.replacen("  push:\n", &format!("  {t}:\n  push:\n"), 1);
            let p = problems("ci.yml", &text);
            assert!(p.iter().any(|m| m.contains(t)), "{t}: {p:?}");
        }
    }

    #[test]
    fn an_action_pinned_by_tag_or_short_sha_fails() {
        for pin in ["v7.0.1", "3d3c42e", "main"] {
            let text = GOOD.replacen("3d3c42e5aac5ba805825da76410c181273ba90b1", pin, 1);
            let p = problems("ci.yml", &text);
            assert!(p.iter().any(|m| m.contains("not pinned")), "{pin}: {p:?}");
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
        let bad = GOOD.replacen("./local", "docker://alpine:3", 1);
        assert!(
            problems("ci.yml", &bad)
                .iter()
                .any(|m| m.contains("not pinned"))
        );
    }

    #[test]
    fn broader_top_level_permissions_fail() {
        let text = GOOD.replacen("  contents: read\n", "  contents: write\n", 1);
        assert!(
            problems("ci.yml", &text)
                .iter()
                .any(|m| m.contains("permissions"))
        );
        let text = GOOD.replacen(
            "  contents: read\n",
            "  contents: read\n  packages: write\n",
            1,
        );
        assert!(
            problems("ci.yml", &text)
                .iter()
                .any(|m| m.contains("permissions"))
        );
        let text = GOOD.replacen("permissions:\n  contents: read\n", "", 1);
        assert!(
            problems("ci.yml", &text)
                .iter()
                .any(|m| m.contains("permissions"))
        );
    }

    #[test]
    fn a_missing_concurrency_group_fails() {
        let text = GOOD.replacen(
            "concurrency:\n  group: ci-${{ github.ref }}\n  cancel-in-progress: true\n",
            "",
            1,
        );
        assert!(
            problems("ci.yml", &text)
                .iter()
                .any(|m| m.contains("concurrency"))
        );
    }

    #[test]
    fn a_job_without_runs_on_fails() {
        let text = GOOD.replacen("    runs-on: [self-hosted, songbird-stack]\n", "", 1);
        assert!(
            problems("ci.yml", &text)
                .iter()
                .any(|m| m.contains("job `b` has no `runs-on`"))
        );
    }

    #[test]
    fn an_inline_on_list_is_rejected() {
        let text = GOOD.replacen(
            "on:\n  pull_request:\n    paths-ignore: [\"docs/**\"]\n  push:\n    branches: [main]\n",
            "on: [pull_request]\n",
            1,
        );
        assert!(
            problems("ci.yml", &text)
                .iter()
                .any(|m| m.contains("block"))
        );
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
    steps:
      - run: true
";

    #[test]
    fn release_may_use_hosted_runners_on_tags() {
        assert_eq!(problems("release.yml", RELEASE), Vec::<String>::new());
    }

    #[test]
    fn hosted_release_on_pull_requests_branches_or_schedule_fails() {
        let p = problems(
            "release.yml",
            &RELEASE.replacen("  push:\n", "  pull_request:\n  push:\n", 1),
        );
        assert!(p.iter().any(|m| m.contains("pull_request")), "{p:?}");
        let p = problems(
            "release.yml",
            &RELEASE.replacen("tags: [\"v*\"]", "branches: [main]", 1),
        );
        assert!(p.iter().any(|m| m.contains("tags only")), "{p:?}");
        let p = problems(
            "release.yml",
            &RELEASE.replacen("    tags: [\"v*\"]\n", "", 1),
        );
        assert!(p.iter().any(|m| m.contains("tags only")), "{p:?}");
        let p = problems(
            "deploy.yml",
            &RELEASE.replacen(
                "  push:\n    tags: [\"v*\"]\n",
                "  schedule:\n    - cron: \"1 2 * * *\"\n",
                1,
            ),
        );
        assert!(p.iter().any(|m| m.contains("schedule")), "{p:?}");
    }

    #[test]
    fn the_repository_workflows_follow_the_policy() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows");
        check(&dir).unwrap();
    }
}
