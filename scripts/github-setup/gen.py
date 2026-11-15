#!/usr/bin/env python3
"""Generate Songbird repo files and issue specs from PROMPT_SET.md / MASTER_BUILD_PROMPT.md.

Usage: gen.py <input_dir> <repo_dir> <out_json>
Idempotent: rewrites the same files with the same content every run.
"""
import json, os, re, sys

src, repo, out_json = sys.argv[1:4]
OWNER = "songbirdchat"
REPO_URL = f"https://github.com/{OWNER}/songbird"
MASTER_LINK = "https://claude.ai/artifact/WBgym6gXuXwJcm9VJQhtmB"

text = open(os.path.join(src, "PROMPT_SET.md"), encoding="utf-8").read()
master = open(os.path.join(src, "MASTER_BUILD_PROMPT.md"), encoding="utf-8").read()


def w(rel, content):
    p = os.path.join(repo, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content.rstrip("\n") + "\n")


def drop_mentions(s):
    # "@Radu" lines would notify an unrelated GitHub user.
    return re.sub(r"^@\w+\s*\n\n?", "", s, flags=re.M)


# ---------- split PROMPT_SET.md ----------
parts = re.split(r"^(?=## Prompt \d+ — )", text, flags=re.M)
head, prompt_parts = parts[0], parts[1:]

how = head.split("## How to use this prompt set", 1)[1]
how = how.strip().rstrip("-").strip()
how = how.replace(MASTER_LINK, "02a-realtime-master.md")
how = how.replace("Save this document in the repo as `docs/prompts/` (one file per prompt)",
                  "This folder holds them, one file per prompt")
prompts = []
for part in prompt_parts:
    m = re.match(r"## Prompt (\d+) — (.+)\n", part)
    n, title = int(m.group(1)), m.group(2).strip()
    fm = re.search(r"docs/prompts/(\d\d-[a-z0-9-]+\.md)", part)
    fname = fm.group(1)
    body = part[m.end():].strip()
    body = body.replace(MASTER_LINK, "02a-realtime-master.md")
    md = f"# Prompt {n} — {title}\n\n" + re.sub(r"^### ", "## ", body, flags=re.M)
    w(f"docs/prompts/{fname}", md)
    prompts.append({"n": n, "title": title, "file": fname, "body": body})

# README index of files
idx = "\n".join(f"- [Prompt {p['n']} — {p['title']}]({p['file']})" for p in prompts)
idx_lines = idx.split("\n")
idx_lines.insert(3, "- [Prompt 2a — Realtime master build prompt (detailed spec for Prompt 2)](02a-realtime-master.md)")
w("docs/prompts/README.md",
  "# Songbird Backend — Prompt Set\n\n## How to use this prompt set\n\n" + how +
  "\n\n## Files\n\n" + "\n".join(idx_lines))

# ---------- master prompt ----------
mtxt = drop_mentions(master)
mtxt = mtxt.replace("monorepo) and save a copy in the repo as `docs/BUILD_PROMPT.md` so",
                    "monorepo). It lives in the repo as `docs/prompts/02a-realtime-master.md` so")
mtxt = mtxt.replace("docs/           BUILD_PROMPT, DECISIONS", "docs/           prompts/, DECISIONS")
mtxt = mtxt.replace("docs/BUILD\\_PROMPT.md", "docs/prompts/02a-realtime-master.md")
mtxt = mtxt.replace("docs/BUILD_PROMPT.md", "docs/prompts/02a-realtime-master.md")
w("docs/prompts/02a-realtime-master.md", mtxt)

# ---------- issue specs ----------
LABEL_RE = re.compile(r"^\*\*(Build|Also build|Add beyond|Detailed specification)")


def clean(s):
    return re.sub(r"\s+", " ", s).strip()


def parse(body):
    lines = body.split("\n")
    goal = gate = None
    sections = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("**Goal:**"):
            goal = clean(ln[len("**Goal:**"):]); goal = goal[0].upper() + goal[1:]
        gm = re.match(r"^\*\*Gate(?: \([^)]*\))?:\*\*(.*)", ln)
        if gm:
            gate = clean(gm.group(1))
        if LABEL_RE.match(ln):
            label = ln.strip()
            items = []  # (level, text)
            j = i + 1
            while j < len(lines) and lines[j].strip() == "":
                j += 1
            while j < len(lines) and re.match(r"^\s*- ", lines[j]):
                lvl = 1 if lines[j].startswith("  ") else 0
                items.append((lvl, clean(re.sub(r"^\s*- ", "", lines[j]))))
                j += 1
            if items:
                sections.append({"label": label, "items": items})
                i = j
                continue
            # paragraph-only section: the paragraph is the single item
            lm = re.match(r"^\*\*(.+?)\*\*\s*(.*)", label)
            sections.append({"label": None, "items": [(0, clean(f"**{lm.group(1)}** {lm.group(2)}"))]})
        i += 1
    return goal, sections, gate


AREA = {1: "platform", 2: "realtime", 3: "identity", 4: "messaging", 5: "groups", 6: "media",
        7: "calls", 8: "push", 9: "settings", 10: "backups", 11: "plans-abuse", 12: "security",
        13: "perf-dr", 14: "interop"}
PRIO = {**{n: "p0" for n in (1, 2, 3, 4, 5, 6, 8)}, **{n: "p1" for n in (7, 9, 10, 12, 13)},
        **{n: "p2" for n in (11, 14)}}
MILESTONE = {1: "M0 Foundations", **{n: "M1 Closed-beta backend" for n in (2, 3, 4, 5, 6, 8, 9, 10)},
             **{n: "M2 Public-beta backend" for n in (7, 11, 12, 13)}, 14: "M3 Interop and growth"}
DEPS = {1: [], 2: [1], 3: [2], 4: [3], 5: [3], 6: [3], 7: [4, 5, 6], 8: [4, 5, 6],
        9: [7, 8], 10: [7, 8], 11: [7, 8], 12: [9, 10, 11], 13: [9, 10, 11], 14: [3, 4]}

issues = []
for p in prompts:
    if p["n"] == 0:
        continue
    goal, sections, gate = parse(p["body"])
    assert goal and gate and sections, p["n"]
    n = p["n"]
    build = []
    for s in sections:
        if s["label"]:
            build.append(f"\n{s['label']}\n")
        for lvl, t in s["items"]:
            build.append(("  " if lvl else "") + f"- [ ] {t}")
    gates = [g.strip().rstrip(".") for g in gate.split(";") if g.strip()]
    gates = [g[0].upper() + g[1:] for g in gates]
    labels = ["epic", f"area:{AREA[n]}", PRIO[n]] + (["continuous"] if n in (12, 13) else [])
    issues.append({
        "key": f"P{n:02d}", "n": n,
        "title": f"P{n:02d} — {p['title']}",
        "labels": labels, "milestone": MILESTONE[n], "area": AREA[n],
        "deps": [f"P{d:02d}" for d in DEPS[n]] + (["OWNER14"] if n == 14 else []),
        "body_tmpl": "\n".join([
            "## Goal", "", goal, "",
            f"**Prompt:** [docs/prompts/{p['file']}]({REPO_URL}/blob/main/docs/prompts/{p['file']})"
            + (f" · detailed spec: [02a-realtime-master.md]({REPO_URL}/blob/main/docs/prompts/02a-realtime-master.md)" if n == 2 else ""),
            "", "Run with: read the constitution, DECISIONS.md and this prompt, then continue.", "",
            "## Build", "", "\n".join(build).strip(), "",
            "## Gate", "", "\n".join(f"- [ ] {g}" for g in gates), "",
            "## Depends on", "", "{DEPS}",
        ]),
    })

# Prompt 14 legal gate
p14 = next(p for p in prompts if p["n"] == 14)
g0 = re.search(r"\*\*Gate 0 \(owner, legal and privacy\):\*\* (.+)", p14["body"]).group(1)
issues.append({
    "key": "OWNER14", "n": None,
    "title": "Owner decision: WhatsApp interop legal gate",
    "labels": ["owner-decision", "area:interop", "gate"], "milestone": "M3 Interop and growth",
    "area": "interop", "deps": [],
    "body_tmpl": "\n".join([
        "Gate 0 of [Prompt 14 — WhatsApp interoperability]"
        f"({REPO_URL}/blob/main/docs/prompts/{p14['file']}). P14 cannot start until this is closed.", "",
        "## Owner checklist", "",
        "- [ ] Obtain and review the current WhatsApp Reference Offer and developer documentation",
        "- [ ] Sign Meta's interoperability agreement",
        "- [ ] Write down exactly what Meta will learn about Songbird users who opt in (their interop identifier and the metadata of chats with WhatsApp users)",
        "- [ ] Confirm interop is opt-in per user and clearly labelled in the app",
        "- [ ] Record the decision in `docs/DECISIONS.md`", "",
        "## Source text", "", "> " + g0, "",
        "## Blocks", "", "{BLOCKS}",
    ]),
})

json.dump({"issues": issues, "prompts": [{k: p[k] for k in ("n", "title", "file")} for p in prompts]},
          open(out_json, "w"), indent=1, ensure_ascii=False)
print(f"{len(prompts)} prompt files, {len(issues)} issue specs")
for it in issues:
    print(it["key"], it["title"], "| build items:", it["body_tmpl"].count("- [ ]"))
