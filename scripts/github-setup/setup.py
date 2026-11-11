#!/usr/bin/env python3
"""Idempotent GitHub setup for countradooku/songbird: security settings, branch protection,
labels, milestones, epics, issue dependencies, the pinned Start here issue and the project board.

Usage: setup.py <issues.json from gen.py> [--skip-project]
Every step checks what exists first, so it is safe to re-run. Needs the gh CLI, logged in as the
owner; the project board also needs the `project` scope (gh auth refresh -s project).
"""
import json, subprocess, sys

OWNER, NAME = "countradooku", "songbird"
REPO = f"{OWNER}/{NAME}"
URL = f"https://github.com/{REPO}"
spec = json.load(open(sys.argv[1]))
SKIP_PROJECT = "--skip-project" in sys.argv
problems = []  # (step, reason)


def run(args, data=None, check=True):
    r = subprocess.run(args, input=data, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:4])}: {(r.stderr or r.stdout).strip()}")
    return r


def api(method, path, body=None, check=True):
    args = ["gh", "api", "-X", method, path, "-H", "Accept: application/vnd.github+json"]
    if body is not None:
        args += ["--input", "-"]
    r = run(args, json.dumps(body) if body is not None else None, check)
    return json.loads(r.stdout) if r.stdout.strip() else None


def gql(query, **variables):
    r = run(["gh", "api", "graphql", "--input", "-"], json.dumps({"query": query, "variables": variables}))
    out = json.loads(r.stdout)
    if out.get("errors"):
        raise RuntimeError(out["errors"][0]["message"])
    return out["data"]


def attempt(step, fn):
    try:
        fn()
        print(f"ok    {step}")
        return True
    except Exception as e:  # record and continue
        msg = str(e).splitlines()[0][:300]
        problems.append((step, msg))
        print(f"FAIL  {step}: {msg}")
        return False


# ---------------- 1. security settings and branch protection ----------------
attempt("private vulnerability reporting", lambda: api("PUT", f"/repos/{REPO}/private-vulnerability-reporting"))
attempt("Dependabot alerts", lambda: api("PUT", f"/repos/{REPO}/vulnerability-alerts"))
attempt("Dependabot security updates", lambda: api("PUT", f"/repos/{REPO}/automated-security-fixes"))


def secret_scanning():
    api("PATCH", f"/repos/{REPO}", {"security_and_analysis": {
        "secret_scanning": {"status": "enabled"},
        "secret_scanning_push_protection": {"status": "enabled"}}})
    sa = api("GET", f"/repos/{REPO}").get("security_and_analysis") or {}
    if (sa.get("secret_scanning") or {}).get("status") != "enabled":
        raise RuntimeError(f"not enabled after request; security_and_analysis={json.dumps(sa)}")


attempt("secret scanning and push protection", secret_scanning)
attempt("CodeQL default setup", lambda: api("PATCH", f"/repos/{REPO}/code-scanning/default-setup",
                                            {"state": "configured", "query_suite": "default"}))
attempt("protect main", lambda: api("PUT", f"/repos/{REPO}/branches/main/protection", {
    # PRs required; 0 approvals because the owner works alone (GitHub forbids approving your own PR).
    "required_pull_request_reviews": {"required_approving_review_count": 0, "dismiss_stale_reviews": True},
    # No CI yet: strict mode on, no required contexts. Add the CI job names once CI exists.
    "required_status_checks": {"strict": True, "contexts": []},
    "enforce_admins": True,
    "restrictions": None,
    "allow_force_pushes": False,
    "allow_deletions": False,
    "required_linear_history": False,
    "required_conversation_resolution": True,
}))

# ---------------- 2. labels ----------------
LABELS = {
    "epic": ("5319e7", "One prompt from docs/prompts, end to end"),
    "gate": ("b60205", "Stops at a gate: report and wait for the owner"),
    "owner-decision": ("d93f0b", "Needs a decision from the owner"),
    "security": ("b60205", "Security-relevant"),
    "benchmark": ("fbca04", "Needs or changes benchmark numbers"),
    "continuous": ("0e8a16", "Starts early and reruns before every release"),
    "p0": ("b60205", "Priority 0: closed-beta critical path"),
    "p1": ("d93f0b", "Priority 1"),
    "p2": ("fbca04", "Priority 2"),
}
AREAS = ["platform", "realtime", "identity", "messaging", "groups", "media", "calls", "push",
         "settings", "backups", "plans-abuse", "security", "perf-dr", "interop"]
for a in AREAS:
    LABELS[f"area:{a}"] = ("c5def5", f"Area: {a}")
for name, (color, desc) in LABELS.items():
    attempt(f"label {name}", lambda n=name, c=color, d=desc: run(
        ["gh", "label", "create", n, "-R", REPO, "--color", c, "--description", d, "--force"]))

# ---------------- 3. milestones ----------------
MILESTONES = {
    "M0 Foundations": "Prompt 1",
    "M1 Closed-beta backend": "Prompts 2, 3, 4, 5, 6, 8, 9, 10",
    "M2 Public-beta backend": "Prompts 7, 11, 12, 13 (12 and 13 start early and rerun before every release)",
    "M3 Interop and growth": "Prompt 14",
}
existing_ms = {m["title"]: m for m in api("GET", f"/repos/{REPO}/milestones?state=all&per_page=100")}
for title, desc in MILESTONES.items():
    if title not in existing_ms:
        attempt(f"milestone {title}", lambda t=title, d=desc: api(
            "POST", f"/repos/{REPO}/milestones", {"title": t, "description": d}))
    else:
        print(f"skip  milestone {title} (exists)")
milestones = {m["title"]: m for m in api("GET", f"/repos/{REPO}/milestones?state=all&per_page=100")}

# ---------------- 4. issues ----------------
START_TITLE = "Start here"
issues = spec["issues"]


def list_issues():
    r = run(["gh", "issue", "list", "-R", REPO, "--state", "all", "--limit", "500",
             "--json", "number,title,id,isPinned"])
    return {i["title"]: i for i in json.loads(r.stdout)}


have = list_issues()
for it in issues + [{"title": START_TITLE, "labels": [], "milestone": None}]:
    if it["title"] in have:
        print(f"skip  issue {it['title']} (exists #{have[it['title']]['number']})")
        continue
    args = ["gh", "issue", "create", "-R", REPO, "--title", it["title"], "--body", "_Being set up._"]
    attempt(f"create issue {it['title']}", lambda a=args: run(a))
have = list_issues()
num = {it["key"]: have[it["title"]]["number"] for it in issues}
title_of = {it["key"]: it["title"] for it in issues}
by_num = {v: k for k, v in num.items()}


def deps_md(keys):
    return "\n".join(f"- #{num[k]} {title_of[k]}" for k in keys) if keys else "_None. This is the first epic._"


for it in issues:
    n = num[it["key"]]
    body = it["body_tmpl"].replace("{DEPS}", deps_md(it["deps"]))
    if it["key"] == "OWNER14":
        body = body.replace("{BLOCKS}", f"- #{num['P14']} {title_of['P14']}")
    args = ["gh", "issue", "edit", str(n), "-R", REPO, "--body-file", "-",
            "--milestone", it["milestone"]]
    for lab in it["labels"]:
        args += ["--add-label", lab]
    attempt(f"update issue #{n}", lambda a=args, b=body: run(a, b))

# issue dependencies ("blocked by")
db_id = {}


def issue_db_id(n):
    if n not in db_id:
        db_id[n] = api("GET", f"/repos/{REPO}/issues/{n}")["id"]
    return db_id[n]


deps_supported = True
for it in issues:
    if not it["deps"] or not deps_supported:
        continue
    n = num[it["key"]]
    try:
        current = {i["number"] for i in api("GET", f"/repos/{REPO}/issues/{n}/dependencies/blocked_by")}
    except Exception as e:
        deps_supported = False
        problems.append(("issue dependencies (blocked by)", str(e).splitlines()[0][:300]))
        print(f"FAIL  issue dependencies: {e}")
        continue
    for k in it["deps"]:
        if num[k] in current:
            continue
        attempt(f"#{n} blocked by #{num[k]}", lambda n=n, k=k: api(
            "POST", f"/repos/{REPO}/issues/{n}/dependencies/blocked_by", {"issue_id": issue_db_id(num[k])}))

# ---------------- 5. project board ----------------
project_url = None
PHASES = list(MILESTONES)
STATUS = ["Todo", "In progress", "At gate", "Done"]
COLORS = ["GRAY", "BLUE", "GREEN", "YELLOW", "ORANGE", "RED", "PINK", "PURPLE"]


def opts(names):
    return [{"name": n, "color": COLORS[i % len(COLORS)], "description": ""} for i, n in enumerate(names)]


def project():
    global project_url
    q = gql("""query($login:String!){ user(login:$login){ id projectsV2(first:100){ nodes{ id number title url } } } }""",
            login=OWNER)["user"]
    proj = next((p for p in q["projectsV2"]["nodes"] if p["title"] == "Songbird Backend"), None)
    if not proj:
        proj = gql("""mutation($o:ID!,$t:String!){ createProjectV2(input:{ownerId:$o,title:$t}){ projectV2{ id number title url } } }""",
                   o=q["id"], t="Songbird Backend")["createProjectV2"]["projectV2"]
        print(f"ok    created project {proj['url']}")
    project_url = proj["url"]
    pid = proj["id"]
    repo_id = gql("""query($o:String!,$n:String!){ repository(owner:$o,name:$n){ id projectsV2(first:20){ nodes{ id } } } }""",
                  o=OWNER, n=NAME)["repository"]
    if pid not in [p["id"] for p in repo_id["projectsV2"]["nodes"]]:
        gql("""mutation($p:ID!,$r:ID!){ linkProjectV2ToRepository(input:{projectId:$p,repositoryId:$r}){ clientMutationId } }""",
            p=pid, r=repo_id["id"])
    gql("""mutation($p:ID!,$d:String!,$r:String!){ updateProjectV2(input:{projectId:$p,shortDescription:$d,readme:$r}){ projectV2{ id } } }""",
        p=pid, d="Songbird backend epics by phase and area",
        r=f"Epics for {URL}. One epic per prompt in docs/prompts. Status: Todo → In progress → At gate → Done.")

    def fields():
        f = gql("""query($p:ID!){ node(id:$p){ ... on ProjectV2 { fields(first:50){ nodes{
                  ... on ProjectV2SingleSelectField { id name options{ id name } } } } } } }""", p=pid)
        return {x["name"]: x for x in f["node"]["fields"]["nodes"] if x}

    fs = fields()
    if [o["name"] for o in fs["Status"]["options"]] != STATUS:
        gql("""mutation($f:ID!,$o:[ProjectV2SingleSelectFieldOptionInput!]!){
                 updateProjectV2Field(input:{fieldId:$f,singleSelectOptions:$o}){ projectV2Field{ ... on ProjectV2SingleSelectField { id } } } }""",
            f=fs["Status"]["id"], o=opts(STATUS))
    for fname, names in (("Phase", PHASES), ("Area", AREAS)):
        if fname not in fs:
            gql("""mutation($p:ID!,$n:String!,$o:[ProjectV2SingleSelectFieldOptionInput!]!){
                     createProjectV2Field(input:{projectId:$p,dataType:SINGLE_SELECT,name:$n,singleSelectOptions:$o}){ clientMutationId } }""",
                p=pid, n=fname, o=opts(names))
    fs = fields()
    oid = {fn: {o["name"]: o["id"] for o in fs[fn]["options"]} for fn in ("Status", "Phase", "Area")}

    items = gql("""query($p:ID!){ node(id:$p){ ... on ProjectV2 { items(first:100){ nodes{ id
                   content{ ... on Issue { number } }
                   fieldValueByName(name:"Status"){ ... on ProjectV2ItemFieldSingleSelectValue { name } } } } } } }""",
                p=pid)["node"]["items"]["nodes"]
    status_of = {i["content"]["number"]: (i["fieldValueByName"] or {}).get("name") for i in items if i["content"]}

    every = list_issues()
    targets = [(it, every[it["title"]]) for it in issues] + [(None, every[START_TITLE])]
    for it, iss in targets:
        item = gql("""mutation($p:ID!,$c:ID!){ addProjectV2ItemById(input:{projectId:$p,contentId:$c}){ item{ id } } }""",
                   p=pid, c=iss["id"])["addProjectV2ItemById"]["item"]["id"]
        values = {"Phase": it["milestone"] if it else PHASES[0]}
        if it:
            values["Area"] = it["area"]
        if not status_of.get(iss["number"]):  # never overwrite progress on re-runs
            values["Status"] = "Todo"
        for fn, val in values.items():
            gql("""mutation($p:ID!,$i:ID!,$f:ID!,$o:String!){ updateProjectV2ItemFieldValue(input:{projectId:$p,itemId:$i,fieldId:$f,
                     value:{singleSelectOptionId:$o}}){ clientMutationId } }""",
                p=pid, i=item, f=fs[fn]["id"], o=oid[fn][val])
    print(f"ok    project items set ({len(targets)})")

    # Views. The API can create views and pick visible fields, but cannot set group-by or sort;
    # those two settings are made once in the web UI (see the report).
    allf = gql("""query($p:ID!){ node(id:$p){ ... on ProjectV2 {
                 fields(first:50){ nodes{ ... on ProjectV2FieldCommon { id name } } }
                 views(first:20){ nodes{ id name layout } } } } }""", p=pid)["node"]
    fid = {f["name"]: f["id"] for f in allf["fields"]["nodes"] if f}
    views = {v["name"]: v for v in allf["views"]["nodes"]}
    wanted = [("Table by issue number", "TABLE_LAYOUT", ["Title", "Status", "Phase", "Area", "Milestone", "Labels"]),
              ("Board by phase", "BOARD_LAYOUT", ["Title", "Status", "Phase", "Area", "Labels"])]
    if "View 1" in views and "Table by issue number" not in views:  # reuse the default view
        gql("""mutation($v:ID!,$n:String!){ updateProjectV2View(input:{viewId:$v,name:$n,layout:TABLE_LAYOUT}){ clientMutationId } }""",
            v=views["View 1"]["id"], n="Table by issue number")
        views["Table by issue number"] = views.pop("View 1")
    for vname, layout, vis in wanted:
        cfg = {"visibleFieldIds": [fid[f] for f in vis]}
        if vname in views:
            gql("""mutation($v:ID!,$c:ProjectV2ViewConfigurationInput){ updateProjectV2View(input:{viewId:$v,configuration:$c}){ clientMutationId } }""",
                v=views[vname]["id"], c=cfg)
        else:
            gql("""mutation($p:ID!,$n:String!,$l:ProjectV2ViewLayout!,$c:ProjectV2ViewConfigurationInput){
                     createProjectV2View(input:{projectId:$p,name:$n,layout:$l,configuration:$c}){ clientMutationId } }""",
                p=pid, n=vname, l=layout, c=cfg)
    print("ok    project views")
    return proj


proj = None
if SKIP_PROJECT:
    problems.append(("project board", "skipped (--skip-project)"))
else:
    def _p():
        global proj
        proj = project()
    attempt("project board", _p)

# ---------------- Start here ----------------
start = list_issues()[START_TITLE]
board = f"[Songbird Backend project board]({project_url})" if project_url else "Songbird Backend project board (not created yet)"
epic_lines = "\n".join(f"- #{num[f'P{n:02d}']} {title_of[f'P{n:02d}']}" for n in range(1, 15))
start_body = f"""Welcome to the Songbird backend. Read these first:

- [README]({URL}#readme)
- [Constitution: docs/prompts/00-constitution.md]({URL}/blob/main/docs/prompts/00-constitution.md) (read before every task)
- [Decisions: docs/DECISIONS.md]({URL}/blob/main/docs/DECISIONS.md)
- [Prompt set and run order]({URL}/blob/main/docs/prompts/README.md)
- [Milestones]({URL}/milestones): M0 Foundations → M1 Closed-beta backend → M2 Public-beta backend → M3 Interop and growth
- {board}

## How to run an epic

Start each session with: *"Read docs/prompts/00-constitution.md, docs/DECISIONS.md and docs/prompts/NN-….md, list the skills available to you and load the best ones for this task, then continue."* Every prompt ends at a gate: the agent stops, writes `docs/reports/PNN-<gate>.md`, and waits for the owner.

## Epics

{epic_lines}

Owner decision blocking P14: #{num['OWNER14']} {title_of['OWNER14']}
"""
attempt("update Start here", lambda: run(["gh", "issue", "edit", str(start["number"]), "-R", REPO, "--body-file", "-"], start_body))
if not start["isPinned"]:
    attempt("pin Start here", lambda: run(["gh", "issue", "pin", str(start["number"]), "-R", REPO]))

# ---------------- report ----------------
final = json.loads(run(["gh", "issue", "list", "-R", REPO, "--state", "all", "--limit", "500",
                        "--json", "number,title,milestone,labels,url"]).stdout)
final.sort(key=lambda i: i["number"])
json.dump({"issues": final, "problems": problems, "project_url": project_url},
          open(sys.argv[1].replace(".json", "-report.json"), "w"), indent=1, ensure_ascii=False)
print("\nproblems:")
for s, m in problems:
    print(f"- {s}: {m}")
