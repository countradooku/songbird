#!/usr/bin/env bash
# Backup, verify and restore cycle against the compose SurrealDB (development check).
set -euo pipefail
cd /Users/radudiaconu/Desktop/Code/Rust/songbird
set -a; . ./.env; set +a
# The deletion journal key (D-0041): restores refuse to run without it.
DELETION_JOURNAL_KEY=$(openssl rand -hex 32); export DELETION_JOURNAL_KEY
# Usage: bench/m6/backup-cycle.sh <work dir> [age dir]: age and age-keygen from [age dir] or PATH.
S=$1; AGEDIR=${2:-}; AGE=${AGEDIR:+$AGEDIR/}age; KEYGEN=${AGEDIR:+$AGEDIR/}age-keygen; W=$S/bk; A=target/debug/songbird-admin
rm -rf "$W"; mkdir -p "$W"; chmod 700 "$W"
"$KEYGEN" -o "$W/owner.key" 2>/dev/null; "$KEYGEN" -o "$W/verify.key" 2>/dev/null
R1=$(grep -o 'age1[0-9a-z]*' "$W/owner.key"); R2=$(grep -o 'age1[0-9a-z]*' "$W/verify.key")
C=(--addr 127.0.0.1:47800 --user "$SURREAL_USER" --namespace test)
sql() { curl -s -u "$SURREAL_USER:$SURREAL_PASS" -H "Surreal-NS: test" -H "Surreal-DB: $1" -H "Accept: application/json" http://127.0.0.1:47800/sql -d "$2"; }
for db in bk_src bk_verify bk_restored; do sql "$db" "REMOVE DATABASE IF EXISTS $db;" >/dev/null; done
sql bk_src "DEFINE DATABASE IF NOT EXISTS bk_src;" >/dev/null
"$A" generation show "${C[@]}" --database bk_src >/dev/null
sql bk_src "FOR \$a IN 1..=3 { LET \$id = <bytes><string>rand::uuid(); CREATE account:[\$id] SET at = time::now(), deleting = false; CREATE device:[<bytes><string>rand::uuid()] SET account = \$id, key = <bytes>'k', disabled = false, at = time::now(); IF \$a < 3 { CREATE device:[<bytes><string>rand::uuid()] SET account = \$id, key = <bytes>'k', disabled = false, at = time::now(); }; }; UPDATE store:g SET generation = 42;" | python3 -c 'import json,sys;r=json.load(sys.stdin);print("seed statuses:",sorted(set(x["status"] for x in r)))'
echo "--- run"; "$A" backup run "${C[@]}" --database bk_src --dir "$W/store" --recipient "$R1" --recipient "$R2" --age "$AGE" --state "$W/state"
find "$W/store" -type f | sed "s|$W/||"
echo "plaintext markers in the stored file: $(grep -c 'DEFINE TABLE' -r "$W/store" | awk -F: '{s+=$2} END{print s+0}')"
echo "--- verify into bk_verify with the verification identity"; "$A" backup verify "${C[@]}" --database bk_verify --dir "$W/store" --identity "$W/verify.key" --age "$AGE"
echo "--- restore into bk_restored with the owner identity"; "$A" backup restore "${C[@]}" --database bk_restored --confirm test/bk_restored --audit-log "$W/audit.jsonl" --dir "$W/store" --identity "$W/owner.key" --age "$AGE"
echo "--- a third identity cannot decrypt"; "$KEYGEN" -o "$W/stranger.key" 2>/dev/null
if "$A" backup verify "${C[@]}" --database bk_verify2 --dir "$W/store" --identity "$W/stranger.key" --age "$AGE" 2>&1 | tail -1; then :; fi
echo "--- an orphaned device makes verify fail"
sql bk_src "CREATE device:[<bytes><string>rand::uuid()] SET account = <bytes>'no-such-account!', key = <bytes>'k', disabled = false, at = time::now();" >/dev/null
"$A" backup run "${C[@]}" --database bk_src --dir "$W/store" --recipient "$R1" --recipient "$R2" --age "$AGE" --state "$W/state"
if "$A" backup verify "${C[@]}" --database bk_verify3 --dir "$W/store" --identity "$W/verify.key" --age "$AGE"; then echo "UNEXPECTED: verify passed"; else echo "verify failed as it should"; fi
echo "--- restore refuses a database that is not empty, and a missing confirmation"
"$A" backup restore "${C[@]}" --database bk_restored --confirm test/bk_restored --audit-log "$W/audit.jsonl" --dir "$W/store" --identity "$W/owner.key" --age "$AGE" 2>&1 | tail -1 || true
"$A" backup restore "${C[@]}" --database bk_restored --audit-log "$W/audit.jsonl" --dir "$W/store" --identity "$W/owner.key" --age "$AGE" 2>&1 | tail -1 || true
echo "--- audit log"; cat "$W/audit.jsonl"
for db in bk_src bk_verify bk_restored bk_verify2 bk_verify3; do sql "$db" "REMOVE DATABASE IF EXISTS $db;" >/dev/null; done
