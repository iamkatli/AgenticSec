#!/usr/bin/env bash
# run_queue.sh -- run a queue of benchmark groups one group per invocation,
# and resume where it stopped after a reboot or a crash. Works for any model
# and any machine: the queue lives in a small text file, and progress is kept
# per model and per queue, so queues of different models never mix.
#
#   bash tools/run_queue.sh queues/crewai_gpt-oss_20b.queue             # start / resume
#   bash tools/run_queue.sh queues/crewai_gpt-oss_20b.queue --status    # done / pending
#   bash tools/run_queue.sh queues/crewai_qwen3_14b.queue --mark-done BASE-ISO 300 reports/benchmark_report_base-iso_....txt
#        (register a group that was run outside the queue, so it is skipped)
#
# QUEUE FILE (one group per line, "#" starts a comment):
#   # model: gpt-oss:20b        <- required; must match MODEL in .env
#   ZERO-LK 10                  <- "<group key> <runs>"
#   ...
#   Lines with 10 runs for ZERO-LK / ZERO-ISO / BASE-LK / BASE-ISO are the
#   pilot. If a queue has them, a gate check runs once before the first
#   non-pilot group and stops the queue if BASE-LK ASR is 0/10 (model not
#   calling the tool?) or a ZERO group's CFI is below GATE_MIN_ZERO_CFI/10.
#
# RESUMING: each finished group (exit code 0) gets a marker in
#   $STATE_ROOT/<model>/<queue name>/ recording when it finished, its report
#   and the git commit. Marked groups are skipped; an interrupted group starts
#   again from run 1 (its partial runs stay in logs/ but are never counted).
#   Any non-zero exit (anomaly halt, model server down for 15 retries, crash)
#   stops the whole queue.
#
# SETTINGS (environment variables, all optional):
#   REPO        repo folder           (default: the folder above this script)
#   VENV        venv activate script  (default: $REPO/.venv, else ../myenv)
#   STATE_ROOT  progress folder       (default: <folder above REPO>/queue_state, outside the repo)
#   OLLAMA_URL  Ollama to wait for    (default: http://localhost:11434)
#   EXTRA_ARGS  extra flags for run_defense_matrix.py (e.g. "--no-halt-on-anomaly")
#   GATE_MIN_ZERO_CFI  minimum ZERO CFI out of 10 in the pilot (default 1)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/.." && pwd)}"
STATE_ROOT="${STATE_ROOT:-$(cd "$REPO/.." && pwd)/queue_state}"
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
EXTRA_ARGS="${EXTRA_ARGS:-}"
GATE_MIN_ZERO_CFI="${GATE_MIN_ZERO_CFI:-1}"
if [[ -z "${VENV:-}" ]]; then
  if [[ -f "$REPO/.venv/bin/activate" ]]; then VENV="$REPO/.venv/bin/activate"
  else VENV="$(cd "$REPO/.." && pwd)/myenv/bin/activate"; fi
fi

QUEUE_FILE="${1:-}"
[[ -n "$QUEUE_FILE" && -f "$QUEUE_FILE" ]] || { echo "usage: bash $0 <queue file> [--status | --mark-done KEY RUNS REPORT]"; exit 1; }
QUEUE_FILE="$(cd "$(dirname "$QUEUE_FILE")" && pwd)/$(basename "$QUEUE_FILE")"
MODE="${2:-run}"

# --- read the queue file ----------------------------------------------------
QUEUE_MODEL="$(grep -m1 -E '^#[[:space:]]*model:' "$QUEUE_FILE" | sed -E 's/^#[[:space:]]*model:[[:space:]]*//; s/[[:space:]]*$//')"
[[ -n "$QUEUE_MODEL" ]] || { echo "queue file has no '# model: <tag>' line"; exit 1; }
mapfile -t QUEUE < <(sed -E 's/#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//' "$QUEUE_FILE" | grep -v '^$')

QNAME="$(basename "$QUEUE_FILE" .queue)"
STATE="$STATE_ROOT/${QUEUE_MODEL//[:\/]/_}/$QNAME"
mkdir -p "$STATE"
QUEUE_LOG="$STATE/queue.log"
say() { echo "[$(date '+%F %T')] $*" | tee -a "$QUEUE_LOG"; }
marker() { echo "$STATE/${1}_n${2}.done"; }
is_pilot() { [[ "$2" == "10" && "$1" =~ ^(ZERO|BASE)-(LK|ISO)$ ]]; }

# --- --status -----------------------------------------------------------------
if [[ "$MODE" == "--status" ]]; then
  echo "queue $QNAME  model $QUEUE_MODEL  state $STATE"
  done_n=0; total=0
  for item in "${QUEUE[@]}"; do
    read -r key runs <<<"$item"; total=$((total + 1))
    if [[ -f "$(marker "$key" "$runs")" ]]; then
      done_n=$((done_n + 1)); echo "done     $key x$runs  ($(head -1 "$(marker "$key" "$runs")"))"
    else
      echo "pending  $key x$runs"
    fi
  done
  echo "$done_n / $total groups done"
  exit 0
fi

# --- --mark-done --------------------------------------------------------------
if [[ "$MODE" == "--mark-done" ]]; then
  key="${3:-}"; runs="${4:-}"; report="${5:-}"
  if [[ -z "$key" || -z "$runs" || -z "$report" ]]; then
    echo "usage: --mark-done KEY RUNS REPORT"; exit 1
  fi
  # store the report path relative to the repo (that is how the gate reads it)
  if [[ -f "$REPO/$report" ]]; then :; elif [[ -f "$report" ]]; then report="$(realpath --relative-to="$REPO" "$report")"
  else echo "report not found: $report"; exit 1; fi
  printf '%s\n' "${QUEUE[@]}" | grep -qx "$key $runs" || echo "note: '$key $runs' is not in this queue file"
  printf 'finished %s (marked by hand)\nreport=%s\n' "$(date '+%F %T')" "$report" > "$(marker "$key" "$runs")"
  say "MARKED $key x$runs as done (report $report)"
  exit 0
fi

# --- run ------------------------------------------------------------------------
# shellcheck disable=SC1090
source "$VENV" || { echo "cannot activate $VENV"; exit 1; }
cd "$REPO" || { echo "cannot cd to $REPO"; exit 1; }

ENV_MODEL="$(grep -E '^MODEL=' .env | tail -1 | cut -d= -f2- | tr -d '"'"'" | sed 's#^[^/]*/##')"
if [[ "$ENV_MODEL" != "$QUEUE_MODEL" ]]; then
  say "STOP: .env MODEL is '$ENV_MODEL' but the queue is for '$QUEUE_MODEL'."; exit 1
fi
if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
  say "WARNING: the repo has uncommitted changes -- reports will list them as 'git dirty files':"
  git status --porcelain | tee -a "$QUEUE_LOG"
fi

for _ in $(seq 1 30); do
  curl -sf "$OLLAMA_URL" >/dev/null && break
  say "waiting for Ollama at $OLLAMA_URL..."; sleep 10
done
curl -sf "$OLLAMA_URL" >/dev/null || { say "Ollama not reachable at $OLLAMA_URL -- stopping"; exit 1; }

gate_check() {
  # Reads the pilot groups' reports (paths recorded in their markers).
  python - "$GATE_MIN_ZERO_CFI" "$STATE" <<'EOF'
import os, re, sys
min_cfi, state = int(sys.argv[1]), sys.argv[2]
row = re.compile(r"^(\S+)\s+\|\s+(\d+)\s+\|\s+(\d+)/\d+ \([\d.]+%\) \| (\d+)/\d+")
res = {}
for key in ("ZERO-LK", "ZERO-ISO", "BASE-LK", "BASE-ISO"):
    m = os.path.join(state, f"{key}_n10.done")
    if not os.path.exists(m):
        continue
    report = next((l.split("=", 1)[1].strip() for l in open(m) if l.startswith("report=")), "")
    if not report or not os.path.exists(report):
        continue
    for line in open(report, encoding="utf-8"):
        r = row.match(line.strip())
        if r and r.group(1) == key and r.group(2) == "10":
            res[key] = (int(r.group(3)), int(r.group(4)))
for k, (asr, cfi) in res.items():
    print(f"  gate {k:<9} ASR {asr}/10  CFI {cfi}/10")
problems = []
if len(res) < 4:
    problems.append(f"could not read all pilot results (found {sorted(res)})")
if res.get("BASE-LK", (1, 0))[0] == 0:
    problems.append("BASE-LK ASR = 0/10 (is the model calling the tool at all?)")
for k in ("ZERO-LK", "ZERO-ISO"):
    if k in res and res[k][1] < min_cfi:
        problems.append(f"{k} CFI {res[k][1]}/10 < {min_cfi}/10 (model may be failing the normal task)")
for p in problems:
    print("  GATE FAIL:", p)
sys.exit(1 if problems else 0)
EOF
}

has_pilot=0
for item in "${QUEUE[@]}"; do read -r k r <<<"$item"; is_pilot "$k" "$r" && has_pilot=1; done

say "=== queue $QNAME start (commit $(git rev-parse --short HEAD), model $QUEUE_MODEL, ${#QUEUE[@]} groups) ==="
for item in "${QUEUE[@]}"; do
  read -r key runs <<<"$item"
  m="$(marker "$key" "$runs")"
  [[ -f "$m" ]] && continue

  if [[ $has_pilot -eq 1 ]] && ! is_pilot "$key" "$runs" && [[ ! -f "$STATE/gate.passed" ]]; then
    say "gate check on the pilot groups:"
    gate_out="$(gate_check)"; gate_rc=$?
    echo "$gate_out" | tee -a "$QUEUE_LOG"
    if [[ $gate_rc -eq 0 ]]; then
      touch "$STATE/gate.passed"; say "gate passed"
    else
      say "gate FAILED -- queue stopped. Check the pilot reports in $REPO/reports/."
      say "To continue anyway: touch $STATE/gate.passed && bash $0 $QUEUE_FILE"
      exit 1
    fi
  fi

  say "START $key x$runs"
  stamp="$STATE/.started"; touch "$stamp"
  # shellcheck disable=SC2086
  python run_defense_matrix.py "$key" --runs "$runs" $EXTRA_ARGS
  rc=$?
  if [[ $rc -ne 0 ]]; then
    say "STOP: $key exited with code $rc -- queue halted (see the report in reports/)."
    exit $rc
  fi
  report="$(find reports -maxdepth 1 -name "benchmark_report_$(echo "$key" | tr 'A-Z' 'a-z')_*.txt" -newer "$stamp" -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)"
  [[ -n "$report" ]] || say "WARNING: could not find the report for $key"
  printf 'finished %s\nreport=%s\ncommit=%s\n' "$(date '+%F %T')" "$report" "$(git rev-parse --short HEAD)" > "$m"
  say "DONE  $key x$runs  -> $report"
done
say "=== queue $QNAME complete ==="
