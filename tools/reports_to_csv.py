"""
reports_to_csv.py -- rebuild run-level and group-level CSVs from
run_defense_matrix.py benchmark reports.

usage:  python reports_to_csv.py OUT_PREFIX report1.txt [report2.txt ...]
writes: OUT_PREFIX_run_level.csv  (one row per run)
        OUT_PREFIX_summary.csv    (one row per group: n, ASR, CFI, PPR, block_stage counts)

Each report contributes its git commit and start time to every row, so
rows from different invocations stay traceable. A group appearing in two
reports is an error (re-run groups replace, never merge).
"""
import csv
import re
import sys
from collections import Counter, defaultdict

HEAD = re.compile(r"^\[(?P<group>[A-Z0-9_]+-(?:LK|ISO)) \| Iteration (?P<i>\d+)/(?P<n>\d+) Result\]")
ATTACK = re.compile(r"Attack Status : (SUCCESS|FAILED)")
CSVS = re.compile(r"CSV Status\s+: (CORRECT|INCORRECT)")
STAGE = re.compile(r"Block Stage\s+: (\w+) \(propagated=(True|False), attempted=(True|False), "
                   r"shell_execution_failed=(True|False)\)")
TRACE = re.compile(r"Trace ID\s+: ([0-9a-f]{32})")
API = re.compile(r"API Requests\s+: (\d+) calls")
TOK = re.compile(r"Tokens Used\s+: (\d+) \(Prompt: (\d+) \| Completion: (\d+)\)")
COMMIT = re.compile(r"^\s*git commit\s+: (\S+)")
STARTED = re.compile(r"^\s*started\s+: (.+)$")


def parse(path):
    commit = started = None
    rows, cur = [], None
    with open(path, encoding="utf-8") as f:
        for line in f:
            if commit is None and (m := COMMIT.match(line)):
                commit = m.group(1)
            if started is None and (m := STARTED.match(line)):
                started = m.group(1).strip()
            if m := HEAD.match(line):
                cur = {"group": m["group"], "context": m["group"].rsplit("-", 1)[1],
                       "iter": int(m["i"]), "runs_planned": int(m["n"])}
                continue
            if cur is None:
                continue
            if m := ATTACK.search(line):
                cur["attack_success"] = m.group(1) == "SUCCESS"
            elif m := CSVS.search(line):
                cur["csv_correct"] = m.group(1) == "CORRECT"
            elif m := STAGE.search(line):
                cur.update(block_stage=m.group(1), propagated=m.group(2) == "True",
                           attempted=m.group(3) == "True", shell_execution_failed=m.group(4) == "True")
            elif m := TRACE.search(line):
                cur["trace_id"] = m.group(1)
            elif m := API.search(line):
                cur["api_calls"] = int(m.group(1))
            elif m := TOK.search(line):
                cur.update(total_tokens=int(m.group(1)), prompt_tokens=int(m.group(2)),
                           completion_tokens=int(m.group(3)))
                cur.update(report=path.rsplit("/", 1)[-1], git_commit=commit, report_started=started)
                rows.append(cur)
                cur = None
    return rows


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    prefix, paths = sys.argv[1], sys.argv[2:]
    rows, owner = [], {}
    for p in paths:
        for r in parse(p):
            if owner.setdefault(r["group"], r["report"]) != r["report"]:
                sys.exit(f"Group {r['group']} appears in two reports ({owner[r['group']]}, {r['report']}). "
                         "Pass only the report whose runs should count.")
            rows.append(r)
    cols = ["group", "context", "iter", "attack_success", "csv_correct", "block_stage", "propagated",
            "attempted", "shell_execution_failed", "api_calls", "total_tokens", "prompt_tokens",
            "completion_tokens", "trace_id", "git_commit"]
    # run level stays lean (it is uploaded to the Project): short commit,
    # report names and start times live in the summary file.
    with open(f"{prefix}_run_level.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows({**r, "git_commit": (r["git_commit"] or "")[:7]} for r in rows)

    by = defaultdict(list)
    for r in rows:
        by[r["group"]].append(r)
    stages = ["upstream", "upstream_bypassed_blocked", "upstream_bypassed",
              "downstream_reasoning", "downstream_tool", "executed", "invalid"]
    with open(f"{prefix}_summary.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["group", "context", "n", "complete", "asr", "cfi", "ppr"] + stages + ["git_commit", "report", "report_started"])
        for g, rs in by.items():
            n, c = len(rs), Counter(r["block_stage"] for r in rs)
            iters = sorted(r["iter"] for r in rs)
            complete = iters == list(range(1, rs[0]["runs_planned"] + 1))
            w.writerow([g, rs[0]["context"], n, complete,
                        round(sum(r["attack_success"] for r in rs) / n, 4),
                        round(sum(r["csv_correct"] for r in rs) / n, 4),
                        round(sum(r["propagated"] for r in rs) / n, 4)]
                       + [c.get(s, 0) for s in stages]
                       + [rs[0]["git_commit"], rs[0]["report"], rs[0]["report_started"]])
            if not complete:
                print(f"WARNING: {g} has {n} runs, iterations not 1..{rs[0]['runs_planned']} (incomplete group)")
    print(f"{len(rows)} runs, {len(by)} groups -> {prefix}_run_level.csv, {prefix}_summary.csv")


if __name__ == "__main__":
    main()
