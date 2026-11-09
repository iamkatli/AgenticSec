"""
group_windows.py -- Extract actual execution start and end windows for each group
by reading timestamps recorded inside each run's *.log.txt file.

Usage:
    python group_windows.py logs/
    python group_windows.py logs/ A3_LP-LK T3_LP-LK TL_LP-LK
"""

import os
import re
import sys
from datetime import datetime, timedelta, timezone

# Filename pattern: <GROUP>_<BATCH_TS>_run_<RUN_ID>.log.txt
NAME = re.compile(
    r"^(?P<group>.+)_(?P<batch>\d{8}_\d{6})_run_(?P<run>\d+)\.log\.txt$"
)

# Match standard timestamps at the beginning of log lines
# Example: 2026-11-04 06:52:24
TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")

# Get the host's current local timezone (e.g., AEDT / UTC+11)
LOCAL_TZ = datetime.now().astimezone().tzinfo


def extract_file_timestamps(filepath: str):
    """
    Read a single .log.txt file and extract:
    - The earliest valid timestamp (run start)
    - The latest valid timestamp (run end)
    """
    first_dt, last_dt = None, None
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = TS_RE.match(line)
                if m:
                    dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
                    if first_dt is None:
                        first_dt = dt
                    last_dt = dt
    except Exception:
        pass
    return first_dt, last_dt


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    log_dir = sys.argv[1]
    wanted = {g.upper() for g in sys.argv[2:]}
    groups = {}

    # 1. Collect matching .log.txt files
    for fn in os.listdir(log_dir):
        m = NAME.match(fn)
        if not m:
            continue

        group_name = m["group"]
        if wanted and group_name.upper() not in wanted:
            continue

        key = (group_name, m["batch"])
        run_num = int(m["run"])
        groups.setdefault(key, {})[run_num] = os.path.join(log_dir, fn)

    if not groups:
        print("No matching *.log.txt files found.")
        sys.exit(0)

    # 2. Header format (display both UTC and local time)
    header = (
        f"{'group':<12} {'batch':<16} {'runs':>4} | "
        f"{'UTC from':<20} {'UTC to':<20} | "
        f"{'Local from':<19} {'Local to':<19}"
    )
    print(header)
    print("-" * len(header))

    # 3. Sort groups by actual execution start time
    results = []
    for (group, batch), runs in groups.items():
        sorted_run_nums = sorted(runs.keys())
        first_run_file = runs[sorted_run_nums[0]]
        last_run_file = runs[sorted_run_nums[-1]]

        # Take the first timestamp from run_1 (or the lowest run number)
        t0_local, _ = extract_file_timestamps(first_run_file)

        # Take the last timestamp from the final run
        _, t1_local = extract_file_timestamps(last_run_file)

        # Fallback: if no timestamps were found in the log,
        # use the file modification time
        if t0_local is None:
            mtime = os.path.getmtime(first_run_file)
            t0_local = datetime.fromtimestamp(mtime) - timedelta(minutes=5)

        if t1_local is None:
            mtime = os.path.getmtime(last_run_file)
            t1_local = datetime.fromtimestamp(mtime)

        # Add a buffer window:
        # start time minus 1 minute, end time plus 1 minute
        # to avoid missing edge traces from the log server
        t0_local_buffered = t0_local - timedelta(minutes=1)
        t1_local_buffered = t1_local + timedelta(minutes=1)

        # Attach timezone information and convert to UTC
        t0_utc = (
            t0_local_buffered.replace(tzinfo=LOCAL_TZ)
            .astimezone(timezone.utc)
        )
        t1_utc = (
            t1_local_buffered.replace(tzinfo=LOCAL_TZ)
            .astimezone(timezone.utc)
        )

        results.append({
            "group": group,
            "batch": batch,
            "count": len(sorted_run_nums),
            "t0_utc": t0_utc,
            "t1_utc": t1_utc,
            "t0_local": t0_local_buffered,
            "t1_local": t1_local_buffered,
        })

    # Output sorted by actual execution start time
    for r in sorted(results, key=lambda x: x["t0_utc"]):
        print(
            f"{r['group']:<12} {r['batch']:<16} {r['count']:>4} | "
            f"{r['t0_utc']:%Y-%m-%dT%H:%M:%SZ} {r['t1_utc']:%Y-%m-%dT%H:%M:%SZ} | "
            f"{r['t0_local']:%Y-%m-%d %H:%M:%S}   {r['t1_local']:%Y-%m-%d %H:%M:%S}"
        )


if __name__ == "__main__":
    main()
