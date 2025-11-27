import sys
import re
from collections import deque
from typing import List, Dict, Any
from tabulate import tabulate


TIMESTAMP_RE = re.compile(r"at\[(\d+)\]")
HOOK_RE = re.compile(r"at\[\d+]\[(.*?)\]")
SYSCALL_TAG_RE = re.compile(r"^\+.*?\s(\w+)$")   # + <timestamp> <syscall>


def extract_timestamp(line: str) -> int | None:
    m = TIMESTAMP_RE.search(line)
    return int(m.group(1)) if m else None


def extract_hook_name(line: str) -> str | None:
    m = HOOK_RE.search(line)
    return m.group(1) if m else None



def process_syscall_block(
    lines: List[str],
    syscall_stats: Dict[str, Dict[str, int]],
    detail_stats: Dict[str, Dict[str, int]],
) -> int:
    """Process one syscall block (starts with '+', ends with '~')."""

    if not lines or not lines[0].startswith("+"):
        return 0

    # Parse syscall name from the "+ ..." header
    parts = lines[0].strip().split()
    syscall_name = parts[2] if len(parts) > 2 else "unknown"

    # If unknown: derive from first hook
    if syscall_name == "unknown" and len(lines) > 1:
        hook = extract_hook_name(lines[1])
        if hook:
            syscall_name = hook

    # Ensure syscall in global stats
    entry = syscall_stats.setdefault(syscall_name, {"event_count": 0, "total_time_ms": 0})

    # Extract timestamps from block
    ts_begin = extract_timestamp(lines[1]) if len(lines) > 1 else None
    ts_end = extract_timestamp(lines[-2]) if len(lines) > 2 else None

    if ts_begin is None or ts_end is None:
        return 0

    elapsed = max(ts_end - ts_begin, 1)
    entry["event_count"] += 1
    entry["total_time_ms"] += elapsed

    stack: deque[Dict[str, Any]] = deque()

    for line in lines:
        if "call(" in line:
            hook = extract_hook_name(line)
            t = extract_timestamp(line)
            if hook and t is not None:
                stack.append({"func": hook, "timestamp": t})

        elif "returned" in line:
            if not stack:
                continue  # unmatched return, ignore

            ret = stack.pop()
            t = extract_timestamp(line)
            if t is None:
                continue

            elapsed_inner = t - ret["timestamp"]
            func = ret["func"]

            d = detail_stats.setdefault(func, {"count": 0, "exec_time": 0})
            d["count"] += 1
            d["exec_time"] += elapsed_inner

    return ts_end



def profile(path: str):
    syscall_stats = {}
    detail_stats = {}

    # Track overall begin/end timestamps
    global_begin_ts = None
    global_end_ts = None

    block = []

    with open(path, "r") as f:
        for line in f:
            ts = extract_timestamp(line)
            if ts is not None:
                if global_begin_ts is None:
                    global_begin_ts = ts
                global_end_ts = ts

            if line.strip():
                block.append(line)
            else:
                # End of block
                end_ts = process_syscall_block(block, syscall_stats, detail_stats)
                block = []

        # Handle final block if missing newline
        if block:
            process_syscall_block(block, syscall_stats, detail_stats)

    if global_begin_ts is None or global_end_ts is None:
        print("No valid timestamps found in file.")
        return

    total_exec_time_sec = (global_end_ts - global_begin_ts) / 1000.0

    # ---------------- GLOBAL SYSCALL STATS ---------------- #

    rows = []
    max_time = max((v["total_time_ms"] for v in syscall_stats.values()), default=1)

    for name, v in syscall_stats.items():
        total_ms = v["total_time_ms"]
        events = v["event_count"]
        rows.append([
            name,
            events,
            total_ms / 1000.0,
            (total_ms / events) / 1000.0,
            (total_ms / max_time) * 100.0,
        ])

    rows.sort(key=lambda r: r[2], reverse=True)

    print(f"Total execution time: {total_exec_time_sec:.6f} Seconds")

    print("\n=== GLOBAL SYSCALL STATISTICS ===")
    print(tabulate(
        rows,
        headers=["SYSCALL", "Events", "Total (Sec.)", "Avg Time (Sec.)", "% of Max"],
        tablefmt="github",
    ))


    print("\n=== DETAILED INTERNAL FUNCTION STATS ===")

    drows = []
    for func, info in sorted(detail_stats.items(), key=lambda kv: kv[1]["exec_time"], reverse=True):
        drows.append([func, info["count"], info["exec_time"] / 1000.0])

    print(tabulate(
        drows,
        headers=["Function", "Count", "Total Time (s)"],
        tablefmt="github",
    ))