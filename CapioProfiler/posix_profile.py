from .regex_extractors import *
from collections import deque
from typing import List, Dict, Any
import numpy as np


def process_syscall_block(
        lines: List[str],
        syscall_stats: Dict[str, Dict[str, int]],
        detail_stats: Dict[str, Dict[str, int]],
) -> int:
    """Process one syscall block (starts with '+', ends with '~')."""

    if not lines or not lines[0].startswith("+"):
        return

    # Parse syscall name from the "+ ..." header
    parts = lines[0].strip().split()
    syscall_name = parts[2] if len(parts) > 2 else "unknown"

    # If unknown: derive from first hook
    if syscall_name == "unknown" and len(lines) > 1:
        hook = extract_hook_name(lines[1])
        if hook:
            syscall_name = hook

    # Ensure syscall in global stats
    entry = syscall_stats.setdefault(syscall_name, {"event_count": 0, "total_time_ms": []})

    # Extract timestamps from block
    ts_begin = extract_timestamp(lines[1]) if len(lines) > 1 else None
    ts_end = extract_timestamp(lines[-2]) if len(lines) > 2 else None

    if ts_begin is None or ts_end is None:
        return

    elapsed = max(ts_end - ts_begin, 1)
    entry["event_count"] += 1
    entry["total_time_ms"].append(elapsed)

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

            d = detail_stats.setdefault(func, {"count": 0, "exec_time": []})
            d["count"] += 1
            d["exec_time"].append(elapsed_inner)

    return


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
                process_syscall_block(block, syscall_stats, detail_stats)
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
    max_time = max((np.sum(v["total_time_ms"]) for v in syscall_stats.values()), default=1)

    for name, v in syscall_stats.items():
        total_ms = v["total_time_ms"]
        events = v["event_count"]
        reduced_total_ms = np.sum(total_ms)
        rows.append([
            name,
            events,
            reduced_total_ms / max_time,
            reduced_total_ms / 1000.0,
            reduced_total_ms / 1000.0,
            np.sqrt(np.mean((total_ms - np.mean(total_ms)) ** 2)) / 1000.0,
            np.mean(total_ms) / 1000.0,
        ])

    clean_rows = [r for r in rows if len(r) >= 3]

    if len(clean_rows) != len(rows):
        print(f"[WARN] Skipped {len(rows) - len(clean_rows)} malformed rows in {path}")

    clean_rows.sort(key=lambda r: np.sum(r[2]), reverse=True)
    rows = clean_rows

    drows = []
    for name, info in sorted(detail_stats.items(), key=lambda kv: np.sum(kv[1]["exec_time"]), reverse=True):
        events = info["count"]
        total_ms = info["exec_time"]
        drows.append([
            name,
            events,
            np.sum(total_ms) / 1000.0,
            np.average(total_ms) / 1000.0,
            np.sqrt(np.mean((total_ms - np.mean(total_ms)) ** 2)),
            np.mean(total_ms) / 1000.0,
        ])

    traced_pid = path.split("_")[-1]
    traced_pid = traced_pid.split(".")[0]

    return {
        "pid": int(traced_pid),
        "name": "posix",
        "total_exec_time": total_exec_time_sec,
        "global": {
            "headers": ["SYSCALL", "Events", "% over time", "Total seconds", "Average", "Std.dev", "Variance"],
            "data": rows,
        },
        "function": {
            "headers": ["__FUNCTION__", "Events", "Total seconds", "Average", "Std.dev", "Variance"],
            "data": drows,
        }
    }
