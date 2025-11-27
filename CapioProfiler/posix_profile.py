from .regex_extractors import *
from collections import deque
from typing import List, Dict, Any
from .utils import process_capio_inner_methods, process_statistics, format_event_output


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
    if syscall_name.lower() == "unknown" and len(lines) > 1:
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
        return None

    total_exec_time_sec = (global_end_ts - global_begin_ts) / 1000.0

    rows = process_statistics(syscall_stats)
    drows = process_capio_inner_methods(detail_stats)

    traced_pid = path.split("_")[-1]
    traced_pid = traced_pid.split(".")[0]

    return format_event_output(drows,"__FUNCTION__", rows,"SYSCALL",
                               total_exec_time_sec, traced_pid)
