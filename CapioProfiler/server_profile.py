from .regex_extractors import *
from collections import deque
from typing import List, Dict, Any
from .utils import process_capio_inner_methods, format_event_output, process_statistics


def process_request_block(
        lines: List[str],
        request_stats: Dict[str, Dict[str, Any]],
        detail_stats: Dict[str, Dict[str, Any]],
) -> None:
    if not lines or not SERVER_REQUEST_RE.match(lines[0]):
        return

    # Request name: default "REQUEST" or first hook
    request_name = "REQUEST"  # default
    for line in lines:
        hook = extract_hook_name(line)
        if hook and hook.endswith("_handler") and "call(" in line:
            request_name = hook
            break

    # Ensure request in global stats
    entry = request_stats.setdefault(request_name, {"event_count": 0, "total_time_ms": []})

    # Extract timestamps from block
    ts_begin = extract_timestamp(lines[1]) if len(lines) > 1 else None
    ts_end = extract_timestamp(lines[-2]) if len(lines) > 2 else None
    if ts_begin is None or ts_end is None:
        return

    elapsed = max(ts_end - ts_begin, 1)
    entry["event_count"] += 1
    entry["total_time_ms"].append(elapsed)

    # Track function calls
    stack: deque[Dict[str, Any]] = deque()
    for line in lines:
        if "call(" in line:
            hook = extract_hook_name(line)
            t = extract_timestamp(line)
            if hook and t is not None:
                stack.append({"func": hook, "timestamp": t})

        elif "returned" in line:
            if not stack:
                continue
            ret = stack.pop()
            t = extract_timestamp(line)
            if t is None:
                continue
            elapsed_inner = t - ret["timestamp"]
            func = ret["func"]
            d = detail_stats.setdefault(func, {"count": 0, "exec_time": []})
            d["count"] += 1
            d["exec_time"].append(elapsed_inner)


def profile(path: str) -> Dict[str, Any]:
    request_stats = {}
    detail_stats = {}

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
                if SERVER_END_REQUEST_RE.match(line):
                    process_request_block(block, request_stats, detail_stats)
                    block = []
            else:
                # fallback for empty lines (not strictly needed)
                if block:
                    process_request_block(block, request_stats, detail_stats)
                    block = []

        if block:
            process_request_block(block, request_stats, detail_stats)

    if global_begin_ts is None or global_end_ts is None:
        print("No valid timestamps found in file.")
        return {}

    total_exec_time_sec = (global_end_ts - global_begin_ts) / 1000.0

    rows = process_statistics(request_stats)
    drows = process_capio_inner_methods(detail_stats)

    traced_pid = path.split("_")[-1]
    traced_pid = traced_pid.split(".")[0]

    return format_event_output(drows, "__FUNCTION__", rows, "REQUEST",
                               total_exec_time_sec, traced_pid)
