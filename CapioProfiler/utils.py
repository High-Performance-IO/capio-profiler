import copy
import numpy as np
from collections import deque
from typing import Dict, Any

from CapioProfiler.regex_extractors import extract_timestamp, extract_hook_name


def process_capio_inner_methods(detail_stats: dict[Any, Any]) -> list[Any]:
    drows = []
    max_time = max((np.sum(v["exec_time"]) for v in detail_stats.values()), default=1)
    for name, info in sorted(detail_stats.items(), key=lambda kv: np.sum(kv[1]["exec_time"]), reverse=True):
        events = info["count"]
        total_ms = info["exec_time"]
        reduced_total_ms = np.sum(total_ms)
        drows.append([
            name,
            events,
            reduced_total_ms / max_time,
            reduced_total_ms / 1000.0,
            np.average(total_ms) / 1000.0,
            np.sqrt(np.mean((total_ms - np.mean(total_ms)) ** 2)),
            np.mean(total_ms) / 1000.0,
        ])
    return drows


def process_statistics(
        stats: dict[Any, Any]
) -> list[Any]:
    max_time = max((np.sum(v["total_time_ms"]) for v in stats.values()), default=1)
    rows = []
    for name, v in stats.items():
        total_ms = v["total_time_ms"]
        events = v["event_count"]
        reduced_total_ms = np.sum(total_ms)
        rows.append([
            name,
            events,
            reduced_total_ms / max_time,
            reduced_total_ms / 1000.0,
            np.average(total_ms) / 1000.0,
            np.sqrt(np.mean((total_ms - np.mean(total_ms)) ** 2)) / 1000.0,
            np.mean(total_ms) / 1000.0,
        ])

    clean_rows = [r for r in rows if len(r) >= 3]

    if len(clean_rows) != len(rows):
        print(f"[WARN] Skipped {len(rows) - len(clean_rows)} malformed rows")
    clean_rows.sort(key=lambda r: np.sum(r[2]), reverse=True)

    return clean_rows


def format_event_output(
        events: list[Any],
        detailed_events: list[Any],
        event_kind: str,
        total_exec_time_sec: float,
        traced_pid: str
) -> dict[
    str, int | str | float | dict[str, list[str] | list[Any]]]:
    _TEMPLATE_HEADERS = ["Events", "% over time", "Total seconds", "Average", "Std.dev",
                         "Variance"]

    rows_headers = copy.deepcopy(_TEMPLATE_HEADERS)
    rows_headers.insert(0, event_kind)
    rows_headers_detail = copy.deepcopy(_TEMPLATE_HEADERS)
    rows_headers_detail.insert(0, "__FUNCTION__")
    return {
        "pid": int(traced_pid),
        "name": "posix",
        "total_exec_time": total_exec_time_sec,
        "global": {
            "headers": rows_headers,
            "data": events,
        },
        "function": {
            "headers": rows_headers_detail,
            "data": detailed_events,
        }
    }


def process_single_event(lines, stats, detail_stats, event_name):
    # Ensure syscall in global stats
    entry = stats.setdefault(event_name, {"event_count": 0, "total_time_ms": []})

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
