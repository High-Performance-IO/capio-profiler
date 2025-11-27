import copy
from typing import Any
import numpy as np


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


def format_event_output(drows: list[Any],
                        event_kind_detail: str,
                        rows: list[Any],
                        event_kind: str,
                        total_exec_time_sec: float,
                        traced_pid: str) -> dict[
    str, int | str | float | dict[str, list[str] | list[Any]]]:
    _TEMPLATE_HEADERS = ["Events", "% over time", "Total seconds", "Average", "Std.dev",
                         "Variance"]

    rows_headers = copy.deepcopy(_TEMPLATE_HEADERS)
    rows_headers.insert(0, event_kind)
    rows_headers_detail = copy.deepcopy(_TEMPLATE_HEADERS)
    rows_headers_detail.insert(0, event_kind_detail)
    return {
        "pid": int(traced_pid),
        "name": "posix",
        "total_exec_time": total_exec_time_sec,
        "global": {
            "headers": rows_headers,
            "data": rows,
        },
        "function": {
            "headers": rows_headers_detail,
            "data": drows,
        }
    }
