from .regex_extractors import *
from .utils import *


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

    process_single_event(lines, request_stats, detail_stats, request_name)


def profile(
        path: str
) -> dict[str, int | str | float | dict[str, list[str] | list[Any]]]:
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
    traced_pid = path.split("_")[-1].split(".")[0]

    return format_event_output(
        process_statistics(request_stats),
        process_capio_inner_methods(detail_stats),
        "REQUEST",
        total_exec_time_sec,
        traced_pid
    )
