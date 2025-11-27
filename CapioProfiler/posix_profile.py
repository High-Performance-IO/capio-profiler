from .regex_extractors import *
from .utils import *


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

    process_single_event(lines, syscall_stats, detail_stats, syscall_name)



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
    traced_pid = path.split("_")[-1].split(".")[0]

    return format_event_output(
        process_statistics(syscall_stats),
        process_capio_inner_methods(detail_stats),
        "SYSCALL",
        total_exec_time_sec,
        traced_pid
    )
