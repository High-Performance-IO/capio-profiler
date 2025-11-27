import os
import argparse
from tabulate import tabulate
from alive_progress import alive_bar

from .posix_profile import profile as posix_profile
from .server_profile import profile as server_profile
from .viewer import TraceViewer


def process_file(path: str):
    if "posix" in path.lower():
        print(f"Loaded POSIX: {path}")
        return posix_profile(path)
    else:
        print(f"Loaded SERVER: {path}")
        return server_profile(path)


def collect_trace_files_recursive(root_path: str):
    """Return a list of .log files found in root_path and all subdirectories."""
    log_files = []

    if os.path.isfile(root_path) and root_path.endswith(".log"):
        return [root_path]

    for dirpath, _, filenames in os.walk(root_path):
        for name in filenames:
            if name.endswith(".log"):
                log_files.append(os.path.join(dirpath, name))

    return log_files


def load_traces(file_list):
    """Load all trace files with a progress bar."""
    traces = []
    with alive_bar(len(file_list), title="Loading traces") as bar:
        for file_path in file_list:
            traces.append(process_file(file_path))
            bar()
    return traces


def main():
    parser = argparse.ArgumentParser(
        description="CAPIO Trace Profiler",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "path",
        help="Path to a CAPIO trace file or directory containing .log files (recursively scanned).",
    )

    parser.add_argument(
        "--no-interactive",
        action="store_true",
        help="Disable TUI viewer and print statistics only.",
    )

    args = parser.parse_args()

    trace_files = collect_trace_files_recursive(args.path)

    if not trace_files:
        print(f"No .log trace files found under: {args.path}")
        return

    traces = load_traces(trace_files)

    if args.no_interactive:
        for result in traces:
            print(f"-> Global execution time: {result['total_exec_time']} seconds")
            print(f"-> Traced pid: {result['pid']}")
            print(f"-> Traced name: {result['name']}")

            print("\n=== GLOBAL STATISTICS ===")
            print(
                tabulate(
                    result["global"]["data"],
                    headers=result["global"]["headers"],
                    tablefmt="outline",
                )
            )

            print("\n=== DETAILED INTERNAL FUNCTION STATS ===")
            print(
                tabulate(
                    result["function"]["data"],
                    headers=result["function"]["headers"],
                    tablefmt="outline",
                )
            )
    else:
        TraceViewer(traces).run()


if __name__ == "__main__":
    main()
