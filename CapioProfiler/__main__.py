from .profile import *


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m CapioProfiler <trace-file>")
        sys.exit(1)

    profile(sys.argv[1])
