import re

TIMESTAMP_RE = re.compile(r"at\[(\d+)\]")
HOOK_RE = re.compile(r"at\[\d+]\[(.*?)\]")

SERVER_REQUEST_RE = re.compile(r"^\s*at\[\d+]\[.*?\]:\s*\+{3,}\s*REQUEST\s*\+{3,}")
SERVER_END_REQUEST_RE = re.compile(r"^\s*at\[\d+]\[.*?\]:\s*~{3,}\s*END REQUEST\s*~{3,}")

SYSCALL_TAG_RE = re.compile(r"^\+.*?\s(\w+)$")  # + <timestamp> <syscall>




def extract_timestamp(line: str) -> int | None:
    m = TIMESTAMP_RE.search(line)
    return int(m.group(1)) if m else None

def extract_hook_name(line: str) -> str | None:
    m = HOOK_RE.search(line)
    return m.group(1) if m else None