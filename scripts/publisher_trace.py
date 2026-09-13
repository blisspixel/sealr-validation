"""Conservatively analyze one bounded, merged strace of the publisher tree."""

import hashlib
import re


TRACE_LIMIT = 4 * 1024 * 1024
FILE_CALLS = {"open", "openat", "openat2", "unlink", "unlinkat"}
OPEN_CALLS = {"open", "openat", "openat2"}
QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')


def decode_path(token):
    value = token[1:-1]
    output = bytearray()
    index = 0
    escapes = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13,
               "\\": 92, '"': 34}
    while index < len(value):
        if value[index] != "\\":
            output.extend(value[index].encode("utf-8"))
            index += 1
            continue
        index += 1
        if index == len(value):
            raise RuntimeError("Incomplete trace pathname escape")
        if value[index] == "x":
            digits = value[index + 1:index + 3]
            if not re.fullmatch(r"[0-9a-fA-F]{2}", digits):
                raise RuntimeError("Invalid trace pathname hex escape")
            output.append(int(digits, 16))
            index += 3
        elif value[index] in "01234567":
            match = re.match(r"[0-7]{1,3}", value[index:])
            output.append(int(match[0], 8))
            index += len(match[0])
        elif value[index] in escapes:
            output.append(escapes[value[index]])
            index += 1
        else:
            raise RuntimeError("Unknown trace pathname escape")
    return output.decode("utf-8", errors="strict")


def analyze_trace(content, caller_source, expected_exit):
    if not content or len(content) > TRACE_LIMIT or not content.endswith(b"\n"):
        raise RuntimeError("Trace is absent, truncated, or exceeds its four MiB bound")
    pending = {}
    events = []
    pids = set()
    exits = {}
    spawned = set()
    root = None
    for index, line in enumerate(content.decode("utf-8", errors="strict").splitlines()):
        match = re.fullmatch(r"\s*(\d+)\s+(.*)", line)
        if not match:
            raise RuntimeError("Unrecognized or truncated PID-tagged trace record")
        pid, body = int(match[1]), match[2]
        pids.add(pid)
        if pid in exits:
            raise RuntimeError("Trace contains events after a process terminated")
        exited = re.fullmatch(r"\+\+\+ exited with (\d+) \+\+\+", body)
        if exited:
            exits[pid] = int(exited[1])
            continue
        if body.startswith("--- ") and body.endswith(" ---"):
            continue
        if body.startswith("+++ "):
            raise RuntimeError("Traced process did not exit normally")
        resumed = re.match(r"<\.\.\. (\w+) resumed>(.*)", body)
        if resumed:
            if pid not in pending or pending[pid][0] != resumed[1]:
                raise RuntimeError("Unmatched or inconsistent resumed trace syscall")
            call, start, prefix = pending.pop(pid)
            body = prefix + resumed[2]
        else:
            call_match = re.match(r"(\w+)\(", body)
            if not call_match or pid in pending:
                raise RuntimeError("Unrecognized or overlapping trace syscall")
            call, start = call_match[1], index
            if body.endswith("<unfinished ...>"):
                pending[pid] = (call, start, body.removesuffix("<unfinished ...>"))
                continue
        if not re.search(r"\)\s+=\s+", body):
            raise RuntimeError("Incomplete trace syscall result")
        if root is None:
            if call != "execve" or not re.search(r"\)\s+=\s+0$", body):
                raise RuntimeError("Trace must begin with successful publisher execution")
            root = pid
        if call in {"clone", "clone3", "fork", "vfork"}:
            result = re.search(r"\)\s+=\s+(-?\d+)", body)
            if not result:
                raise RuntimeError("Unparseable child creation result")
            if int(result[1]) > 0:
                spawned.add(int(result[1]))
        if call not in FILE_CALLS:
            continue
        strings = QUOTED.findall(body)
        null_path = re.match(r"(?:openat|openat2|unlinkat)\([^,]+,\s*NULL(?:,|\))", body) or re.match(r"(?:open|unlink)\(NULL(?:,|\))", body)
        if not strings and null_path and re.search(r"\)\s+=\s+-1\s+[A-Z]+\b", body):
            # The worker deliberately probes forbidden syscalls with a null
            # pathname. A failed null pointer has no pathname to reopen.
            continue
        if not strings or "..." in QUOTED.sub("", body):
            raise RuntimeError(f"Unparseable or abbreviated file syscall pathname at line {index + 1}: {body[:240]}")
        paths = [decode_path(token) for token in strings]
        annotations = re.findall(r"<([^<>]*)>", body)
        if any("\\" in path for path in annotations):
            raise RuntimeError("Escaped FD annotations require an explicit pathname interpretation")
        paths += [path.removesuffix(" (deleted)") for path in annotations]
        result = re.search(r"\)\s+=\s+(-?\d+)", body)
        if not result:
            raise RuntimeError("Unparseable file syscall result")
        events.append({"pid": pid, "call": call, "start": start, "end": index,
                       "path": paths[0], "paths": paths, "result": int(result[1])})
    if pending or root is None or set(exits) != pids or pids != {root, *spawned} or exits[root] != expected_exit:
        raise RuntimeError("Trace lacks complete syscall and process termination evidence")
    if any(status != 0 for pid, status in exits.items() if pid != root):
        raise RuntimeError("Traced child exited unsuccessfully")
    caller = str(caller_source)
    def canonical_absolute(path):
        return path.startswith("/") and all(part not in {"", ".", ".."} for part in path[1:].split("/"))
    if not canonical_absolute(caller):
        raise RuntimeError("Caller source trace identity must be a canonical absolute pathname")
    filename = caller.rsplit("/", 1)[-1]
    deletions = [event for event in events if event["pid"] == root
                 and event["call"] in {"unlink", "unlinkat"} and event["result"] == 0
                 and canonical_absolute(event["path"]) and event["path"] != caller
                 and event["path"].rsplit("/", 1)[-1] == filename]
    if len(deletions) != 1:
        raise RuntimeError("Expected exactly one successful private wheel deletion by the publisher")
    deletion = deletions[0]
    opens = [event for event in events if event["call"] in OPEN_CALLS]
    wheel_opens = [event for event in opens if any(
        component.lower().endswith(".whl") for path in event["paths"] for component in path.split("/")
    )]
    if any(event["end"] >= deletion["start"] for event in wheel_opens):
        raise RuntimeError("Wheel open attempt occurred after or overlapped private source deletion")
    for path in (caller, deletion["path"]):
        if not any(event["path"] == path and event["result"] >= 0 for event in opens):
            raise RuntimeError("Trace does not include both caller and private source acquisition")
    return {
        "schema": "sealr.publisher-source-open-trace.v1",
        "trace_bytes": len(content),
        "trace_sha256": hashlib.sha256(content).hexdigest(),
        "processes": len(pids),
        "publisher_pid": root,
        "private_source": deletion["path"],
        "private_source_unlink_line": deletion["start"] + 1,
        "wheel_opens_before_deletion": len(wheel_opens),
        "wheel_open_attempts_after_deletion": 0,
        "all_processes_terminated": True,
        "claim": "No observed wheel pathname or wheel FD-annotation open after private source deletion in this traced process tree.",
        "nonclaim": "No claim about unobserved processes or aliases absent from pathname and FD annotations; verified snapshot FD reads remain allowed.",
    }
