"""Deterministic stdio/TCP DAP peer for Rust tests, never a live debugger."""
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time

TCP = len(sys.argv) > 1 and sys.argv[1] == "tcp"
MODE_INDEX = 2 if TCP else 1
MODE = sys.argv[MODE_INDEX] if len(sys.argv) > MODE_INDEX else "normal"
LOCK = threading.Lock()
SEQUENCE = 0
REQUESTS = []
LAUNCH = None
INPUT = sys.stdin.buffer
OUTPUT = sys.stdout.buffer


def send(message):
    global SEQUENCE
    with LOCK:
        SEQUENCE += 1
        message["seq"] = SEQUENCE
        payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
        OUTPUT.write(b"Content-Length: %d\r\n\r\n" % len(payload) + payload)
        OUTPUT.flush()


def reply(request, body=None, error=None):
    send({"type": "response", "request_seq": request["seq"],
          "command": request["command"], "success": error is None,
          "body": body or {}, "message": error or ""})


def event(name, body=None):
    send({"type": "event", "event": name, "body": body or {}})


def read():
    length = None
    header_bytes = 0
    while True:
        line = INPUT.readline(4097)
        header_bytes += len(line)
        if header_bytes > 16384 or len(line) > 4096:
            raise ValueError("oversized DAP test header")
        if not line:
            return None
        if line == b"\r\n":
            break
        key, value = line.split(b":", 1)
        if key.lower() == b"content-length":
            length = int(value)
    if length is None or not 0 < length <= 2 * 1024 * 1024:
        raise ValueError("invalid DAP test frame")
    payload = INPUT.read(length)
    if len(payload) != length:
        raise ValueError("incomplete DAP test frame")
    return json.loads(payload)


def main():
    global LAUNCH
    while True:
        request = read()
        if request is None:
            return
        command = request["command"]
        args = request.get("arguments", {})
        REQUESTS.append({"command": command, "arguments": args})
        if command == "initialize":
            caps = {name: True for name in [
                "supportsConfigurationDoneRequest", "supportsFunctionBreakpoints",
                "supportsInstructionBreakpoints", "supportsDataBreakpoints",
                "supportsConditionalBreakpoints", "supportsHitConditionalBreakpoints",
                "supportsLogPoints", "supportsDisassembleRequest", "supportsReadMemoryRequest",
                "supportsWriteMemoryRequest", "supportsModulesRequest", "supportsLoadedSourcesRequest",
                "supportTerminateDebuggee"
            ]}
            caps["exceptionBreakpointFilters"] = [{"filter": "raised", "label": "Raised"}]
            if MODE == "no_configuration_done":
                caps.pop("supportsConfigurationDoneRequest")
            if MODE == "no_terminate_attached":
                caps.pop("supportTerminateDebuggee")
            reply(request, caps)
        elif command in ("launch", "attach"):
            LAUNCH = request
            if MODE == "slow_build":
                time.sleep(0.2)
            event("initialized")
            if MODE == "no_configuration_done":
                event("stopped", {"threadId": 7, "reason": "entry"})
                reply(request)
        elif command == "configurationDone":
            if MODE == "configuration_error":
                reply(request, error="configuration rejected by test adapter")
                continue
            if MODE == "configuration_stall":
                continue
            event("stopped", {"threadId": 7, "reason": "entry"})
            reply(request)
            reply(LAUNCH)
        elif command in ("setBreakpoints", "setFunctionBreakpoints", "setInstructionBreakpoints", "setDataBreakpoints"):
            entries = args["breakpoints"]
            if any(entry.get("line") == 13 for entry in entries):
                reply(request, error="test breakpoint rejection")
                continue
            actual = [dict(entry, id=index + 1, verified=entry.get("line") != 777)
                      for index, entry in enumerate(entries)]
            if any(entry.get("line") == 99 for entry in entries):
                actual = []
            reply(request, {"breakpoints": actual})
        elif command == "setExceptionBreakpoints":
            reply(request)
        elif command in ("next", "stepIn", "stepOut"):
            if MODE == "stop_before_reply":
                event("stopped", {"threadId": 8, "reason": "step"})
                reply(request)
            else:
                reply(request)
                timer = threading.Timer(0.05, event, ("stopped", {"threadId": 8, "reason": "step"}))
                timer.daemon = True
                timer.start()
        elif command == "continue":
            reply(request, {"allThreadsContinued": True})
        elif command == "pause":
            event("stopped", {"threadId": args["threadId"], "reason": "pause"})
            reply(request)
        elif command == "threads":
            reply(request, {"threads": [{"id": 7, "name": "main"}, {"id": 8, "name": "worker"}]})
        elif command == "stackTrace":
            reply(request, {"stackFrames": [{"id": 21, "name": "main", "line": 10, "column": 1}], "totalFrames": 1})
        elif command == "scopes":
            reply(request, {"scopes": [{"name": "Locals", "variablesReference": 41, "expensive": False}]})
        elif command == "dataBreakpointInfo":
            reply(request, {"dataId": "opaque-watch-id", "description": args["name"], "accessTypes": ["read", "write", "readWrite"]})
        elif command == "evaluate":
            reply(request, {"result": "object", "type": "Object", "variablesReference": 66, "namedVariables": 2, "memoryReference": "0x100"})
        elif command == "variables":
            reply(request, {"variables": [{"name": "answer", "value": "42", "variablesReference": 0}]})
        elif command == "capture":
            reply(request, {"requests": REQUESTS})
        elif command == "flood":
            for _ in range(700):
                event("output", {"category": "stdout", "output": "progress\n"})
            event("stopped", {"threadId": 9, "reason": "breakpoint"})
            reply(request)
        elif command == "disconnect":
            if MODE == "disconnect_error":
                reply(request, error="disconnect rejected by test adapter")
                continue
            Path("disconnect.json").write_text(json.dumps(args), encoding="utf-8")
            reply(request)
            event("terminated")
            return
        elif command == "terminate":
            reply(request)
            event("terminated")
            return
        else:
            reply(request, error="unexpected test command: " + command)


def tcp_main():
    global INPUT, OUTPUT
    assert "--listen=127.0.0.1:0" in sys.argv
    assert "--only-same-user=true" in sys.argv
    Path("adapter.pid").write_text(str(os.getpid()), encoding="ascii")
    if MODE == "never_ready":
        time.sleep(30)
        return
    if MODE == "bad_endpoint":
        print("DAP server listening at: 192.0.2.1:9", flush=True)
        time.sleep(30)
        return
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(10)
        sys.stdout.write("DAP server listen")
        sys.stdout.flush()
        time.sleep(0.01)
        print("ing at: 127.0.0.1:%d" % listener.getsockname()[1], flush=True)
        with listener.accept()[0] as connection:
            connection.settimeout(30)
            print("debuggee stdout is not a DAP frame", flush=True)
            with connection.makefile("rwb") as stream:
                INPUT = OUTPUT = stream
                main()


if __name__ == "__main__":
    tcp_main() if TCP else main()
