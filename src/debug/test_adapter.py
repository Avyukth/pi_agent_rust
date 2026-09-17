"""Deterministic stdio DAP peer for Rust protocol tests, never a live adapter."""
import json
import sys
import threading

MODE = sys.argv[1] if len(sys.argv) > 1 else "normal"
LOCK = threading.Lock()
SEQUENCE = 0
REQUESTS = []
LAUNCH = None


def send(message):
    global SEQUENCE
    with LOCK:
        SEQUENCE += 1
        message["seq"] = SEQUENCE
        payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
        sys.stdout.buffer.write(b"Content-Length: %d\r\n\r\n" % len(payload) + payload)
        sys.stdout.buffer.flush()


def reply(request, body=None, error=None):
    send({"type": "response", "request_seq": request["seq"],
          "command": request["command"], "success": error is None,
          "body": body or {}, "message": error or ""})


def event(name, body=None):
    send({"type": "event", "event": name, "body": body or {}})


def read():
    length = None
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line == b"\r\n":
            break
        key, value = line.split(b":", 1)
        if key.lower() == b"content-length":
            length = int(value)
    if length is None or not 0 < length <= 2 * 1024 * 1024:
        raise ValueError("invalid DAP test frame")
    payload = sys.stdin.buffer.read(length)
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
                "supportsWriteMemoryRequest", "supportsModulesRequest", "supportsLoadedSourcesRequest"
            ]}
            caps["exceptionBreakpointFilters"] = [{"filter": "raised", "label": "Raised"}]
            if MODE == "no_configuration_done":
                caps.pop("supportsConfigurationDoneRequest")
            reply(request, caps)
        elif command in ("launch", "attach"):
            LAUNCH = request
            event("initialized")
            if MODE == "no_configuration_done":
                event("stopped", {"threadId": 7, "reason": "entry"})
                reply(request)
        elif command == "configurationDone":
            if MODE == "configuration_error":
                reply(request, error="configuration rejected by test adapter")
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
        elif command == "terminate":
            reply(request)
            event("terminated")
            return
        else:
            reply(request, error="unexpected test command: " + command)


if __name__ == "__main__":
    main()
