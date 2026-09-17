"""Bounded AT-SPI inspection helper. Executed as fixed Python source with -I.

The input contains a host-resolved PID and exact top-level window title, not
code. No Text/Value interface is queried and password descendants are omitted.
The Rust parent owns the deadline and kills/reaps this process on cancellation.
"""

import json
import sys
import unicodedata

MAX_NODES = 512
MAX_DEPTH = 8
MAX_CHILDREN = 64
MAX_TREE_BYTES = 180 * 1024


class InspectionError(Exception):
    pass


def label(value, limit):
    cleaned = "".join(ch for ch in str(value or "")
                      if not unicodedata.category(ch).startswith("C"))
    return cleaned[:limit]


def find_window(desktop, pid, title):
    count = desktop.get_child_count()
    if not 0 <= count <= 512:
        raise InspectionError("desktop_registry_limit")
    matches = []
    for index in range(count):
        try:
            app = desktop.get_child_at_index(index)
            if app is None or app.get_process_id() != pid:
                continue
        except Exception:
            continue
        count = app.get_child_count()
        if not 0 <= count <= 256:
            raise InspectionError("application_window_limit")
        for child_index in range(count):
            try:
                window = app.get_child_at_index(child_index)
                if window is not None and window.get_name() == title:
                    matches.append(window)
            except Exception:
                # A failed candidate could hide another exact-title match.
                # Do not silently choose the only candidate we could read.
                raise InspectionError("target_unavailable") from None
    if len(matches) != 1:
        raise InspectionError("target_not_unique_or_not_exposed")
    return matches[0]


def snapshot(root, api):
    budget = {"nodes": 0, "bytes": MAX_TREE_BYTES,
              "truncated": False, "omitted_children": 0}

    def walk(node, depth):
        if budget["nodes"] >= MAX_NODES:
            budget["truncated"] = True
            budget["omitted_children"] += 1
            return None
        try:
            role = node.get_role()
            states = node.get_state_set()
            if states.contains(api.StateType.DEFUNCT):
                raise InspectionError("defunct_accessible")
            password = role == api.Role.PASSWORD_TEXT
            name = None if password else node.get_name()
            title = label(name, 256) or None
            raw_role = node.get_role_name()
            role_name = label(raw_role, 64)
            if len(str(name or "")) > 256 or len(str(raw_role or "")) > 64:
                budget["truncated"] = True
            if not role_name:
                raise InspectionError("missing_accessible_role")
            children = 0 if password else node.get_child_count()
            if children < 0:
                raise InspectionError("invalid_child_count")
            record = {"role": role_name, "title": title, "value": None,
                      "enabled": bool(states.contains(api.StateType.ENABLED)
                                      and states.contains(api.StateType.SENSITIVE)),
                      "focused": bool(states.contains(api.StateType.FOCUSED)),
                      "children": []}
        except Exception:
            if depth == 0:
                raise InspectionError("target_unavailable") from None
            budget["truncated"] = True
            budget["omitted_children"] += 1
            return None
        cost = len(json.dumps(record, ensure_ascii=True).encode("ascii")) + 2
        if cost > budget["bytes"]:
            budget["truncated"] = True
            budget["omitted_children"] += 1
            return None
        budget["bytes"] -= cost
        budget["nodes"] += 1
        visit_count = min(children, MAX_CHILDREN) if depth < MAX_DEPTH else 0
        if visit_count < children:
            budget["truncated"] = True
            budget["omitted_children"] += children - visit_count
        for index in range(visit_count):
            if budget["nodes"] >= MAX_NODES:
                budget["truncated"] = True
                budget["omitted_children"] += visit_count - index
                break
            try:
                child = node.get_child_at_index(index)
                if child is None:
                    raise InspectionError("missing_child")
            except Exception:
                budget["truncated"] = True
                budget["omitted_children"] += 1
                continue
            item = walk(child, depth + 1)
            if item is not None:
                record["children"].append(item)
        return record

    tree = walk(root, 0)
    if tree is None:
        raise InspectionError("target_unavailable")
    return {"root": tree, "node_count": budget["nodes"],
            "truncated": budget["truncated"],
            "omitted_children": budget["omitted_children"],
            "values_included": False}


def main():
    raw = sys.stdin.buffer.read(16385)
    if len(raw) > 16384:
        raise InspectionError("invalid_target")
    try:
        target = json.loads(raw)
        pid, title = target["pid"], target["title"]
        if type(pid) is not int or pid <= 0 or not isinstance(title, str) or not title:
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise InspectionError("invalid_target") from None
    try:
        import gi
        gi.require_version("Atspi", "2.0")
        from gi.repository import Atspi
    except (ImportError, ValueError):
        raise InspectionError("atspi_bindings_unavailable") from None
    try:
        if Atspi.init() not in (0, 1):
            raise InspectionError("accessibility_bus_unavailable")
        desktop = Atspi.get_desktop(0)
        if desktop is None:
            raise InspectionError("accessibility_bus_unavailable")
        root = find_window(desktop, pid, title)
        return snapshot(root, Atspi)
    finally:
        Atspi.exit()


if __name__ == "__main__":
    try:
        result = main()
    except InspectionError as failure:
        result = {"error": str(failure)}
    except Exception:
        # DBus exceptions can contain application-supplied text. Never echo
        # private titles, values, or arbitrary exception contents in errors.
        result = {"error": "accessibility_request_failed"}
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
