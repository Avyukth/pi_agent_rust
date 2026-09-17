#!/usr/bin/env python3
"""Fail when a loopback test fixture treats a socket read timeout as an error.

Provider tests stand up real loopback servers and read the request off the
socket. Eleven of those fixtures used to do one of two things when the read
timed out, and both are wrong (bd-eg6ng):

  FATAL        `stream.read(&mut chunk).expect(...)` — macOS reports a read
               timeout as EAGAIN/WouldBlock, not TimedOut, so `.expect` turned
               "the client has not been scheduled yet" into a failed test.

  TRUNCATING   `Err(WouldBlock | TimedOut) => break` — worse. The loop exits
               with a partial buffer and the header scan then fails as
               `.expect("request header boundary")`, so a SLOW request is
               misreported as a MALFORMED one and sends whoever debugs it
               after the wrong thing entirely.

Neither shows up on an idle machine: the client's request is already buffered
before the fixture's first read, so the timeout arm is never entered. They
surface only under contention, which is why they went unnoticed and why seven
tests were being lost from a full darwin run before anyone looked.

The fix is always the same shape — a short POLLING interval plus a wall
deadline for the whole exchange — and this gate exists because eleven fixtures
needed it one at a time and nothing stopped a twelfth being written the old
way. A unit test cannot cover that: it can prove the fixtures that exist, not
the ones someone adds tomorrow.

SCOPE, widened once: the first version scanned only `src/`, which missed the
integration suites entirely even though they stand up more loopback fixtures
than `src/` does. Adding `tests/` found five more real instances immediately —
three in tests/e2e_cli.rs, two in tests/provider_bedrock_streaming.rs — plus
both halves of the shared mock HTTP server in tests/common/harness.rs, which
backs most of the e2e suite and had a 2s read timeout whose expiry dropped the
connection without a response. On a loaded host that reads to the client as a
transient network error, so a slow machine silently became extra retries, extra
failovers and flaky exact-count assertions.

RETIREMENT: delete this when the fixtures share one helper that makes the bad
shape unexpressible. A gate that guards a copied idiom is a stand-in for the
abstraction, not a substitute for it.

Exit 0 = no fixture treats a read timeout as an error.
Exit 1 = at least one does, and is not allowlisted.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Sites that genuinely want a fatal read. Each entry must say WHY, because a
# reason is what separates a decision from an oversight.
#
# Do NOT add an entry to quiet the gate. If a fixture should be patient and is
# not, the fix is the poll-plus-deadline shape, not an exemption.
ALLOWLIST: dict[str, str] = {}

# `foo.read(&mut buf).expect(...)` / `.unwrap()` — a timeout becomes a panic.
FATAL_READ = re.compile(r"\.read\(\s*&mut\s+\w+\s*\)\s*\.\s*(?:expect\(|unwrap\(\))")

# A WouldBlock/TimedOut match arm whose body is just `break` — a timeout
# silently ends the request. Matched across the arm's few lines because rustfmt
# splits the guard over several.
TRUNCATING_READ = re.compile(
    r"ErrorKind::(?:WouldBlock|TimedOut)[^{]*\{\s*(?://[^\n]*\n\s*)*break\s*;",
    re.MULTILINE,
)

# `tests/` was outside this list when the gate shipped, which was a mistake: the
# integration suites stand up more loopback fixtures than `src/` does, and the
# shared one in tests/common/harness.rs backs most of the e2e suite. Adding it
# found seven more instances of the same two shapes on the first run.
SEARCH_ROOTS = (
    "src/providers",
    "src/agent_cx",
    "src/media_tools",
    "src/browser",
    "tests",
)

# `socket.set_read_timeout(Some(Duration::from_secs(5)))` and friends.
READ_TIMEOUT = re.compile(
    r"set_read_timeout\(\s*Some\(\s*(?:std::time::)?Duration::from_(secs|millis)\(\s*(\d+)"
)

# The invariant this gate actually enforces is not "never panic on a read"; it
# is THE PATIENCE BUDGET MUST BE LONG, however it is spent. A fixture that waits
# 30s on a single blocking read has the same budget as one that polls every
# 250ms against a 30s deadline — it just spends it differently, and flagging it
# would teach people to reach for the allowlist instead of the fix.
#
# So a fatal read is reported only where the socket's own timeout is SHORT
# enough that expiry means "not yet" rather than "never came".
#
# Out of scope by construction: a fixture that sets no read timeout at all. Its
# reads block forever, so a timeout cannot make them panic; the failure mode
# there is a hung suite, which is a different bead.
MIN_PATIENCE_SECS = 30.0


def offending_lines(text: str, pattern: re.Pattern[str]) -> list[int]:
    return [text.count("\n", 0, m.start()) + 1 for m in pattern.finditer(text)]


def shortest_read_timeout_secs(text: str) -> float | None:
    """The least patient read timeout the file sets, in seconds."""
    timeouts = [
        float(value) if unit == "secs" else float(value) / 1000.0
        for unit, value in READ_TIMEOUT.findall(text)
    ]
    return min(timeouts) if timeouts else None


def scan(repo: Path) -> list[tuple[str, int, str]]:
    findings: list[tuple[str, int, str]] = []
    for root in SEARCH_ROOTS:
        base = repo / root
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.rs")):
            rel = str(path.relative_to(repo))
            if rel in ALLOWLIST:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            timeout = shortest_read_timeout_secs(text)
            if timeout is not None and timeout < MIN_PATIENCE_SECS:
                for line in offending_lines(text, FATAL_READ):
                    findings.append(
                        (
                            rel,
                            line,
                            f"fatal: a read timeout panics, and this file's "
                            f"shortest read timeout is {timeout:g}s",
                        )
                    )
            # Truncation is wrong at any timeout: however long the fixture
            # waited, ending the request with a partial buffer reports a SLOW
            # client as a MALFORMED one.
            for line in offending_lines(text, TRUNCATING_READ):
                findings.append(
                    (rel, line, "truncating: a read timeout ends the request")
                )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="machine-readable report")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parent.parent
    findings = scan(repo)

    if args.json:
        print(
            json.dumps(
                {
                    "ok": not findings,
                    "findings": [
                        {"file": f, "line": ln, "kind": kind} for f, ln, kind in findings
                    ],
                    "allowlist": ALLOWLIST,
                },
                indent=2,
            )
        )
        return 1 if findings else 0

    if not findings:
        print("fixture read patience: no fixture treats a read timeout as an error")
        return 0

    print("FIXTURE READ PATIENCE CHECK FAILED", file=sys.stderr)
    for path, line, kind in findings:
        print(f"- {path}:{line} — {kind}", file=sys.stderr)
    print(
        "\nA read timeout means 'nothing yet', not 'fail'. Use a short polling\n"
        "interval plus a wall deadline for the whole exchange:\n"
        "\n"
        "    socket.set_read_timeout(Some(Duration::from_millis(250)))?;\n"
        "    let deadline = Instant::now() + Duration::from_secs(30);\n"
        "    ...\n"
        "    Err(e) if matches!(e.kind(), WouldBlock | TimedOut) => {\n"
        "        assert!(Instant::now() < deadline, \"fixture timed out waiting for X\");\n"
        "    }\n"
        "\n"
        "See src/providers/anthropic.rs and its regression test\n"
        "`a_fixture_waits_out_a_client_slower_than_the_old_read_timeout` (bd-n0hjg).",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
