#!/usr/bin/env bash
# fuzz_crash_manage.sh — Crash corpus management for cargo-fuzz.
#
# Provides subcommands for the crash lifecycle:
#   triage   — List and categorize unprocessed crash artifacts
#   minimize — Minimize a crash input via cargo fuzz tmin
#   store    — Move a processed crash to fuzz/crashes/<target>/
#   regress  — Move a fixed crash to fuzz/regression/<target>/
#   report   — Emit a JSON summary of all stored crashes
#
# Usage:
#   ./scripts/fuzz_crash_manage.sh triage [--target=<name>]
#   ./scripts/fuzz_crash_manage.sh minimize <target> <artifact-path>
#   ./scripts/fuzz_crash_manage.sh store <target> <artifact-path> --category=<cat> [--description=<desc>]
#   ./scripts/fuzz_crash_manage.sh regress <target> <crash-name> [--bead=<id>]
#   ./scripts/fuzz_crash_manage.sh report [--format=json|text]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FUZZ_DIR="$REPO_ROOT/fuzz"
ARTIFACTS_DIR="$FUZZ_DIR/artifacts"
CRASHES_DIR="$FUZZ_DIR/crashes"
REGRESSION_DIR="$FUZZ_DIR/regression"

# Crash categories
VALID_CATEGORIES="oom,stack-overflow,panic-unwrap,panic-index,panic-assertion,timeout,logic-error,unknown"

die() { echo "ERROR: $*" >&2; exit 1; }

usage() {
    cat <<'USAGE'
fuzz_crash_manage.sh — Crash corpus management

Subcommands:
  triage   [--target=NAME]          List unprocessed crash artifacts
  minimize TARGET ARTIFACT_PATH     Minimize a crash via cargo fuzz tmin
  store    TARGET ARTIFACT --category=CAT [--description=DESC]
                                    Move crash to fuzz/crashes/TARGET/
  regress  TARGET CRASH_NAME [--bead=ID]
                                    Move fixed crash to fuzz/regression/TARGET/
  report   [--format=json|text]     Summarize all stored crashes

Categories: oom, stack-overflow, panic-unwrap, panic-index, panic-assertion,
            timeout, logic-error, unknown
USAGE
    exit 1
}

# ── triage ──────────────────────────────────────────────────────────────────

cmd_triage() {
    local target_filter=""
    for arg in "$@"; do
        case "$arg" in
            --target=*) target_filter="${arg#--target=}" ;;
            *) die "Unknown option: $arg" ;;
        esac
    done

    echo "=== Crash Artifact Triage ==="
    echo ""

    local total=0
    local found=0

    for target_dir in "$ARTIFACTS_DIR"/*/; do
        [ -d "$target_dir" ] || continue
        local target
        target="$(basename "$target_dir")"

        if [ -n "$target_filter" ] && [ "$target" != "$target_filter" ]; then
            continue
        fi

        local crashes=()
        while IFS= read -r -d '' f; do
            crashes+=("$f")
        done < <(find "$target_dir" -maxdepth 1 -type f \( -name 'crash-*' -o -name 'oom-*' -o -name 'timeout-*' -o -name 'slow-unit-*' \) -print0 2>/dev/null)

        if [ ${#crashes[@]} -eq 0 ]; then
            continue
        fi

        found=1
        echo "Target: $target (${#crashes[@]} crash artifact(s))"
        for crash in "${crashes[@]}"; do
            local name size
            name="$(basename "$crash")"
            size="$(stat -c%s "$crash" 2>/dev/null || stat -f%z "$crash" 2>/dev/null || echo "?")"
            echo "  - $name (${size} bytes)"
            total=$((total + 1))
        done
        echo ""
    done

    if [ "$found" -eq 0 ]; then
        echo "No unprocessed crash artifacts found."
    else
        echo "Total: $total crash artifact(s) pending triage."
    fi
}

# ── minimize ────────────────────────────────────────────────────────────────

cmd_minimize() {
    [ $# -ge 2 ] || die "Usage: minimize TARGET ARTIFACT_PATH"
    local target="$1"
    local artifact="$2"

    [ -f "$artifact" ] || die "Artifact not found: $artifact"

    echo "Minimizing crash for target '$target': $artifact"

    local min_output
    min_output="${artifact}.minimized"

    # Determine runner prefix
    local runner=""
    if command -v rch &>/dev/null; then
        runner="rch exec --"
    fi

    $runner cargo fuzz tmin "$target" "$artifact" -- 2>&1 | tee /dev/stderr

    if [ -f "$min_output" ]; then
        local orig_size min_size
        orig_size="$(stat -c%s "$artifact" 2>/dev/null || stat -f%z "$artifact")"
        min_size="$(stat -c%s "$min_output" 2>/dev/null || stat -f%z "$min_output")"
        echo ""
        echo "Minimized: $orig_size -> $min_size bytes ($(( (orig_size - min_size) * 100 / orig_size ))% reduction)"
        echo "Output: $min_output"
    else
        echo ""
        echo "Note: cargo fuzz tmin may have modified the input in-place."
        echo "Check the artifact at: $artifact"
    fi
}

# ── store ───────────────────────────────────────────────────────────────────

cmd_store() {
    local target="" artifact="" category="" description=""

    [ $# -ge 2 ] || die "Usage: store TARGET ARTIFACT --category=CAT [--description=DESC]"
    target="$1"; shift
    artifact="$1"; shift

    for arg in "$@"; do
        case "$arg" in
            --category=*) category="${arg#--category=}" ;;
            --description=*) description="${arg#--description=}" ;;
            *) die "Unknown option: $arg" ;;
        esac
    done

    [ -n "$category" ] || die "Required: --category=<$VALID_CATEGORIES>"
    echo "$VALID_CATEGORIES" | tr ',' '\n' | grep -qx "$category" || die "Invalid category '$category'. Valid: $VALID_CATEGORIES"
    [ -f "$artifact" ] || die "Artifact not found: $artifact"

    local dest_dir="$CRASHES_DIR/$target"
    mkdir -p "$dest_dir"

    # Generate sequential name: <category>-NNN.bin
    local seq=1
    while [ -f "$dest_dir/${category}-$(printf '%03d' $seq).bin" ]; do
        seq=$((seq + 1))
    done
    local dest_name="${category}-$(printf '%03d' $seq).bin"
    local dest_path="$dest_dir/$dest_name"

    cp "$artifact" "$dest_path"

    # Write metadata sidecar
    local meta_path="${dest_path%.bin}.json"
    cat > "$meta_path" <<EOF
{
  "schema": "pi.fuzz.crash_metadata.v1",
  "target": "$target",
  "category": "$category",
  "original_artifact": "$(basename "$artifact")",
  "stored_as": "$dest_name",
  "description": "$description",
  "stored_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "size_bytes": $(stat -c%s "$dest_path" 2>/dev/null || stat -f%z "$dest_path"),
  "status": "open"
}
EOF

    echo "Stored: $dest_path"
    echo "Metadata: $meta_path"
    echo "Category: $category"
    [ -n "$description" ] && echo "Description: $description"
}

# ── regress ─────────────────────────────────────────────────────────────────

cmd_regress() {
    local target="" crash_name="" bead=""

    [ $# -ge 2 ] || die "Usage: regress TARGET CRASH_NAME [--bead=ID]"
    target="$1"; shift
    crash_name="$1"; shift

    for arg in "$@"; do
        case "$arg" in
            --bead=*) bead="${arg#--bead=}" ;;
            *) die "Unknown option: $arg" ;;
        esac
    done

    local src="$CRASHES_DIR/$target/$crash_name"
    [ -f "$src" ] || die "Crash file not found: $src"

    local dest_dir="$REGRESSION_DIR/$target"
    mkdir -p "$dest_dir"

    local dest="$dest_dir/$crash_name"
    mv "$src" "$dest"

    # Update metadata if present
    local meta_src="${src%.bin}.json"
    if [ -f "$meta_src" ]; then
        local meta_dest="${dest%.bin}.json"
        # Update status to resolved
        python3 -c "
import json, sys
from datetime import datetime, timezone
with open('$meta_src') as f:
    m = json.load(f)
m['status'] = 'resolved'
m['resolved_at'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
m['bead'] = '${bead}'
with open('$meta_dest', 'w') as f:
    json.dump(m, f, indent=2)
    f.write('\n')
" 2>/dev/null || mv "$meta_src" "${dest%.bin}.json"
        rm -f "$meta_src"
    fi

    echo "Moved to regression: $dest"
    [ -n "$bead" ] && echo "Linked bead: $bead"
}

# ── report ──────────────────────────────────────────────────────────────────

cmd_report() {
    local format="text"
    for arg in "$@"; do
        case "$arg" in
            --format=*) format="${arg#--format=}" ;;
            *) die "Unknown option: $arg" ;;
        esac
    done

    if [ "$format" = "json" ]; then
        python3 - "$CRASHES_DIR" "$REGRESSION_DIR" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

crashes_dir = Path(sys.argv[1])
regression_dir = Path(sys.argv[2])

def scan_dir(base_dir, status_default):
    entries = []
    if not base_dir.exists():
        return entries
    for target_dir in sorted(base_dir.iterdir()):
        if not target_dir.is_dir():
            continue
        target = target_dir.name
        for f in sorted(target_dir.glob("*.bin")):
            meta_path = f.with_suffix(".json")
            meta = {}
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text())
                except Exception:
                    pass
            entries.append({
                "target": target,
                "file": f.name,
                "category": meta.get("category", "unknown"),
                "status": meta.get("status", status_default),
                "description": meta.get("description", ""),
                "size_bytes": f.stat().st_size,
                "stored_at": meta.get("stored_at", ""),
                "resolved_at": meta.get("resolved_at", ""),
                "bead": meta.get("bead", ""),
            })
    return entries

open_crashes = scan_dir(crashes_dir, "open")
resolved = scan_dir(regression_dir, "resolved")

report = {
    "schema": "pi.fuzz.crash_report.v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "summary": {
        "open_count": len(open_crashes),
        "resolved_count": len(resolved),
        "total_count": len(open_crashes) + len(resolved),
        "categories": {},
    },
    "open": open_crashes,
    "resolved": resolved,
}

for entry in open_crashes + resolved:
    cat = entry["category"]
    report["summary"]["categories"][cat] = report["summary"]["categories"].get(cat, 0) + 1

print(json.dumps(report, indent=2))
PY
    else
        echo "=== Crash Corpus Report ==="
        echo ""

        local open_count=0 resolved_count=0

        if [ -d "$CRASHES_DIR" ]; then
            for target_dir in "$CRASHES_DIR"/*/; do
                [ -d "$target_dir" ] || continue
                local target
                target="$(basename "$target_dir")"
                local count
                count=$(find "$target_dir" -maxdepth 1 -name '*.bin' 2>/dev/null | wc -l)
                if [ "$count" -gt 0 ]; then
                    echo "Open crashes ($target): $count"
                    open_count=$((open_count + count))
                fi
            done
        fi

        if [ -d "$REGRESSION_DIR" ]; then
            for target_dir in "$REGRESSION_DIR"/*/; do
                [ -d "$target_dir" ] || continue
                local target
                target="$(basename "$target_dir")"
                local count
                count=$(find "$target_dir" -maxdepth 1 -name '*.bin' 2>/dev/null | wc -l)
                if [ "$count" -gt 0 ]; then
                    echo "Regression tests ($target): $count"
                    resolved_count=$((resolved_count + count))
                fi
            done
        fi

        echo ""
        echo "Total: $open_count open, $resolved_count resolved"
    fi
}

# ── main ────────────────────────────────────────────────────────────────────

[ $# -ge 1 ] || usage

cmd="$1"; shift
case "$cmd" in
    triage)   cmd_triage "$@" ;;
    minimize) cmd_minimize "$@" ;;
    store)    cmd_store "$@" ;;
    regress)  cmd_regress "$@" ;;
    report)   cmd_report "$@" ;;
    help|-h|--help) usage ;;
    *) die "Unknown subcommand: $cmd. Use 'help' for usage." ;;
esac
