#!/usr/bin/env bash
#
# pi_agent_rust installer
#
# One-liner install:
#   curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/pi_agent_rust/main/install.sh?$(date +%s)" | bash
#
# Highlights:
# - Installs latest (or requested) GitHub release binary for your platform
# - Verifies artifact checksum via SHA256SUMS
# - Detects existing TypeScript pi and can migrate to Rust canonical `pi`
# - Creates `legacy-pi` alias for the preserved TypeScript CLI when migrated
# - Writes installer state for idempotent re-runs and clean uninstall

set -euo pipefail
umask 022
shopt -s lastpipe 2>/dev/null || true

OWNER="${OWNER:-Dicklesworthstone}"
REPO="${REPO:-pi_agent_rust}"
VERSION="${VERSION:-}"

DEST_DEFAULT="$HOME/.local/bin"
DEST="$DEST_DEFAULT"
DEST_EXPLICIT=0
SYSTEM=0

EASY=0
YES=0
QUIET=0
NO_GUM=0
FROM_SOURCE=0
VERIFY=0
NO_VERIFY=0
FORCE_INSTALL=0
OFFLINE="${PI_INSTALLER_OFFLINE:-0}"

CHECKSUM="${CHECKSUM:-}"
CHECKSUM_URL="${CHECKSUM_URL:-}"
ARTIFACT_URL="${ARTIFACT_URL:-}"
SIGSTORE_BUNDLE_URL="${SIGSTORE_BUNDLE_URL:-}"
COSIGN_IDENTITY_RE="${COSIGN_IDENTITY_RE:-^https://github.com/${OWNER}/${REPO}/.github/workflows/release.yml@refs/tags/.*$}"
COSIGN_OIDC_ISSUER="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
COMPLETIONS_MODE="${COMPLETIONS_MODE:-auto}"

# ask|yes|no
ADOPT_MODE="ask"
LEGACY_ALIAS_NAME="${LEGACY_ALIAS_NAME:-legacy-pi}"

OS=""
ARCH=""
TARGET=""
EXE_EXT=""
ASSET_PLATFORM=""
ASSET_NAME=""
SHA_URL=""

CURRENT_PI_PATH=""
CURRENT_PI_VERSION=""
TS_PI_DETECTED=0
ADOPT_TS=0
ADOPT_CANONICAL=0

FINAL_BIN_NAME="pi"
INSTALL_BIN_PATH=""

LEGACY_ALIAS_PATH=""
LEGACY_TARGET_PATH=""
LEGACY_MOVED_FROM=""
LEGACY_MOVED_TO=""

PATH_MARKER="# pi-agent-rust installer PATH"
PATH_UPDATED_FILES=""

STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/pi-agent-rust"
STATE_FILE="$STATE_DIR/install-state.env"
STATE_VERSION="1"

TMP=""
LOCK_DIR="/tmp/pi-agent-rust-install.lock.d"
LOCKED=0
MIGRATION_MOVED=0
INSTALL_COMMITTED=0
INSTALL_SOURCE="release"
CHECKSUM_STATUS="pending"
SIGSTORE_STATUS="pending"
COMPLETIONS_STATUS="pending"

HAS_GUM=0
if command -v gum >/dev/null 2>&1 && [ -t 1 ]; then
  HAS_GUM=1
fi

log() {
  [ "$QUIET" -eq 1 ] && return 0
  echo -e "$*" >&2
}

info() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 39 "→ $*" >&2
  else
    echo -e "\033[0;34m→\033[0m $*" >&2
  fi
}

ok() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 42 "✓ $*" >&2
  else
    echo -e "\033[0;32m✓\033[0m $*" >&2
  fi
}

warn() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 214 "⚠ $*" >&2
  else
    echo -e "\033[1;33m⚠\033[0m $*" >&2
  fi
}

err() {
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 196 "✗ $*" >&2
  else
    echo -e "\033[0;31m✗\033[0m $*" >&2
  fi
}

run_with_spinner() {
  local title="$1"
  shift
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ] && [ "$QUIET" -eq 0 ]; then
    gum spin --spinner dot --title "$title" -- "$@"
  else
    # Keep status text off stdout so callers can safely capture command output.
    info "$title" >&2
    "$@"
  fi
}

pi_ascii_logo() {
  cat <<'ASCII'
 ____  _   ____            _
|  _ \(_) |  _ \ _   _ ___| |_
| |_) | | | |_) | | | / __| __|
|  __/| | |  _ <| |_| \__ \ |_
|_|   |_| |_| \_\\__,_|___/\__|
ASCII
}

usage() {
  cat <<'USAGE'
Usage: install.sh [options]

Options:
  --version vX.Y.Z       Install a specific release tag
  --dest DIR             Install directory (default: ~/.local/bin)
  --system               Install to /usr/local/bin
  --easy-mode            Add install dir to PATH in shell rc files
  --artifact-url URL     Install from explicit release artifact URL
  --checksum HEX         Expected SHA256 for explicit artifact
  --checksum-url URL     URL to checksum file or manifest
  --sigstore-bundle-url URL
                          URL to Sigstore bundle (.sigstore.json)
  --from-source          Build from source instead of downloading release binary
  --verify               Run `pi --version` after install
  --no-verify            Skip checksum + signature verification
  --offline              Skip network preflight check
  --completions SHELL    Install shell completions for auto|bash|zsh|fish
  --no-completions       Skip shell completion installation
  --yes, -y              Non-interactive yes to prompts
  --adopt                Auto-adopt Rust as canonical `pi` when TS pi is detected
  --keep-existing-pi     Do not replace existing `pi`; install as `pi-rust`
  --legacy-alias NAME    Alias name for migrated TypeScript pi (default: legacy-pi)
  --force                Reinstall even if same version is already installed
  --quiet, -q            Suppress non-error output
  --no-gum               Disable gum formatting
  -h, --help             Show this help
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      VERSION="$2"
      shift 2
      ;;
    --dest)
      DEST="$2"
      DEST_EXPLICIT=1
      shift 2
      ;;
    --system)
      SYSTEM=1
      DEST="/usr/local/bin"
      DEST_EXPLICIT=1
      shift
      ;;
    --easy-mode)
      EASY=1
      shift
      ;;
    --artifact-url)
      ARTIFACT_URL="$2"
      shift 2
      ;;
    --checksum)
      CHECKSUM="$2"
      shift 2
      ;;
    --checksum-url)
      CHECKSUM_URL="$2"
      shift 2
      ;;
    --sigstore-bundle-url)
      SIGSTORE_BUNDLE_URL="$2"
      shift 2
      ;;
    --from-source)
      FROM_SOURCE=1
      shift
      ;;
    --verify)
      VERIFY=1
      shift
      ;;
    --no-verify)
      NO_VERIFY=1
      shift
      ;;
    --offline)
      OFFLINE=1
      shift
      ;;
    --completions)
      COMPLETIONS_MODE="$2"
      shift 2
      ;;
    --no-completions)
      COMPLETIONS_MODE="off"
      shift
      ;;
    --yes|-y)
      YES=1
      shift
      ;;
    --adopt)
      ADOPT_MODE="yes"
      shift
      ;;
    --keep-existing-pi)
      ADOPT_MODE="no"
      shift
      ;;
    --legacy-alias)
      LEGACY_ALIAS_NAME="$2"
      shift 2
      ;;
    --force)
      FORCE_INSTALL=1
      shift
      ;;
    --quiet|-q)
      QUIET=1
      shift
      ;;
    --no-gum)
      NO_GUM=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      err "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

show_header() {
  [ "$QUIET" -eq 1 ] && return 0
  local logo
  logo="$(pi_ascii_logo)"

  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style \
      --border double \
      --border-foreground 51 \
      --padding "1 2" \
      --margin "1 0" \
      "$(gum style --foreground 51 --bold "$logo")" \
      "$(gum style --foreground 42 --bold 'Pi Rust Installer')" \
      "$(gum style --foreground 245 'High-performance coding agent CLI')" \
      "$(gum style --foreground 244 'Install + verify + TypeScript migration helper')"
  else
    echo ""
    printf '\033[1;36m%s\033[0m\n' "$logo"
    echo -e "\033[1;32mPi Rust Installer\033[0m"
    echo -e "\033[0;37mHigh-performance coding agent CLI\033[0m"
    echo -e "\033[0;90mInstall + verify + TypeScript migration helper\033[0m"
    echo ""
  fi
}

prompt_confirm() {
  local prompt="$1"
  local default_yes="${2:-0}"

  if [ "$YES" -eq 1 ]; then
    return 0
  fi

  if [ ! -t 0 ]; then
    if [ "$default_yes" -eq 1 ]; then
      return 0
    fi
    return 1
  fi

  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum confirm "$prompt"
    return $?
  fi

  local suffix="[y/N]"
  if [ "$default_yes" -eq 1 ]; then
    suffix="[Y/n]"
  fi

  printf "%s %s " "$prompt" "$suffix"
  local ans
  read -r ans || true
  if [ -z "$ans" ]; then
    if [ "$default_yes" -eq 1 ]; then
      return 0
    fi
    return 1
  fi
  case "$ans" in
    y|Y|yes|YES|Yes)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

normalize_version() {
  if [ -z "$VERSION" ]; then
    return 0
  fi
  if [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.].+)?$ ]]; then
    VERSION="v$VERSION"
  fi
}

resolve_version() {
  normalize_version
  if [ -n "$VERSION" ]; then
    return 0
  fi

  if [ -n "$ARTIFACT_URL" ] && [ "$FROM_SOURCE" -eq 0 ]; then
    VERSION="custom-artifact"
    info "Using custom artifact URL; skipping release tag resolution"
    return 0
  fi

  info "Resolving latest release tag"
  local latest_url="https://api.github.com/repos/${OWNER}/${REPO}/releases/latest"
  local tag=""
  if command -v curl >/dev/null 2>&1; then
    tag=$(curl -fsSL -H "Accept: application/vnd.github+json" "$latest_url" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)
    if [ -z "$tag" ]; then
      local redirect_target=""
      redirect_target=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${OWNER}/${REPO}/releases/latest" 2>/dev/null || true)
      if [[ "$redirect_target" =~ /tag/([^/?#]+) ]]; then
        tag="${BASH_REMATCH[1]}"
      fi
    fi
  fi

  if [ -z "$tag" ]; then
    err "Failed to resolve latest release tag"
    err "Pass --version vX.Y.Z or check network connectivity"
    exit 1
  fi

  VERSION="$tag"
  ok "Resolved ${VERSION}"
}

detect_platform() {
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  ARCH=$(uname -m)

  case "$ARCH" in
    x86_64|amd64)
      ARCH="x86_64"
      ;;
    arm64|aarch64)
      ARCH="aarch64"
      ;;
  esac

  TARGET=""
  EXE_EXT=""

  case "${OS}-${ARCH}" in
    linux-x86_64)
      TARGET="x86_64-unknown-linux-gnu"
      ASSET_PLATFORM="linux-amd64"
      ;;
    linux-aarch64)
      TARGET="aarch64-unknown-linux-gnu"
      ASSET_PLATFORM="linux-arm64"
      ;;
    darwin-x86_64)
      TARGET="x86_64-apple-darwin"
      ASSET_PLATFORM="darwin-amd64"
      ;;
    darwin-aarch64)
      TARGET="aarch64-apple-darwin"
      ASSET_PLATFORM="darwin-arm64"
      ;;
    msys_nt*-x86_64|mingw*-x86_64|cygwin_nt*-x86_64)
      TARGET="x86_64-pc-windows-msvc"
      ASSET_PLATFORM="windows-amd64"
      EXE_EXT=".exe"
      ;;
    *)
      ;;
  esac

  if [ -z "$TARGET" ] && [ "$FROM_SOURCE" -eq 0 ]; then
    warn "No prebuilt binary published for ${OS}/${ARCH}; switching to --from-source"
    FROM_SOURCE=1
  fi
}

prepare_asset_urls() {
  if [ "$FROM_SOURCE" -eq 1 ]; then
    return 0
  fi

  if [ -n "$ARTIFACT_URL" ]; then
    local cleaned="${ARTIFACT_URL%%\?*}"
    cleaned="${cleaned%%#*}"
    ASSET_NAME="$(basename "$cleaned")"
    if [ -z "$ASSET_NAME" ] || [ "$ASSET_NAME" = "/" ] || [ "$ASSET_NAME" = "." ]; then
      err "Could not infer artifact name from --artifact-url: $ARTIFACT_URL"
      exit 1
    fi
  else
    ASSET_NAME="pi-${VERSION}-${TARGET}${EXE_EXT}"
  fi

  SHA_URL="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/SHA256SUMS"
}

ensure_dest_dir() {
  mkdir -p "$DEST" 2>/dev/null || true
  if [ ! -d "$DEST" ]; then
    err "Install directory does not exist and could not be created: $DEST"
    exit 1
  fi
  if [ ! -w "$DEST" ]; then
    err "No write permission for install directory: $DEST"
    if [ "$SYSTEM" -eq 1 ]; then
      err "Re-run with sudo for --system installs"
    else
      err "Choose a writable directory with --dest"
    fi
    exit 1
  fi
}

check_disk_space() {
  local min_kb=20480
  local path="$DEST"
  if [ ! -d "$path" ]; then
    path=$(dirname "$path")
  fi

  if command -v df >/dev/null 2>&1; then
    local avail_kb
    avail_kb=$(df -Pk "$path" 2>/dev/null | awk 'NR==2 {print $4}')
    if [ -n "$avail_kb" ] && [ "$avail_kb" -lt "$min_kb" ]; then
      err "Insufficient disk space in $path (need at least 20MB free)"
      exit 1
    fi
  else
    warn "df not found; skipping disk space preflight check"
  fi
}

check_existing_install() {
  local existing="$DEST/pi"
  if [ -x "$existing" ]; then
    local current
    current=$("$existing" --version 2>/dev/null | head -1 || true)
    if [ -n "$current" ]; then
      info "Existing pi detected at $existing: $current"
    fi
  fi
}

check_network_preflight() {
  if [ "$OFFLINE" -eq 1 ]; then
    info "Offline mode enabled; skipping network preflight"
    return 0
  fi

  if ! command -v curl >/dev/null 2>&1; then
    warn "curl not found; skipping network preflight check"
    return 0
  fi

  local probe_url=""
  if [ "$FROM_SOURCE" -eq 1 ]; then
    probe_url="https://github.com/${OWNER}/${REPO}"
  elif [ -n "$ARTIFACT_URL" ]; then
    probe_url="$ARTIFACT_URL"
  else
    probe_url="$SHA_URL"
  fi

  if [ -z "$probe_url" ]; then
    return 0
  fi

  if ! curl -fsSLI --connect-timeout 5 --max-time 10 "$probe_url" >/dev/null 2>&1; then
    warn "Network preflight failed for $probe_url"
    warn "Continuing; install may still succeed on retry"
  fi
}

preflight_checks() {
  info "Running installer preflight checks"
  check_disk_space
  check_existing_install
  check_network_preflight
}

validate_options() {
  case "$COMPLETIONS_MODE" in
    auto|off|bash|zsh|fish)
      ;;
    *)
      err "Invalid --completions value '$COMPLETIONS_MODE' (expected auto|off|bash|zsh|fish)"
      exit 1
      ;;
  esac

  if [ "$FROM_SOURCE" -eq 1 ] && [ -n "$ARTIFACT_URL" ]; then
    warn "--artifact-url is ignored with --from-source"
  fi

  if [ "$NO_VERIFY" -eq 1 ] && { [ -n "$CHECKSUM" ] || [ -n "$CHECKSUM_URL" ] || [ -n "$SIGSTORE_BUNDLE_URL" ]; }; then
    warn "--no-verify set; checksum/signature override flags are ignored"
  fi

  if [ -n "$CHECKSUM" ] && [[ ! "$CHECKSUM" =~ ^[0-9a-fA-F]{64}$ ]]; then
    err "--checksum must be a 64-character hex SHA256 digest"
    exit 1
  fi

  if [ -n "$CHECKSUM" ] && [ -n "$CHECKSUM_URL" ]; then
    warn "Both --checksum and --checksum-url provided; --checksum takes precedence"
  fi
}

check_dependencies() {
  if [ "$FROM_SOURCE" -eq 0 ] && ! command -v curl >/dev/null 2>&1; then
    err "curl is required for release downloads"
    exit 1
  fi

  if [ "$FROM_SOURCE" -eq 1 ]; then
    if ! command -v git >/dev/null 2>&1; then
      err "git is required for --from-source installs"
      exit 1
    fi
    if ! command -v cargo >/dev/null 2>&1; then
      err "cargo is required for --from-source installs"
      err "Install Rust nightly first: https://rustup.rs"
      exit 1
    fi
  fi
}

acquire_lock() {
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    LOCKED=1
    echo $$ > "$LOCK_DIR/pid"
    return 0
  fi

  if [ -f "$LOCK_DIR/pid" ]; then
    local old_pid
    old_pid=$(cat "$LOCK_DIR/pid" 2>/dev/null || true)
    if [ -n "$old_pid" ] && ! kill -0 "$old_pid" 2>/dev/null; then
      rmdir "$LOCK_DIR" 2>/dev/null || true
      if mkdir "$LOCK_DIR" 2>/dev/null; then
        LOCKED=1
        echo $$ > "$LOCK_DIR/pid"
        return 0
      fi
    fi
  fi

  err "Another installer appears to be running: $LOCK_DIR"
  exit 1
}

cleanup() {
  local exit_code=$?

  if [ "$exit_code" -ne 0 ] && [ "$MIGRATION_MOVED" -eq 1 ] && [ "$INSTALL_COMMITTED" -eq 0 ]; then
    if [ -n "$LEGACY_MOVED_FROM" ] && [ -n "$LEGACY_MOVED_TO" ] && [ -e "$LEGACY_MOVED_TO" ] && [ ! -e "$LEGACY_MOVED_FROM" ]; then
      mv "$LEGACY_MOVED_TO" "$LEGACY_MOVED_FROM" 2>/dev/null || true
      warn "Rolled back legacy pi preservation due to installer failure"
    fi
  fi

  if [ -n "$TMP" ] && [ -d "$TMP" ]; then
    rm -rf "$TMP" 2>/dev/null || true
  fi
  if [ "$LOCKED" -eq 1 ]; then
    rm -f "$LOCK_DIR/pid" 2>/dev/null || true
    rmdir "$LOCK_DIR" 2>/dev/null || true
  fi

  trap - EXIT
  exit "$exit_code"
}

trap cleanup EXIT

is_rust_pi_output() {
  local out="$1"
  [[ "$out" =~ ^pi[[:space:]][0-9]+\.[0-9]+\.[0-9]+[[:space:]]\( ]]
}

looks_like_node_script() {
  local path="$1"
  [ -f "$path" ] || return 1

  if [[ "$path" == *.js ]] || [[ "$path" == *node_modules* ]]; then
    return 0
  fi

  local head_line
  head_line=$(head -n 1 "$path" 2>/dev/null || true)
  if [[ "$head_line" == *node* ]]; then
    return 0
  fi

  return 1
}

detect_existing_pi() {
  CURRENT_PI_PATH=$(command -v pi 2>/dev/null || true)
  CURRENT_PI_VERSION=""
  TS_PI_DETECTED=0

  if [ -z "$CURRENT_PI_PATH" ]; then
    return 0
  fi

  CURRENT_PI_VERSION=$("$CURRENT_PI_PATH" --version 2>/dev/null | head -1 || true)

  if is_rust_pi_output "$CURRENT_PI_VERSION"; then
    TS_PI_DETECTED=0
    return 0
  fi

  if looks_like_node_script "$CURRENT_PI_PATH"; then
    TS_PI_DETECTED=1
    return 0
  fi

  if command -v npm >/dev/null 2>&1; then
    if npm list -g --depth=0 @mariozechner/pi-coding-agent >/dev/null 2>&1; then
      TS_PI_DETECTED=1
      return 0
    fi
  fi

  if [ -n "$CURRENT_PI_VERSION" ] && ! is_rust_pi_output "$CURRENT_PI_VERSION"; then
    TS_PI_DETECTED=1
  fi
}

choose_adoption_mode() {
  ADOPT_TS=0
  ADOPT_CANONICAL=0
  FINAL_BIN_NAME="pi"

  if [ "$TS_PI_DETECTED" -eq 0 ]; then
    return 0
  fi

  info "Detected existing non-Rust pi command at: $CURRENT_PI_PATH"
  if [ -n "$CURRENT_PI_VERSION" ]; then
    info "Existing pi reports: $CURRENT_PI_VERSION"
  fi

  local decision=""
  case "$ADOPT_MODE" in
    yes)
      decision="yes"
      ;;
    no)
      decision="no"
      ;;
    ask)
      if prompt_confirm "Install Rust Pi as canonical 'pi' and preserve existing one as '${LEGACY_ALIAS_NAME}'?" 0; then
        decision="yes"
      else
        decision="no"
      fi
      ;;
    *)
      decision="no"
      ;;
  esac

  if [ "$decision" = "yes" ]; then
    ADOPT_TS=1
    ADOPT_CANONICAL=1
  else
    ADOPT_TS=0
    ADOPT_CANONICAL=0
    FINAL_BIN_NAME="pi-rust"
    warn "Keeping existing pi untouched; Rust binary will be installed as ${FINAL_BIN_NAME}"
  fi
}

choose_dest_for_adoption() {
  if [ "$ADOPT_TS" -ne 1 ]; then
    return 0
  fi

  local current_dir=""
  if [ -n "$CURRENT_PI_PATH" ]; then
    current_dir=$(dirname "$CURRENT_PI_PATH")
  fi

  if [ "$DEST_EXPLICIT" -eq 1 ]; then
    if [ -n "$current_dir" ] && [ "$DEST" = "$current_dir" ]; then
      ADOPT_CANONICAL=1
    else
      ADOPT_CANONICAL=0
    fi
    return 0
  fi

  if [ -z "$CURRENT_PI_PATH" ]; then
    return 0
  fi

  if [ -w "$current_dir" ]; then
    DEST="$current_dir"
    ADOPT_CANONICAL=1
    info "Using existing pi directory for canonical replacement: $DEST"
    return 0
  fi

  ADOPT_CANONICAL=0
  warn "Cannot write to existing pi directory: $current_dir"
  warn "Will install to default destination: $DEST"
  warn "Enable --easy-mode to prepend that path for future shells"
}

ensure_install_target() {
  INSTALL_BIN_PATH="$DEST/$FINAL_BIN_NAME"
}

compute_sha256() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return 0
  fi
  err "No SHA256 tool found (sha256sum or shasum)"
  return 1
}

verify_download_checksum() {
  local artifact_file="$1"
  local asset_name="${2:-$ASSET_NAME}"
  local artifact_url="${3:-}"

  if [ "$NO_VERIFY" -eq 1 ]; then
    CHECKSUM_STATUS="skipped (--no-verify)"
    return 0
  fi

  local checksum_file="$TMP/checksum.txt"
  local expected=""
  local checksum_source_kind="release-manifest"

  if [ -n "$CHECKSUM" ]; then
    expected="$CHECKSUM"
    checksum_source_kind="inline"
  elif [ -n "$CHECKSUM_URL" ]; then
    if ! curl -fsSL "$CHECKSUM_URL" -o "$checksum_file"; then
      err "Failed to download checksum file: $CHECKSUM_URL"
      return 4
    fi
    checksum_source_kind="custom-url"
  elif [ -n "$ARTIFACT_URL" ]; then
    local artifact_base="${artifact_url%%\?*}"
    artifact_base="${artifact_base%%#*}"
    local derived_checksum_url="${artifact_base}.sha256"
    if ! curl -fsSL "$derived_checksum_url" -o "$checksum_file"; then
      err "Failed to download checksum file: $derived_checksum_url"
      err "Provide --checksum or --checksum-url for custom artifact installs"
      return 4
    fi
    checksum_source_kind="artifact-derived"
  else
    if ! curl -fsSL "$SHA_URL" -o "$checksum_file"; then
      err "Failed to download checksum manifest: $SHA_URL"
      return 4
    fi
  fi

  if [ -z "$expected" ]; then
    expected=$(awk -v name="$asset_name" '
      $1 ~ /^[0-9a-fA-F]{64}$/ {
        file=$2
        sub(/^\*/, "", file)
        sub(/^\.\//, "", file)
        if (file == name) {
          print $1
          exit
        }
      }
    ' "$checksum_file")

    if [ -z "$expected" ]; then
      if [ "$checksum_source_kind" != "release-manifest" ]; then
        local checksum_count
        checksum_count=$(awk '$1 ~ /^[0-9a-fA-F]{64}$/ { c += 1 } END { print c + 0 }' "$checksum_file")
        if [ "$checksum_count" -eq 1 ]; then
          expected=$(awk '$1 ~ /^[0-9a-fA-F]{64}$/ { print $1; exit }' "$checksum_file")
        fi
      fi
    fi

    if [ -z "$expected" ]; then
      CHECKSUM_STATUS="failed (missing checksum entry)"
      return 2
    fi
  fi

  local actual
  actual=$(compute_sha256 "$artifact_file")
  if [ "$actual" != "$expected" ]; then
    CHECKSUM_STATUS="failed (mismatch)"
    err "Checksum mismatch for $asset_name"
    err "Expected: $expected"
    err "Actual:   $actual"
    return 3
  fi

  local source_desc="SHA256SUMS"
  if [ -n "$CHECKSUM" ]; then
    source_desc="--checksum"
  elif [ -n "$CHECKSUM_URL" ]; then
    source_desc="--checksum-url"
  elif [ -n "$ARTIFACT_URL" ]; then
    source_desc="artifact .sha256"
  fi

  CHECKSUM_STATUS="verified (${source_desc})"
  ok "Checksum verified for ${asset_name}"
  if [ -n "$artifact_url" ] && [ "$QUIET" -eq 0 ]; then
    log "  checksum source: $source_desc"
  fi
}

verify_sigstore_bundle() {
  local artifact_file="$1"
  local artifact_url="$2"

  if [ "$NO_VERIFY" -eq 1 ]; then
    SIGSTORE_STATUS="skipped (--no-verify)"
    return 0
  fi

  if ! command -v cosign >/dev/null 2>&1; then
    SIGSTORE_STATUS="skipped (cosign not found)"
    warn "cosign not found; skipping signature verification"
    return 0
  fi

  local bundle_url="$SIGSTORE_BUNDLE_URL"
  if [ -z "$bundle_url" ]; then
    local artifact_base="${artifact_url%%\?*}"
    artifact_base="${artifact_base%%#*}"
    bundle_url="${artifact_base}.sigstore.json"
  fi

  local bundle_file="$TMP/$(basename "${bundle_url%%\?*}")"
  if ! curl -fsSL "$bundle_url" -o "$bundle_file"; then
    SIGSTORE_STATUS="skipped (bundle unavailable)"
    warn "Sigstore bundle not found; skipping signature verification"
    return 0
  fi

  if ! cosign verify-blob \
    --bundle "$bundle_file" \
    --certificate-identity-regexp "$COSIGN_IDENTITY_RE" \
    --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
    "$artifact_file"; then
    SIGSTORE_STATUS="failed"
    err "Sigstore verification failed for $(basename "$artifact_file")"
    return 1
  fi

  SIGSTORE_STATUS="verified"
  ok "Signature verified (cosign)"
}

extract_release_artifact() {
  local candidate="$1"
  local artifact_file="$2"

  if [[ "$candidate" == *.tar.xz ]]; then
    if ! command -v tar >/dev/null 2>&1; then
      warn "tar is not available to extract $candidate"
      return 1
    fi
    if ! command -v xz >/dev/null 2>&1; then
      warn "xz is not available to extract $candidate"
      return 1
    fi
    local extract_dir="$TMP/extract-${candidate//\//_}"
    mkdir -p "$extract_dir"
    if ! tar -xJf "$artifact_file" -C "$extract_dir"; then
      warn "Failed to extract archive: $candidate"
      return 1
    fi
    local found_bin=""
    found_bin="$(find "$extract_dir" -type f \( -name "pi${EXE_EXT}" -o -name "pi" -o -name "pi.exe" \) | head -1)"
    if [ -z "$found_bin" ]; then
      warn "archive '$candidate' did not contain a pi binary"
      return 1
    fi
    chmod +x "$found_bin" 2>/dev/null || true
    printf '%s\n' "$found_bin"
    return 0
  fi

  if [[ "$candidate" == *.tar.gz ]] || [[ "$candidate" == *.tgz ]]; then
    if ! command -v tar >/dev/null 2>&1; then
      warn "tar is not available to extract $candidate"
      return 1
    fi
    local extract_dir="$TMP/extract-${candidate//\//_}"
    mkdir -p "$extract_dir"
    if ! tar -xzf "$artifact_file" -C "$extract_dir"; then
      warn "Failed to extract archive: $candidate"
      return 1
    fi
    local found_bin=""
    found_bin="$(find "$extract_dir" -type f \( -name "pi${EXE_EXT}" -o -name "pi" -o -name "pi.exe" \) | head -1)"
    if [ -z "$found_bin" ]; then
      warn "archive '$candidate' did not contain a pi binary"
      return 1
    fi
    chmod +x "$found_bin" 2>/dev/null || true
    printf '%s\n' "$found_bin"
    return 0
  fi

  if [[ "$candidate" == *.zip ]]; then
    if ! command -v unzip >/dev/null 2>&1; then
      warn "unzip is not available to extract $candidate"
      return 1
    fi
    local extract_dir="$TMP/extract-${candidate//\//_}"
    mkdir -p "$extract_dir"
    if ! unzip -q "$artifact_file" -d "$extract_dir"; then
      warn "Failed to extract archive: $candidate"
      return 1
    fi
    local found_bin=""
    found_bin="$(find "$extract_dir" -type f \( -name "pi${EXE_EXT}" -o -name "pi" -o -name "pi.exe" \) | head -1)"
    if [ -z "$found_bin" ]; then
      warn "archive '$candidate' did not contain a pi binary"
      return 1
    fi
    chmod +x "$found_bin" 2>/dev/null || true
    printf '%s\n' "$found_bin"
    return 0
  fi

  chmod +x "$artifact_file" 2>/dev/null || true
  printf '%s\n' "$artifact_file"
}

download_release_binary() {
  local candidates=()
  if [ -n "$ARTIFACT_URL" ]; then
    candidates+=("$ASSET_NAME|$ARTIFACT_URL")
  else
    candidates+=("pi-${VERSION}-${TARGET}${EXE_EXT}|https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/pi-${VERSION}-${TARGET}${EXE_EXT}")
    if [ -n "$ASSET_PLATFORM" ]; then
      if [ -n "$EXE_EXT" ]; then
        candidates+=("pi-${ASSET_PLATFORM}.zip|https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/pi-${ASSET_PLATFORM}.zip")
      else
        candidates+=("pi-${ASSET_PLATFORM}.tar.xz|https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/pi-${ASSET_PLATFORM}.tar.xz")
      fi
    fi
  fi

  local entry=""
  for entry in "${candidates[@]}"; do
    local candidate="${entry%%|*}"
    local candidate_url="${entry#*|}"
    local artifact_file="$TMP/$candidate"
    if ! curl -fsSL "$candidate_url" -o "$artifact_file"; then
      if [ -n "$ARTIFACT_URL" ]; then
        err "Failed to download artifact: $candidate_url"
      fi
      continue
    fi

    ASSET_NAME="$candidate"

    local checksum_rc=0
    if verify_download_checksum "$artifact_file" "$candidate" "$candidate_url"; then
      :
    else
      checksum_rc=$?
      if [ "$checksum_rc" -eq 2 ]; then
        if [ -n "$ARTIFACT_URL" ] || [ -n "$CHECKSUM" ] || [ -n "$CHECKSUM_URL" ]; then
          err "No checksum entry found for $candidate"
          return "$checksum_rc"
        fi
        warn "No checksum entry for $candidate in SHA256SUMS; trying next candidate"
        continue
      fi
      return "$checksum_rc"
    fi

    if ! verify_sigstore_bundle "$artifact_file" "$candidate_url"; then
      return 5
    fi

    local extracted=""
    extracted="$(extract_release_artifact "$candidate" "$artifact_file" || true)"
    if [ -n "$extracted" ] && [ -e "$extracted" ]; then
      printf '%s\n' "$extracted"
      return 0
    fi
  done

  err "No downloadable release artifact found for version ${VERSION} and target ${TARGET}"
  return 1
}

build_from_source() {
  local src_dir="$TMP/src"
  git clone --depth 1 --branch "$VERSION" "https://github.com/${OWNER}/${REPO}.git" "$src_dir"
  (cd "$src_dir" && cargo build --release --locked --bin pi)

  local built_bin="$src_dir/target/release/pi${EXE_EXT}"
  if [ ! -x "$built_bin" ]; then
    err "Source build succeeded but binary was not found: $built_bin"
    return 1
  fi

  printf '%s\n' "$built_bin"
}

install_binary_file() {
  local source_bin="$1"
  install -m 0755 "$source_bin" "$INSTALL_BIN_PATH"
  ok "Installed $FINAL_BIN_NAME to $INSTALL_BIN_PATH"
}

choose_legacy_alias_path() {
  local candidate="$DEST/$LEGACY_ALIAS_NAME"
  if [ ! -e "$candidate" ]; then
    LEGACY_ALIAS_PATH="$candidate"
    return 0
  fi

  if grep -q "pi_agent_rust installer managed alias" "$candidate" 2>/dev/null; then
    LEGACY_ALIAS_PATH="$candidate"
    return 0
  fi

  local alt="$DEST/${LEGACY_ALIAS_NAME}-ts"
  if [ ! -e "$alt" ]; then
    warn "Existing $candidate is not installer-managed; using ${LEGACY_ALIAS_NAME}-ts instead"
    LEGACY_ALIAS_PATH="$alt"
    return 0
  fi

  local idx=1
  while :; do
    alt="$DEST/${LEGACY_ALIAS_NAME}-ts-${idx}"
    if [ ! -e "$alt" ]; then
      warn "Using alternate legacy alias: $(basename "$alt")"
      LEGACY_ALIAS_PATH="$alt"
      return 0
    fi
    idx=$((idx + 1))
  done
}

create_legacy_alias_wrapper() {
  local alias_path="$1"
  local target_path="$2"

  if [ -z "$alias_path" ] || [ -z "$target_path" ]; then
    return 1
  fi

  {
    printf '#!/usr/bin/env bash\n'
    printf '# pi_agent_rust installer managed alias\n'
    printf 'set -euo pipefail\n'
    printf 'exec %q "$@"\n' "$target_path"
  } > "$alias_path"
  chmod 0755 "$alias_path"
  ok "Created legacy alias: $alias_path"
}

prepare_typescript_migration() {
  MIGRATION_MOVED=0
  LEGACY_ALIAS_PATH=""
  LEGACY_TARGET_PATH=""
  LEGACY_MOVED_FROM=""
  LEGACY_MOVED_TO=""

  if [ "$ADOPT_TS" -ne 1 ]; then
    return 0
  fi

  choose_legacy_alias_path

  if [ -z "$CURRENT_PI_PATH" ]; then
    warn "No existing pi command path found; skipping legacy alias creation"
    return 0
  fi

  local current_real="$CURRENT_PI_PATH"
  if [ "$current_real" = "$INSTALL_BIN_PATH" ] && [ -e "$current_real" ]; then
    local preserve_candidate="$DEST/.pi-legacy-typescript"
    if [ -e "$preserve_candidate" ]; then
      local stamp
      stamp=$(date +%Y%m%d%H%M%S)
      preserve_candidate="$DEST/.pi-legacy-typescript.${stamp}"
    fi

    mv "$current_real" "$preserve_candidate"
    LEGACY_MOVED_FROM="$current_real"
    LEGACY_MOVED_TO="$preserve_candidate"
    LEGACY_TARGET_PATH="$preserve_candidate"
    MIGRATION_MOVED=1
    ok "Preserved existing pi binary at: $preserve_candidate"
  else
    LEGACY_TARGET_PATH="$current_real"
    info "Existing pi remains at: $current_real"
  fi

  create_legacy_alias_wrapper "$LEGACY_ALIAS_PATH" "$LEGACY_TARGET_PATH"
}

maybe_add_path() {
  case ":$PATH:" in
    *":$DEST:"*)
      return 0
      ;;
  esac

  if [ "$EASY" -ne 1 ]; then
    warn "Add this directory to PATH to use installed binaries: $DEST"
    return 0
  fi

  local updated=""
  for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
    if [ -e "$rc" ] && [ ! -w "$rc" ]; then
      continue
    fi

    if [ ! -e "$rc" ]; then
      : > "$rc"
    fi

    if grep -F "$PATH_MARKER" "$rc" >/dev/null 2>&1; then
      continue
    fi

    printf "\nexport PATH=\"%s:\$PATH\" %s\n" "$DEST" "$PATH_MARKER" >> "$rc"
    if [ -z "$updated" ]; then
      updated="$rc"
    else
      updated="$updated:$rc"
    fi
  done

  PATH_UPDATED_FILES="$updated"

  if [ -n "$updated" ]; then
    ok "Updated PATH in shell rc files"
    warn "Restart your shell (or source rc files) to use updated PATH"
  else
    warn "Could not update PATH automatically; add $DEST manually"
  fi
}

detect_default_shell() {
  local shell_name="${SHELL:-}"
  [ -z "$shell_name" ] && return 1
  shell_name=$(basename "$shell_name")
  case "$shell_name" in
    bash|zsh|fish)
      printf '%s\n' "$shell_name"
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

install_completions_for_shell() {
  local shell_name="$1"
  local bin="$INSTALL_BIN_PATH"

  if [ ! -x "$bin" ]; then
    COMPLETIONS_STATUS="skipped (binary missing)"
    return 1
  fi

  local subcommand=""
  if "$bin" completions --help >/dev/null 2>&1; then
    subcommand="completions"
  elif "$bin" completion --help >/dev/null 2>&1; then
    subcommand="completion"
  else
    COMPLETIONS_STATUS="skipped (unsupported by this pi build)"
    info "Shell completions: skipped (binary has no completion subcommand)"
    return 0
  fi

  local target=""
  case "$shell_name" in
    bash)
      target="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/${FINAL_BIN_NAME}"
      ;;
    zsh)
      target="${XDG_DATA_HOME:-$HOME/.local/share}/zsh/site-functions/_${FINAL_BIN_NAME}"
      ;;
    fish)
      target="${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions/${FINAL_BIN_NAME}.fish"
      ;;
    *)
      COMPLETIONS_STATUS="skipped (unsupported shell: $shell_name)"
      return 1
      ;;
  esac

  if ! mkdir -p "$(dirname "$target")" 2>/dev/null; then
    COMPLETIONS_STATUS="failed (cannot create completion dir)"
    warn "Failed to create shell completion directory for $shell_name"
    return 1
  fi

  local completion_output
  if ! completion_output=$("$bin" "$subcommand" "$shell_name" 2>/dev/null); then
    COMPLETIONS_STATUS="failed (completion generation error)"
    warn "Failed to generate $shell_name completions"
    return 1
  fi
  if [ -z "$completion_output" ]; then
    COMPLETIONS_STATUS="failed (completion generation error)"
    warn "Failed to generate $shell_name completions"
    return 1
  fi

  if ! printf '%s\n' "$completion_output" > "$target"; then
    COMPLETIONS_STATUS="failed (write error)"
    warn "Failed to write $shell_name completions to $target"
    return 1
  fi
  ok "Installed $shell_name completions to $target"
  COMPLETIONS_STATUS="installed ($shell_name)"
  return 0
}

maybe_install_completions() {
  if [ "$COMPLETIONS_MODE" = "off" ]; then
    COMPLETIONS_STATUS="skipped (--no-completions)"
    return 0
  fi

  local shell_name="$COMPLETIONS_MODE"
  if [ "$shell_name" = "auto" ]; then
    if ! shell_name=$(detect_default_shell); then
      COMPLETIONS_STATUS="skipped (unknown shell)"
      info "Shell completions: skipped (unable to detect shell)"
      return 0
    fi
  fi

  install_completions_for_shell "$shell_name" || true
}

load_existing_state() {
  if [ -f "$STATE_FILE" ]; then
    # shellcheck disable=SC1090
    source "$STATE_FILE"
  fi
}

write_state() {
  mkdir -p "$STATE_DIR"
  {
    printf '# pi_agent_rust installer state\n'
    printf 'PIAR_STATE_VERSION=%q\n' "$STATE_VERSION"
    printf 'PIAR_INSTALL_VERSION=%q\n' "$VERSION"
    printf 'PIAR_INSTALL_SOURCE=%q\n' "$INSTALL_SOURCE"
    printf 'PIAR_INSTALL_DEST=%q\n' "$DEST"
    printf 'PIAR_INSTALL_BIN=%q\n' "$INSTALL_BIN_PATH"
    printf 'PIAR_INSTALL_BIN_NAME=%q\n' "$FINAL_BIN_NAME"
    printf 'PIAR_CHECKSUM_STATUS=%q\n' "$CHECKSUM_STATUS"
    printf 'PIAR_SIGSTORE_STATUS=%q\n' "$SIGSTORE_STATUS"
    printf 'PIAR_COMPLETIONS_STATUS=%q\n' "$COMPLETIONS_STATUS"
    printf 'PIAR_ADOPTED_TYPESCRIPT=%q\n' "$ADOPT_TS"
    printf 'PIAR_LEGACY_ALIAS_PATH=%q\n' "$LEGACY_ALIAS_PATH"
    printf 'PIAR_LEGACY_TARGET_PATH=%q\n' "$LEGACY_TARGET_PATH"
    printf 'PIAR_LEGACY_MOVED_FROM=%q\n' "$LEGACY_MOVED_FROM"
    printf 'PIAR_LEGACY_MOVED_TO=%q\n' "$LEGACY_MOVED_TO"
    printf 'PIAR_PATH_MARKER=%q\n' "$PATH_MARKER"
    printf 'PIAR_PATH_UPDATED_FILES=%q\n' "$PATH_UPDATED_FILES"
    printf 'PIAR_INSTALLED_AT_UTC=%q\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$STATE_FILE"
}

should_skip_reinstall() {
  if [ "$FORCE_INSTALL" -eq 1 ]; then
    return 1
  fi

  if [ ! -x "$INSTALL_BIN_PATH" ]; then
    return 1
  fi

  local out
  out=$("$INSTALL_BIN_PATH" --version 2>/dev/null | head -1 || true)
  if ! is_rust_pi_output "$out"; then
    return 1
  fi

  if [ -n "${PIAR_INSTALL_VERSION:-}" ] && [ "$PIAR_INSTALL_VERSION" = "$VERSION" ]; then
    return 0
  fi

  return 1
}

print_summary() {
  [ "$QUIET" -eq 1 ] && return 0

  local lines=()
  lines+=("Installed: $INSTALL_BIN_PATH")
  lines+=("Version:   $VERSION")
  lines+=("Source:    $INSTALL_SOURCE")
  lines+=("Checksum:  $CHECKSUM_STATUS")
  lines+=("Signature: $SIGSTORE_STATUS")
  lines+=("Shell:     $COMPLETIONS_STATUS")

  if [ "$ADOPT_TS" -eq 1 ]; then
    if [ "$ADOPT_CANONICAL" -eq 1 ]; then
      lines+=("Mode:      Rust is canonical 'pi'")
    else
      lines+=("Mode:      Adoption requested; ensure '$DEST' precedes existing pi in PATH")
    fi
    if [ -n "$LEGACY_ALIAS_PATH" ]; then
      lines+=("Legacy:    $(basename "$LEGACY_ALIAS_PATH") -> $LEGACY_TARGET_PATH")
    fi
  elif [ "$FINAL_BIN_NAME" = "pi-rust" ]; then
    lines+=("Mode:      Existing pi kept; Rust installed as pi-rust")
  fi

  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    {
      gum style --foreground 42 --bold "pi installed successfully"
      echo ""
      for line in "${lines[@]}"; do
        gum style --foreground 245 "$line"
      done
      echo ""
      gum style --foreground 245 "Uninstall: curl -fsSL https://raw.githubusercontent.com/${OWNER}/${REPO}/main/uninstall.sh | bash"
    } | gum style --border normal --border-foreground 42 --padding "1 2"
  else
    echo -e "\033[0;36m+------------------------------------------------------------------+\033[0m"
    echo -e "\033[1;32m| Pi Rust installed successfully                                   |\033[0m"
    echo -e "\033[0;36m+------------------------------------------------------------------+\033[0m"
    for line in "${lines[@]}"; do
      echo -e "  \033[0;37m$line\033[0m"
    done
    echo ""
    echo -e "  \033[0;90mUninstall: curl -fsSL https://raw.githubusercontent.com/${OWNER}/${REPO}/main/uninstall.sh | bash\033[0m"
  fi
}

main() {
  show_header

  validate_options
  load_existing_state
  resolve_version
  detect_existing_pi
  choose_adoption_mode
  choose_dest_for_adoption

  detect_platform
  prepare_asset_urls
  ensure_dest_dir
  ensure_install_target
  check_dependencies
  preflight_checks

  if should_skip_reinstall; then
    INSTALL_SOURCE="existing (no reinstall)"
    CHECKSUM_STATUS="not run (already installed)"
    SIGSTORE_STATUS="not run (already installed)"
    ok "pi ${VERSION} already installed at $INSTALL_BIN_PATH"
    if [ "$ADOPT_TS" -eq 1 ]; then
      local refresh_legacy=0
      if [ -z "${PIAR_LEGACY_ALIAS_PATH:-}" ]; then
        refresh_legacy=1
      elif [ ! -f "${PIAR_LEGACY_ALIAS_PATH}" ]; then
        refresh_legacy=1
      elif ! grep -q "pi_agent_rust installer managed alias" "${PIAR_LEGACY_ALIAS_PATH}" 2>/dev/null; then
        refresh_legacy=1
      fi

      if [ "$refresh_legacy" -eq 1 ]; then
        prepare_typescript_migration
        write_state
      fi
    fi
    maybe_add_path
    maybe_install_completions
    print_summary
    return 0
  fi

  acquire_lock
  TMP=$(mktemp -d)

  local source_bin=""
  if [ "$FROM_SOURCE" -eq 1 ]; then
    INSTALL_SOURCE="source"
    CHECKSUM_STATUS="not applicable (source build)"
    SIGSTORE_STATUS="not applicable (source build)"
    run_with_spinner "Building pi from source" build_from_source > "$TMP/source_bin_path"
    source_bin=$(cat "$TMP/source_bin_path")
  else
    INSTALL_SOURCE="release"
    local download_rc=0
    if run_with_spinner "Downloading release binary" download_release_binary > "$TMP/source_bin_path"; then
      source_bin=$(cat "$TMP/source_bin_path")
    else
      download_rc=$?
      if [ "$download_rc" -eq 2 ] || [ "$download_rc" -eq 3 ] || [ "$download_rc" -eq 4 ]; then
        err "Release checksum verification failed; aborting install"
        exit 1
      fi
      if [ "$download_rc" -eq 5 ]; then
        err "Release signature verification failed; aborting install"
        exit 1
      fi
      warn "Release download failed; falling back to source build"
      FROM_SOURCE=1
      INSTALL_SOURCE="source (release fallback)"
      CHECKSUM_STATUS="not applicable (source fallback)"
      SIGSTORE_STATUS="not applicable (source fallback)"
      check_dependencies
      run_with_spinner "Building pi from source" build_from_source > "$TMP/source_bin_path"
      source_bin=$(cat "$TMP/source_bin_path")
    fi
  fi

  prepare_typescript_migration
  install_binary_file "$source_bin"

  if [ "$VERIFY" -eq 1 ]; then
    "$INSTALL_BIN_PATH" --version >/dev/null
    ok "Verification passed ($FINAL_BIN_NAME --version)"
  fi

  maybe_add_path
  maybe_install_completions
  write_state
  INSTALL_COMMITTED=1
  print_summary
}

main "$@"
