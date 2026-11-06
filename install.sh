#!/bin/sh
# dwvault installer — DonkeyWork Vault credential CLI.
#
#   curl -fsSL https://raw.githubusercontent.com/andyjmorgan/DonkeyWork-Vault/main/install.sh | sh
#
# Downloads the right prebuilt `dwvault` binary for your OS/arch from the latest
# GitHub release, verifies it against the published SHA256SUMS, and installs it.
# Verification is mandatory and fails closed: if the checksum cannot be fetched
# or computed, the install aborts rather than proceeding unverified.
#
# Environment overrides:
#   DWVAULT_VERSION   release tag to install (default: latest)
#   DWVAULT_BIN_DIR   install directory     (default: ~/.local/bin, or /usr/local/bin if writable & on PATH)
#   DWVAULT_REPO      owner/repo to pull from (default: andyjmorgan/DonkeyWork-Vault)
#   DWVAULT_NO_VERIFY set to 1 to skip checksum verification (not recommended; the only bypass)
set -eu

REPO="${DWVAULT_REPO:-andyjmorgan/DonkeyWork-Vault}"
VERSION="${DWVAULT_VERSION:-latest}"

say()  { printf '%s\n' "$*" >&2; }
err()  { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- detect platform -------------------------------------------------------
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux)  os=linux  ;;
  darwin) os=darwin ;;
  *) err "unsupported OS '$os' (prebuilt binaries: linux, darwin). Build from source: https://github.com/$REPO" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64)  arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) err "unsupported architecture '$arch' (prebuilt binaries: amd64, arm64)" ;;
esac

asset="dwvault-$os-$arch"

# --- resolve download base -------------------------------------------------
if [ "$VERSION" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

# --- pick a download tool --------------------------------------------------
if have curl; then
  dl() { curl -fsSL -o "$1" "$2"; }
elif have wget; then
  dl() { wget -qO "$1" "$2"; }
else
  err "need curl or wget to download"
fi

# --- choose install dir ----------------------------------------------------
bindir="${DWVAULT_BIN_DIR:-}"
if [ -z "$bindir" ]; then
  case ":$PATH:" in
    *:/usr/local/bin:*) [ -w /usr/local/bin ] && bindir=/usr/local/bin ;;
  esac
  [ -z "$bindir" ] && bindir="$HOME/.local/bin"
fi

# --- download into a temp dir ----------------------------------------------
tmp=$(mktemp -d 2>/dev/null || mktemp -d -t dwvault)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading $asset ($VERSION)…"
dl "$tmp/$asset" "$base/$asset" || err "download failed: $base/$asset"

# --- verify checksum -------------------------------------------------------
# Fail closed: unless DWVAULT_NO_VERIFY=1 is explicitly set, any condition that
# prevents completing verification (missing SHA256SUMS, no checksum tool, or no
# matching entry for this asset) is a hard error — never install an unverified
# binary. The only sanctioned bypass is DWVAULT_NO_VERIFY=1.
if [ "${DWVAULT_NO_VERIFY:-0}" != "1" ]; then
  dl "$tmp/SHA256SUMS" "$base/SHA256SUMS" 2>/dev/null \
    || err "could not fetch SHA256SUMS for verification ($base/SHA256SUMS); refusing to install an unverified binary (set DWVAULT_NO_VERIFY=1 to override)"
  want=$(grep " $asset\$" "$tmp/SHA256SUMS" | awk '{print $1}')
  [ -n "$want" ] || err "no checksum for $asset in SHA256SUMS; refusing to install an unverified binary (set DWVAULT_NO_VERIFY=1 to override)"
  if have sha256sum;   then got=$(sha256sum "$tmp/$asset" | awk '{print $1}')
  elif have shasum;    then got=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
  else err "no sha256 tool found (need sha256sum or shasum) to verify the download; refusing to install an unverified binary (set DWVAULT_NO_VERIFY=1 to override)"
  fi
  [ "$got" = "$want" ] || err "checksum mismatch for $asset (expected $want, got $got)"
  say "Checksum OK."
fi

# --- install ---------------------------------------------------------------
chmod +x "$tmp/$asset"
mkdir -p "$bindir" 2>/dev/null || true
if [ -w "$bindir" ] || mkdir -p "$bindir" 2>/dev/null; then
  mv "$tmp/$asset" "$bindir/dwvault"
elif have sudo; then
  say "Installing to $bindir (needs sudo)…"
  sudo install -Dm755 "$tmp/$asset" "$bindir/dwvault"
else
  err "cannot write to $bindir; set DWVAULT_BIN_DIR to a writable directory"
fi

# macOS: binaries are signed with a Developer ID and notarized by Apple, so no
# quarantine workaround is needed. (curl downloads aren't quarantined anyway.)

say "Installed dwvault to $bindir/dwvault"

# --- PATH hint -------------------------------------------------------------
case ":$PATH:" in
  *":$bindir:"*) : ;;
  *) say ""
     say "  $bindir is not on your PATH. Add it, e.g.:"
     say "    echo 'export PATH=\"$bindir:\$PATH\"' >> ~/.profile && . ~/.profile"
     ;;
esac

say ""
say "Done. Next steps:"
say "  dwvault --version"
say "  dwvault auth login            # OAuth device login by default"
say "  dwvault credentials list      # see your credentials"
