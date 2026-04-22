#!/usr/bin/env sh
set -eu

API_BASE="${API_BASE:-https://api.github.com}"
VERSION="${VERSION:-latest}"
PREFIX="${PREFIX:-/usr/local/bin}"
INSTALL_UWGSOCKS="${INSTALL_UWGSOCKS:-1}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

need uname
need curl
need mktemp
need python3

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
os="${TARGET_OS:-$os}"
arch="${TARGET_ARCH:-$arch}"

case "$os" in
  linux|darwin|freebsd) ;;
  *)
    echo "unsupported OS: $os" >&2
    exit 1
    ;;
esac

case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *)
    echo "unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

repo_for_product() {
  case "$1" in
    uwgsocks-ui|uwgkm) printf '%s\n' reindertpelsma/simple-wireguard-server ;;
    uwgsocks) printf '%s\n' reindertpelsma/userspace-wireguard-socks ;;
    *)
      echo "unsupported product: $1" >&2
      exit 1
      ;;
  esac
}

binary_name() {
  case "$1" in
    uwgsocks-ui) printf '%s\n' uwgsocks-ui ;;
    uwgkm) printf '%s\n' uwgkm ;;
    uwgsocks) printf '%s\n' uwgsocks ;;
  esac
}

asset_name() {
  product="$1"
  case "$product" in
    uwgsocks-ui) printf 'uwgsocks-ui-%s-%s\n' "$os" "$arch" ;;
    uwgsocks) printf 'uwgsocks-%s-%s\n' "$os" "$arch" ;;
    uwgkm)
      [ "$os" = "linux" ] || {
        echo "uwgkm is only published for linux" >&2
        exit 1
      }
      printf 'uwgkm-linux-%s\n' "$arch"
      ;;
  esac
}

release_url() {
  repo="$1"
  if [ "$VERSION" = "latest" ]; then
    printf '%s/repos/%s/releases/latest\n' "$API_BASE" "$repo"
  else
    printf '%s/repos/%s/releases/tags/%s\n' "$API_BASE" "$repo" "$VERSION"
  fi
}

download_asset() {
  product="$1"
  repo="$(repo_for_product "$product")"
  asset="$(asset_name "$product")"
  meta="$(mktemp)"
  tmp_bin="$(mktemp)"
  trap 'rm -f "$meta" "$tmp_bin"' EXIT INT TERM

  curl -fsSL -H 'Accept: application/vnd.github+json' "$(release_url "$repo")" >"$meta"
  download_url="$(python3 - "$meta" "$asset" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    data = json.load(fh)
want = sys.argv[2]
for asset in data.get("assets", []):
    if asset.get("name") == want:
        print(asset.get("browser_download_url", ""))
        break
else:
    raise SystemExit(1)
PY
)"
  [ -n "$download_url" ] || {
    echo "release asset not found: $asset" >&2
    exit 1
  }

  mkdir -p "$PREFIX"
  dst="$PREFIX/$(binary_name "$product")"
  curl -fsSL "$download_url" -o "$tmp_bin"
  chmod +x "$tmp_bin"
  mv "$tmp_bin" "$dst"
  printf 'installed %s to %s\n' "$asset" "$dst"
  rm -f "$meta"
  trap - EXIT INT TERM
}

if [ "$#" -eq 0 ]; then
  set -- uwgsocks-ui
fi

need_uwgsocks=1
for product in "$@"; do
  [ "$product" = "uwgsocks" ] && need_uwgsocks=0
done

if [ "$INSTALL_UWGSOCKS" = "1" ] && [ "$need_uwgsocks" = "1" ] && ! command -v uwgsocks >/dev/null 2>&1 && [ ! -x "$PREFIX/uwgsocks" ]; then
  set -- "$@" uwgsocks
fi

for product in "$@"; do
  download_asset "$product"
done
