#!/bin/sh
# Builds the ZimaOS module package (.raw) for ZimaScope.
#
# The package is a squashfs image that systemd-sysext merges under /usr. zpkg
# requires the image basename to equal both the zpkg module name and the
# extension-release metadata name inside it (see ZimaOS-ModManagement
# internal.ValidateRawFile), so this script always emits
# "$DIST_DIR/zimascope.raw".
#
# Env overrides:
#   ZIMASCOPE_VERSION   version written to the module manifest (default: Cargo.toml)
#   ZIMASCOPE_BIN_PATH  host binary to pack (default: target/release/zimascoped)
#   PACKAGE_NAME        module name (default: zimascope)
#   TARGET_ARCH         x86_64|amd64|aarch64|arm64 (default: x86_64)
#   GEOIP_DIR           directory of *.mmdb files bundled into the image
#                       (default: target/geoip when present, otherwise skipped)
#   DIST_DIR, WORK_DIR, RAW_TEMPLATE_DIR

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RAW_TEMPLATE_DIR="${RAW_TEMPLATE_DIR:-$SCRIPT_DIR/zimaos/raw}"
WORK_DIR="${WORK_DIR:-$REPO_ROOT/target/zimaos-raw}"
DIST_DIR="${DIST_DIR:-$REPO_ROOT/dist}"
PACKAGE_NAME="${PACKAGE_NAME:-zimascope}"
TARGET_ARCH="${TARGET_ARCH:-x86_64}"
ZIMASCOPE_BIN_PATH="${ZIMASCOPE_BIN_PATH:-}"
ZIMASCOPE_VERSION="${ZIMASCOPE_VERSION:-}"
GEOIP_DIR="${GEOIP_DIR:-}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'missing command: %s\n' "$1" >&2
    exit 1
  }
}

is_safe_name() {
  case "$1" in
    ""|*[!A-Za-z0-9_.-]*)
      return 1
      ;;
    *)
      return 0
      ;;
  esac
}

is_safe_raw_root() {
  case "$1" in
    "$REPO_ROOT"/target/zimaos-raw/raw-x86_64|"$REPO_ROOT"/target/zimaos-raw/raw-aarch64)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

is_safe_output_path() {
  case "$1" in
    "$REPO_ROOT"/dist/*.raw)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

remove_raw_root() {
  raw_root="$1"
  if [ -d "$raw_root" ]; then
    if ! is_safe_raw_root "$raw_root"; then
      printf 'refusing to remove unsafe raw root: %s\n' "$raw_root" >&2
      return 1
    fi
    find "$raw_root" -mindepth 1 -depth ! -type d -exec unlink {} \;
    find "$raw_root" -mindepth 1 -depth -type d -exec rmdir {} \;
    rmdir "$raw_root"
  fi
}

remove_output_file() {
  output_path="$1"
  if [ -e "$output_path" ] || [ -L "$output_path" ]; then
    if ! is_safe_output_path "$output_path"; then
      printf 'refusing to remove unsafe output path: %s\n' "$output_path" >&2
      return 1
    fi
    unlink "$output_path"
  fi
}

resolve_version() {
  if [ -n "$ZIMASCOPE_VERSION" ]; then
    printf '%s\n' "$ZIMASCOPE_VERSION"
    return 0
  fi

  awk '/^\[workspace.package\]/{found=1} found && /^version =/{gsub(/"/, "", $3); print $3; exit}' \
    "$REPO_ROOT/Cargo.toml"
}

resolve_arch() {
  case "$TARGET_ARCH" in
    x86_64|amd64)
      printf 'x86_64\n'
      ;;
    aarch64|arm64)
      printf 'aarch64\n'
      ;;
    *)
      printf 'unsupported target arch: %s\n' "$TARGET_ARCH" >&2
      return 1
      ;;
  esac
}

resolve_bin_path() {
  if [ -n "$ZIMASCOPE_BIN_PATH" ]; then
    printf '%s\n' "$ZIMASCOPE_BIN_PATH"
    return 0
  fi

  printf '%s\n' "$REPO_ROOT/target/release/zimascoped"
}

bundle_geoip() {
  raw_root="$1"

  if [ -z "$GEOIP_DIR" ] && [ -d "$REPO_ROOT/target/geoip" ]; then
    GEOIP_DIR="$REPO_ROOT/target/geoip"
  fi

  if [ -z "$GEOIP_DIR" ]; then
    printf 'No GeoIP database bundled (set GEOIP_DIR to a directory of *.mmdb files)\n'
    return 0
  fi

  if [ ! -d "$GEOIP_DIR" ]; then
    printf 'GEOIP_DIR is not a directory: %s\n' "$GEOIP_DIR" >&2
    exit 1
  fi

  mkdir -p "$raw_root/usr/share/zimascope/geoip"
  bundled=0
  for db in "$GEOIP_DIR"/*.mmdb; do
    [ -f "$db" ] || continue
    cp "$db" "$raw_root/usr/share/zimascope/geoip/"
    bundled=$((bundled + 1))
  done

  if [ "$bundled" -eq 0 ]; then
    printf 'GEOIP_DIR has no *.mmdb files: %s\n' "$GEOIP_DIR" >&2
    exit 1
  fi

  chmod 0644 "$raw_root"/usr/share/zimascope/geoip/*.mmdb
  printf 'Bundled %s GeoIP database(s) from %s\n' "$bundled" "$GEOIP_DIR"
}

require_cmd mksquashfs

if ! is_safe_name "$PACKAGE_NAME"; then
  printf 'unsafe package name: %s\n' "$PACKAGE_NAME" >&2
  exit 1
fi

ASSET_ARCH=$(resolve_arch)
ZIMASCOPE_VERSION=$(resolve_version)
if [ -z "$ZIMASCOPE_VERSION" ]; then
  printf 'cannot resolve ZimaScope version from Cargo.toml\n' >&2
  exit 1
fi

RAW_ROOT="$WORK_DIR/raw-${ASSET_ARCH}"
OUTPUT_PATH="$DIST_DIR/${PACKAGE_NAME}.raw"
EXTENSION_RELEASE="$RAW_ROOT/usr/lib/extension-release.d/extension-release.${PACKAGE_NAME}"

remove_raw_root "$RAW_ROOT"
mkdir -p "$DIST_DIR" "$WORK_DIR"

cp -R "$RAW_TEMPLATE_DIR"/. "$RAW_ROOT"

if [ ! -f "$EXTENSION_RELEASE" ]; then
  printf 'missing extension-release.d/extension-release.%s in the raw template\n' "$PACKAGE_NAME" >&2
  exit 1
fi

ZIMASCOPE_BIN_PATH=$(resolve_bin_path)
if [ ! -f "$ZIMASCOPE_BIN_PATH" ]; then
  printf 'missing zimascoped binary: %s\n' "$ZIMASCOPE_BIN_PATH" >&2
  printf 'build the release binary first, or set ZIMASCOPE_BIN_PATH to the binary\n' >&2
  exit 1
fi

mkdir -p "$RAW_ROOT/usr/bin"
cp "$ZIMASCOPE_BIN_PATH" "$RAW_ROOT/usr/bin/zimascoped"
chmod 0755 "$RAW_ROOT/usr/bin/zimascoped"

mkdir -p "$RAW_ROOT/usr/share/zimascope"
printf 'v%s\n' "$ZIMASCOPE_VERSION" > "$RAW_ROOT/usr/share/zimascope/VERSION"

bundle_geoip "$RAW_ROOT"

ZIMASCOPE_VERSION_SED=$(printf '%s\n' "$ZIMASCOPE_VERSION" | sed 's/[\/&]/\\&/g')
sed -e "s/__ZIMASCOPE_VERSION__/${ZIMASCOPE_VERSION_SED}/g" \
  "$RAW_TEMPLATE_DIR/usr/share/casaos/modules/zimascope.json" \
  > "$RAW_ROOT/usr/share/casaos/modules/zimascope.json"

remove_output_file "$OUTPUT_PATH"
mksquashfs "$RAW_ROOT" "$OUTPUT_PATH" -noappend -comp gzip -no-xattrs -all-root

printf 'Built %s (ZimaScope %s, %s)\n' "$OUTPUT_PATH" "$ZIMASCOPE_VERSION" "$ASSET_ARCH"
