#!/usr/bin/env bash
# Installs a built Z-Scope release: one binary with the eBPF object and the
# frontend bundle embedded, plus the systemd unit. Data lives in
# /var/lib/zimascope and is never touched.
#
# Usage: sudo packaging/install.sh <release-dir>
#   <release-dir> must contain:
#     bin/zimascoped
#     zimascoped.service
set -euo pipefail

INSTALL_ROOT="/opt/zimascope"
SERVICE_NAME="zimascoped.service"
LEGACY_AGENT_SERVICE="zimascope-agent.service"
LEGACY_UI_SERVICE="zimascope-ui.service"

if [[ ${EUID} -ne 0 ]]; then
  echo "install.sh: run as root (sudo packaging/install.sh <release-dir>)" >&2
  exit 1
fi

RELEASE_DIR=${1:-}
if [[ -z ${RELEASE_DIR} || ! -x "${RELEASE_DIR}/bin/zimascoped" ]]; then
  echo "install.sh: usage: install.sh <release-dir> (needs bin/zimascoped)" >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
UNIT_SRC="${SCRIPT_DIR}/${SERVICE_NAME}"
if [[ ! -f ${UNIT_SRC} ]]; then
  echo "install.sh: ${UNIT_SRC} is missing" >&2
  exit 1
fi

echo "==> installing agent to ${INSTALL_ROOT}/bin"
install -d -m 0755 "${INSTALL_ROOT}/bin"
install -m 0755 -o root -g root "${RELEASE_DIR}/bin/zimascoped" \
  "${INSTALL_ROOT}/bin/zimascoped"

# Releases before the embedded bundle shipped a web/ directory; the binary
# serves the SPA itself now.
rm -rf "${INSTALL_ROOT}/web"

echo "==> installing ${SERVICE_NAME}"
install -m 0644 -o root -g root "${UNIT_SRC}" "/etc/systemd/system/${SERVICE_NAME}"
install -d -m 0755 /var/lib/zimascope

# Retire the pre-rename daemon before starting zimascoped, otherwise both
# units can compete for the same sockets and HTTP port during upgrades.
echo "==> retiring ${LEGACY_AGENT_SERVICE}"
systemctl disable --now "${LEGACY_AGENT_SERVICE}" >/dev/null 2>&1 || true
rm -f "/etc/systemd/system/${LEGACY_AGENT_SERVICE}" "${INSTALL_ROOT}/bin/zimascope-agent"

# Older releases served the SPA with `vite preview` on :8080; the agent owns
# that port now, so the legacy unit must be stopped before the restart.
echo "==> retiring ${LEGACY_UI_SERVICE} (the agent serves the UI now)"
systemctl disable --now "${LEGACY_UI_SERVICE}" >/dev/null 2>&1 || true

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}" >/dev/null
systemctl restart "${SERVICE_NAME}"

echo "==> waiting for the agent"
for _ in $(seq 1 20); do
  if curl -fsS --max-time 2 "http://127.0.0.1:8080/v1/status" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

curl -fsS --max-time 3 "http://127.0.0.1:8080/v1/status" | head -c 200
echo
curl -fsS --max-time 3 "http://127.0.0.1:8080/" | grep -qi "<!doctype html>" \
  && echo "==> UI is being served by the agent"
echo "==> Z-Scope installed: http://<host>:8080/  (API: /v1)"
