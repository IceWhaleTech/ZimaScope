#!/usr/bin/env bash
# Installs a built ZimaScope release: the agent binary (with the eBPF object
# embedded), the frontend bundle, and the systemd unit. Data lives in
# /var/lib/zimascope and is never touched.
#
# Usage: sudo packaging/install.sh <release-dir>
#   <release-dir> must contain:
#     bin/zimascope-agent
#     web/index.html ...
set -euo pipefail

INSTALL_ROOT="/opt/zimascope"
SERVICE_NAME="zimascope-agent.service"
LEGACY_UI_SERVICE="zimascope-ui.service"

if [[ ${EUID} -ne 0 ]]; then
  echo "install.sh: run as root (sudo packaging/install.sh <release-dir>)" >&2
  exit 1
fi

RELEASE_DIR=${1:-}
if [[ -z ${RELEASE_DIR} || ! -x "${RELEASE_DIR}/bin/zimascope-agent" ]]; then
  echo "install.sh: usage: install.sh <release-dir> (needs bin/zimascope-agent)" >&2
  exit 1
fi
if [[ ! -f "${RELEASE_DIR}/web/index.html" ]]; then
  echo "install.sh: ${RELEASE_DIR}/web/index.html is missing" >&2
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
install -m 0755 -o root -g root "${RELEASE_DIR}/bin/zimascope-agent" \
  "${INSTALL_ROOT}/bin/zimascope-agent"

echo "==> installing frontend to ${INSTALL_ROOT}/web"
rm -rf "${INSTALL_ROOT}/web"
install -d -m 0755 "${INSTALL_ROOT}/web"
cp -R "${RELEASE_DIR}/web/." "${INSTALL_ROOT}/web/"
chown -R root:root "${INSTALL_ROOT}/web"

echo "==> installing ${SERVICE_NAME}"
install -m 0644 -o root -g root "${UNIT_SRC}" "/etc/systemd/system/${SERVICE_NAME}"
install -d -m 0755 /var/lib/zimascope

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
echo "==> ZimaScope installed: http://<host>:8080/  (API: /v1)"
