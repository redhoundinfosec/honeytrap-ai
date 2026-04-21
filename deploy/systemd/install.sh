#!/usr/bin/env bash
# Install HoneyTrap AI as a hardened systemd service.
#
# Idempotent: safe to re-run. Creates a dedicated system user, a Python
# venv under /opt/honeytrap, installs the package, and enables the unit.
set -euo pipefail

INSTALL_ROOT="${INSTALL_ROOT:-/opt/honeytrap}"
DATA_DIR="${DATA_DIR:-/var/lib/honeytrap}"
LOG_DIR="${LOG_DIR:-/var/log/honeytrap}"
SERVICE_USER="${SERVICE_USER:-honeytrap}"
SERVICE_GROUP="${SERVICE_GROUP:-honeytrap}"
UNIT_NAME="honeytrap.service"
REPO_SPEC="${REPO_SPEC:-honeytrap-ai}"

if [ "${EUID}" -ne 0 ]; then
    echo "This installer must be run as root." >&2
    exit 1
fi

if ! getent group "${SERVICE_GROUP}" >/dev/null; then
    groupadd --system "${SERVICE_GROUP}"
fi

if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    useradd --system \
        --gid "${SERVICE_GROUP}" \
        --home "${INSTALL_ROOT}" \
        --shell /usr/sbin/nologin \
        "${SERVICE_USER}"
fi

install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0750 "${INSTALL_ROOT}"
install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0750 "${DATA_DIR}"
install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0750 "${LOG_DIR}"

if [ ! -x "${INSTALL_ROOT}/venv/bin/python" ]; then
    python3 -m venv "${INSTALL_ROOT}/venv"
fi

"${INSTALL_ROOT}/venv/bin/pip" install --upgrade pip
"${INSTALL_ROOT}/venv/bin/pip" install --upgrade "${REPO_SPEC}"

chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_ROOT}"

UNIT_SRC="$(dirname "$(readlink -f "$0")")/${UNIT_NAME}"
UNIT_DST="/etc/systemd/system/${UNIT_NAME}"
install -o root -g root -m 0644 "${UNIT_SRC}" "${UNIT_DST}"

systemctl daemon-reload
systemctl enable --now "${UNIT_NAME}"

echo "HoneyTrap AI installed. Check status with: systemctl status ${UNIT_NAME}"
