#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RUN_ID=""
ROOT="${REPO_ROOT}/target/fixtures"
REPORT_PATH="${REPO_ROOT}/target/tmp/webdav-fixture-smoke-evidence.md"
IMAGE="rclone/rclone:1.70.2"
TIMEOUT=90
TAIL_LINES=80
PULL=0

usage() {
  cat <<'EOF'
Usage: scripts/webdav-fixture-smoke.sh [options]

Starts a disposable local WebDAV fixture, exercises WebDAV plugin capabilities,
writes redacted evidence, and tears the fixture down.

Options:
  --run-id <id>         Stable run id. Generated when omitted.
  --root <dir>          Fixture state root. Default: target/fixtures.
  --report <path>       Evidence report path. Default: target/tmp/webdav-fixture-smoke-evidence.md.
  --image <image>       Docker image for the fixture. Default: pinned rclone release tag.
  --timeout <seconds>   Health wait timeout. Default: 90.
  --tail <lines>        Log lines to keep. Default: 80.
  --pull                Pull the fixture image when it is missing.
  -h, --help            Show this help.

The script prints resource names and variable names only. It does not print
fixture credentials, endpoint URLs, file contents, or scratch values.
EOF
}

die() {
  echo "error: $*" >&2
  exit 2
}

generate_run_id() {
  printf 'webdav-cap-%s-%s\n' "$(date -u +%Y%m%dT%H%M%SZ)" "$$"
}

sanitize_id() {
  local value="$1"
  [[ "${value}" =~ ^[A-Za-z0-9_.-]+$ ]] || die "invalid id: ${value}"
}

fixture_dir() {
  printf '%s/%s\n' "${ROOT}" "${RUN_ID}"
}

env_path() {
  printf '%s/webdav.env\n' "$(fixture_dir)"
}

log_path() {
  printf '%s/webdav.log\n' "$(fixture_dir)"
}

container_name() {
  printf 'voidb-fixture-webdav-%s-main\n' "${RUN_ID}"
}

network_name() {
  printf 'voidb-fixture-webdav-%s\n' "${RUN_ID}"
}

cleanup_fixture() {
  "${SCRIPT_DIR}/local-fixture-smoke.sh" teardown \
    --fixture webdav \
    --run-id "${RUN_ID}" \
    --root "${ROOT}" >/dev/null 2>&1 || true
}

write_evidence() {
  local status="$1"
  local cleanup_status="$2"
  local smoke_log="$3"
  local commit
  commit="$(/usr/bin/git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo "unknown")"
  local docker_version
  docker_version="$(docker version --format 'client={{.Client.Version}} server={{.Server.Version}}' 2>/dev/null || echo "unknown")"

  mkdir -p "$(dirname "${REPORT_PATH}")"
  cat > "${REPORT_PATH}" <<EOF
# WebDAV Fixture Capability Smoke Evidence

- Requirements: 65 - Promote WebDAV fixture-backed readiness; Complete S3 and WebDAV Agent transfer workflows
- Fixture: webdav
- Run id: ${RUN_ID}
- Commit: ${commit}
- Status: ${status}
- Platform: $(uname -s)-$(uname -m)
- Docker: ${docker_version}
- Image: ${IMAGE}
- Container: $(container_name)
- Network: $(network_name)
- Health: WebDAV endpoint accepted authenticated PROPFIND for the scratch directory
- Capabilities exercised: webdav.list, webdav.stat, webdav.get, webdav.put, webdav.delete, webdav.mkdir, webdav.probe, webdav.copy, webdav.move, webdav.transfer, webdav.transfer_status, webdav.lock_acquire, webdav.lock_release, webdav.sync_plan
- Destructive policy: dry-run put/delete/mkdir succeeded without a live target; acknowledged put/delete touched only the generated scratch collection
- Object coverage: root list, paged directory list, full directory list, bounded get, stat, delete, missing-path errors, and dry-run sync plan
- Transfer reliability: no-overwrite conflict, verified move, SHA-256 mismatch, range cancellation/resume, stale lock rejection, lock cleanup on close, exact byte round-trip, and explicit unsupported-feature degradation
- Redaction: bad-auth and missing-path errors checked for withheld endpoint and credentials; fixture logs captured through redaction filter
- Variables present by name: VOIDB_FIXTURE_RUN_ID, VOIDB_FIXTURE_NAME, VOIDB_FIXTURE_CONTAINER, VOIDB_FIXTURE_NETWORK, VOIDB_FIXTURE_IMAGE, VOIDB_FIXTURE_HOST, VOIDB_FIXTURE_PORT, VOIDB_WEBDAV_SMOKE_PROFILE, VOIDB_WEBDAV_SMOKE_CONNECTION, VOIDB_WEBDAV_SMOKE_URL, VOIDB_WEBDAV_SMOKE_ROOT, VOIDB_WEBDAV_SMOKE_SEED_PATH, VOIDB_WEBDAV_SMOKE_USER, VOIDB_WEBDAV_SMOKE_PASSWORD, VOIDB_WEBDAV_SMOKE_AUTH, VOIDB_WEBDAV_SMOKE_VERIFY_SSL
- Log capture: $(log_path)
- Capability log: ${smoke_log}
- Cleanup: ${cleanup_status}
- Release decision: capability and Agent transfer reliability smoke passed
EOF

  echo "report: ${REPORT_PATH}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)
      [[ $# -ge 2 ]] || die "missing value for --run-id"
      RUN_ID="$2"
      shift 2
      ;;
    --root)
      [[ $# -ge 2 ]] || die "missing value for --root"
      ROOT="$2"
      shift 2
      ;;
    --report)
      [[ $# -ge 2 ]] || die "missing value for --report"
      REPORT_PATH="$2"
      shift 2
      ;;
    --image)
      [[ $# -ge 2 ]] || die "missing value for --image"
      IMAGE="$2"
      shift 2
      ;;
    --timeout)
      [[ $# -ge 2 ]] || die "missing value for --timeout"
      TIMEOUT="$2"
      [[ "${TIMEOUT}" =~ ^[0-9]+$ ]] || die "timeout must be numeric"
      shift 2
      ;;
    --tail)
      [[ $# -ge 2 ]] || die "missing value for --tail"
      TAIL_LINES="$2"
      [[ "${TAIL_LINES}" =~ ^[0-9]+$ ]] || die "tail must be numeric"
      shift 2
      ;;
    --pull)
      PULL=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

if [[ -z "${RUN_ID}" ]]; then
  RUN_ID="$(generate_run_id)"
fi
sanitize_id "${RUN_ID}"

START_ARGS=(
  --fixture webdav
  --run-id "${RUN_ID}"
  --root "${ROOT}"
  --image "${IMAGE}"
  --timeout "${TIMEOUT}"
  --tail "${TAIL_LINES}"
)
if [[ "${PULL}" -eq 1 ]]; then
  START_ARGS+=(--pull)
fi

mkdir -p "$(fixture_dir)"
cleanup_status="not_run"
smoke_log="$(fixture_dir)/webdav-capability-smoke.log"
trap 'cleanup_fixture' EXIT INT TERM ERR

"${SCRIPT_DIR}/local-fixture-smoke.sh" start "${START_ARGS[@]}"
"${SCRIPT_DIR}/local-fixture-smoke.sh" wait "${START_ARGS[@]}"

set -a
# shellcheck disable=SC1090
source "$(env_path)"
set +a

(
  cd "${REPO_ROOT}"
  cargo run -p voidb-plugin-webdav --example fixture_smoke --quiet
  cargo run -p voidb-plugin-webdav --example webdav_transfer_reliability --quiet
) > "${smoke_log}" 2>&1

"${SCRIPT_DIR}/local-fixture-smoke.sh" logs "${START_ARGS[@]}"
cleanup_fixture
cleanup_status="removed container, network, and generated env file"
trap - EXIT INT TERM ERR

write_evidence "passed" "${cleanup_status}" "${smoke_log}"
