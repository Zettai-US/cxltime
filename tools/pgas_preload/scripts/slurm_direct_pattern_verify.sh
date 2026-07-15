#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SPLASH_ROOT="$(cd -- "${ROOT_DIR}/../../../.." && pwd)"
JOBID="${PGAS_JOB_ID:-${SLURM_JOB_ID:-}}"
RUN_DIR="${PGAS_CONFIG_OUT:-}"
TARGET_IDX="${PGAS_TARGET_IDX:-1}"
READER_IDX="${PGAS_READER_IDX:-2}"
PORT="${PGAS_CXLMEMSIM_PORT:-9999}"

if [[ -z "${JOBID}" || -z "${RUN_DIR}" ]]; then
    echo "Usage: PGAS_JOB_ID=<jobid> PGAS_CONFIG_OUT=<run_dir> $0" >&2
    exit 2
fi

NODES_TSV="${RUN_DIR}/nodes.tsv"
SRC="${ROOT_DIR}/regression/cxlmemsim_direct_pattern_verify.c"
CLIENT_SRC="${SPLASH_ROOT}/src/libpgas/src/cxlmemsim_client.c"
INCLUDE_DIR="${SPLASH_ROOT}/src/libpgas/include"
BIN="${RUN_DIR}/cxlmemsim_direct_pattern_verify.arm64"
LOG_DIR="${RUN_DIR}/direct_pattern_verify"

[[ -f "${NODES_TSV}" ]] || { echo "Missing ${NODES_TSV}" >&2; exit 3; }
[[ -f "${SRC}" ]] || { echo "Missing ${SRC}" >&2; exit 3; }
[[ -f "${CLIENT_SRC}" ]] || { echo "Missing ${CLIENT_SRC}" >&2; exit 3; }

lookup_field() {
    local idx="$1"
    local field="$2"
    awk -v idx="${idx}" -v field="${field}" \
        'BEGIN { FS="\t" } NR > 1 && $1 == idx { print $field; exit }' \
        "${NODES_TSV}"
}

target_host="$(lookup_field "${TARGET_IDX}" 2)"
target_ip="$(lookup_field "${TARGET_IDX}" 3)"
target_range_base="$(lookup_field "${TARGET_IDX}" 7)"
reader_host="$(lookup_field "${READER_IDX}" 2)"

if [[ -z "${target_host}" || -z "${target_ip}" ||
      -z "${target_range_base}" || -z "${reader_host}" ]]; then
    echo "Unable to resolve target or reader from ${NODES_TSV}" >&2
    exit 4
fi

printf -v test_addr '0x%x' "$((target_range_base + 0x00100000 + 0x4000))"
mkdir -p "${LOG_DIR}"

echo "Compiling direct ARM verifier on ${reader_host}"
if ! srun --overlap --jobid="${JOBID}" -N1 -n1 -w "${reader_host}" \
    gcc -O2 -I"${INCLUDE_DIR}" "${SRC}" "${CLIENT_SRC}" \
        -pthread -o "${BIN}"; then
    echo "ARM compilation failed" >&2
    exit 5
fi
chmod u+x "${BIN}"
file "${BIN}"

log="${LOG_DIR}/reader_${READER_IDX}_${reader_host}_from_${TARGET_IDX}_${target_host}.log"
echo "Direct reader: ${reader_host} <- ${target_host} (${target_ip}), addr=${test_addr}"

srun --overlap --jobid="${JOBID}" -N1 -n1 -w "${reader_host}" \
    env -u LD_PRELOAD "${BIN}" "${target_ip}" "${PORT}" "${test_addr}" \
    >"${log}" 2>&1
reader_rc=$?

echo "================ ${log} ================"
sed -n '1,160p' "${log}"
echo "direct_reader_rc=${reader_rc}"
echo "DIRECT_VERIFY_LOG_DIR=${LOG_DIR}"

if (( reader_rc == 0 )); then
    echo "DIRECT_OCEAN_PERSISTENCE_PASS"
    exit 0
fi

echo "DIRECT_OCEAN_PERSISTENCE_FAIL"
exit 1
