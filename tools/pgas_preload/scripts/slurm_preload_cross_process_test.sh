#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
JOBID="${PGAS_JOB_ID:-${SLURM_JOB_ID:-}}"
RUN_DIR="${PGAS_CONFIG_OUT:-}"
PRELOAD="${PGAS_PRELOAD:-${ROOT_DIR}/build-arm/libpgas_preload.so}"
WRITER_IDX="${PGAS_WRITER_IDX:-0}"
TARGET_IDX="${PGAS_TARGET_IDX:-1}"
READER_IDX="${PGAS_READER_IDX:-2}"
PORT="${PGAS_CXLMEMSIM_PORT:-9999}"

if [[ -z "${JOBID}" || -z "${RUN_DIR}" ]]; then
    echo "Usage: PGAS_JOB_ID=<jobid> PGAS_CONFIG_OUT=<run_dir> $0" >&2
    exit 2
fi

NODES_TSV="${RUN_DIR}/nodes.tsv"
SRC="${ROOT_DIR}/regression/pgas_preload_cross_process_test.c"
BIN="${RUN_DIR}/pgas_preload_cross_process_test.arm64"
LOG_DIR="${RUN_DIR}/preload_cross_process"

[[ -f "${NODES_TSV}" ]] || { echo "Missing ${NODES_TSV}" >&2; exit 3; }
[[ -f "${SRC}" ]] || { echo "Missing ${SRC}" >&2; exit 3; }
[[ -f "${PRELOAD}" ]] || { echo "Missing ${PRELOAD}" >&2; exit 3; }

lookup_field() {
    local idx="$1"
    local field="$2"
    awk -v idx="${idx}" -v field="${field}" \
        'BEGIN { FS="\t" } NR > 1 && $1 == idx { print $field; exit }' \
        "${NODES_TSV}"
}

writer_host="$(lookup_field "${WRITER_IDX}" 2)"
target_host="$(lookup_field "${TARGET_IDX}" 2)"
target_ip="$(lookup_field "${TARGET_IDX}" 3)"
target_range_base="$(lookup_field "${TARGET_IDX}" 7)"
reader_host="$(lookup_field "${READER_IDX}" 2)"
node_count="$(awk 'BEGIN { FS="\t" } NR > 1 { n++ } END { print n }' "${NODES_TSV}")"

if [[ -z "${writer_host}" || -z "${target_host}" || -z "${target_ip}" ||
      -z "${target_range_base}" || -z "${reader_host}" ]]; then
    echo "Unable to resolve writer, target, or reader from ${NODES_TSV}" >&2
    exit 4
fi

printf -v test_base '0x%x' "$((target_range_base + 0x00100000))"
mkdir -p "${LOG_DIR}"

echo "Compiling ARM test on ${writer_host}"
if ! srun --overlap --jobid="${JOBID}" -N1 -n1 -w "${writer_host}" \
    gcc -O2 -fno-builtin-memcpy "${SRC}" -o "${BIN}"; then
    echo "ARM compilation failed" >&2
    exit 5
fi
chmod u+x "${BIN}"
file "${BIN}"

writer_log="${LOG_DIR}/writer_${WRITER_IDX}_${writer_host}_to_${TARGET_IDX}_${target_host}.log"
reader_log="${LOG_DIR}/reader_${READER_IDX}_${reader_host}_from_${TARGET_IDX}_${target_host}.log"

echo "Writer: ${writer_host} -> ${target_host} (${target_ip}), base=${test_base}"
srun --overlap --jobid="${JOBID}" -N1 -n1 -w "${writer_host}" \
    env LD_PRELOAD="${PRELOAD}" \
        PGAS_NODE_ID="${WRITER_IDX}" PGAS_NUM_NODES="${node_count}" \
        PGAS_BASE_ADDR="${test_base}" PGAS_SIZE=65536 \
        CXL_MEMSIM_HOST="${target_ip}" CXL_MEMSIM_PORT="${PORT}" \
        PGAS_STALKER=0 PGAS_VERBOSE=1 PGAS_STATS=1 \
        "${BIN}" write >"${writer_log}" 2>&1
writer_rc=$?

echo "Reader: ${reader_host} <- ${target_host} (${target_ip}), base=${test_base}"
srun --overlap --jobid="${JOBID}" -N1 -n1 -w "${reader_host}" \
    env LD_PRELOAD="${PRELOAD}" \
        PGAS_NODE_ID="${READER_IDX}" PGAS_NUM_NODES="${node_count}" \
        PGAS_BASE_ADDR="${test_base}" PGAS_SIZE=65536 \
        CXL_MEMSIM_HOST="${target_ip}" CXL_MEMSIM_PORT="${PORT}" \
        PGAS_STALKER=0 PGAS_VERBOSE=1 PGAS_STATS=1 \
        "${BIN}" read >"${reader_log}" 2>&1
reader_rc=$?

echo "================ ${writer_log} ================"
sed -n '1,160p' "${writer_log}"
echo "================ ${reader_log} ================"
sed -n '1,160p' "${reader_log}"
echo "writer_rc=${writer_rc}"
echo "reader_rc=${reader_rc}"
echo "CROSS_PROCESS_LOG_DIR=${LOG_DIR}"

if (( writer_rc == 0 && reader_rc == 0 )); then
    echo "CROSS_PROCESS_PRELOAD_PASS"
    exit 0
fi

echo "CROSS_PROCESS_PRELOAD_FAIL"
exit 1
