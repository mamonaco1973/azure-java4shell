#!/bin/bash
# ===============================================================================
# File: validate.sh
# Waits for the lab to finish booting, then prints each node's LIVE exposure
# verdict, collected over Azure Run Command. Every node carries all three affected trains (17 / 21 / 25); the per-JDK rows
# below each node show the detector judged every one.
#   vuln-x86     EXPOSED       (3 vulnerable JDKs + AVX-512 VBMI CPU)
#   safe-arm     NOT_EXPOSED   (same 3 JDKs, but ARM64 has no VBMI intrinsic)
#   safe-intel   NOT_EXPOSED   (same 3 JDKs, but this Intel chip has no VBMI)
# ===============================================================================

set -uo pipefail

CHDIR="01-java4shell"
POLL=10
TIMEOUT=600
# Cloud-init (package install + JDK download over NAT) runs well past the moment
# the VM agent reports Ready, so it gets its own, more generous budget. The
# detector script is not written until the custom data script finishes, so collecting a
# verdict before this completes reads an empty "?" on every node.
CLOUD_INIT_TIMEOUT=1200

# ------------------------------------------------------------------------------
# Deploy timing — DEPLOY_START is exported by apply.sh so the headline number
# spans apply + boot + JDK install + first verdict. Standalone runs fall back to
# "now", which times only the agent wait and is not comparable to an apply run.
# ------------------------------------------------------------------------------
T_ANCHOR="${DEPLOY_START:-$(date +%s)}"
T_START=$(date +%s)

RG=$(terraform -chdir="$CHDIR" output -raw resource_group 2>/dev/null || true)
if [ -z "${RG}" ]; then
  echo "ERROR: could not read Terraform outputs. Run ./apply.sh first."
  exit 1
fi

DEPLOYMENT=$(terraform -chdir="$CHDIR" output -raw deployment_name)
NODE_IDS_JSON=$(terraform -chdir="$CHDIR" output -json node_ids)
mapfile -t ROLES < <(echo "${NODE_IDS_JSON}" | jq -r 'keys_unsorted[]')

wait_online() {
  local vm="$1" elapsed=0 status
  while true; do
    status=$(az vm get-instance-view --resource-group "${RG}" --name "${vm}" \
      --query 'instanceView.vmAgent.statuses[0].displayStatus' --output tsv 2>/dev/null || echo "None")
    [ "${status}" = "Ready" ] && return 0
    elapsed=$((elapsed + POLL))
    [ "${elapsed}" -ge "${TIMEOUT}" ] && return 1
    echo "NOTE: ${vm} VM agent not ready yet — retrying in ${POLL}s (${elapsed}s)..."
    sleep "${POLL}"
  done
}

wait_cloudinit() {
  # Block until this node's cloud-init script has finished. A Ready VM agent
  # only means Run Command works; the JDK install and the detector script land
  # minutes later. `cloud-init status --wait` returns on done, error or
  # degraded alike, so a failed install still releases the wait (the verdict
  # then reflects it, e.g. UNKNOWN, instead of hanging). One Run Command call
  # can run for up to 90 minutes, so a single blocking call replaces polling.
  local vm="$1" status
  status=$(run_onbox "${vm}" "timeout ${CLOUD_INIT_TIMEOUT} cloud-init status --wait >/dev/null 2>&1; cloud-init status 2>/dev/null | sed -n 's/^status: //p'")
  case "${status}" in
    done|error|degraded|disabled) return 0 ;;
  esac
  return 1
}

# Run a command on a node with Azure Run Command and echo its stdout. Run
# Command returns stdout and stderr together in one message, as
# "[stdout]\n...\n[stderr]\n..."; keep only the stdout section. The script runs
# as root under /bin/sh.
run_onbox() {
  local vm="$1" cmd="$2" msg
  msg=$(az vm run-command invoke --resource-group "${RG}" --name "${vm}" \
    --command-id RunShellScript --scripts "${cmd}" \
    --query 'value[0].message' --output tsv 2>/dev/null) || true
  printf '%s\n' "${msg}" | awk '/^\[stdout\]$/ {on=1; next} /^\[stderr\]$/ {on=0} on'
}

echo "NOTE: Waiting for each node's Azure VM agent to report Ready..."
for role in "${ROLES[@]}"; do
  id=$(echo "${NODE_IDS_JSON}" | jq -r --arg r "${role}" '.[$r]')
  if ! wait_online "${id}"; then
    echo "ERROR: ${role} (${id}) VM agent not Ready after ${TIMEOUT}s."
    exit 1
  fi
done
T_ONLINE=$(date +%s)

# ------------------------------------------------------------------------------
# Each Run Command call takes 20-40 s, so the nodes are checked in parallel:
# one background job per node, each writing to its own file, and a progress
# line as each finishes. TMPDIR_J4S holds the per-node results.
# ------------------------------------------------------------------------------
TMPDIR_J4S=$(mktemp -d)
trap 'rm -rf "${TMPDIR_J4S}"' EXIT

echo "NOTE: Waiting for the custom data script (package + JDK install) to finish on all nodes..."
declare -A JOB_ROLE=()
for role in "${ROLES[@]}"; do
  id=$(echo "${NODE_IDS_JSON}" | jq -r --arg r "${role}" '.[$r]')
  wait_cloudinit "${id}" > "${TMPDIR_J4S}/${role}.ci" 2>&1 &
  JOB_ROLE[$!]="${role}"
done
CI_FAIL=0
for _ in "${ROLES[@]}"; do
  wait -n -p pid
  rc=$?
  role="${JOB_ROLE[$pid]}"
  if [ "${rc}" -eq 0 ]; then
    echo "NOTE: ${role} custom data finished."
  else
    echo "ERROR: ${role} custom data did not finish within ${CLOUD_INIT_TIMEOUT}s."
    echo "       Check /root/custom-data.log on the node over Run Command."
    CI_FAIL=1
  fi
done
[ "${CI_FAIL}" -eq 0 ] || exit 1

echo "NOTE: Collecting exposure verdicts..."
JOB_ROLE=()
for role in "${ROLES[@]}"; do
  id=$(echo "${NODE_IDS_JSON}" | jq -r --arg r "${role}" '.[$r]')
  run_onbox "${id}" "/opt/java4shell/exposure-check.sh" > "${TMPDIR_J4S}/${role}.out" &
  JOB_ROLE[$!]="${role}"
done
for _ in "${ROLES[@]}"; do
  wait -n -p pid
  echo "NOTE: ${JOB_ROLE[$pid]} verdict collected."
done

echo ""
printf '%-12s %-12s %-6s %s\n' "NODE" "VERDICT" "VBMI" "JDKS"
printf -- '---------------------------------------------------------------------------------------\n'

FAIL=0
for role in "${ROLES[@]}"; do
  out=$(cat "${TMPDIR_J4S}/${role}.out")
  got=$(echo "${out}"   | sed -n 's/^VERDICT=//p')
  vbmi=$(echo "${out}"  | sed -n 's/^AVX512_VBMI=//p')
  count=$(echo "${out}" | sed -n 's/^JDK_COUNT=//p')

  # A blank or UNKNOWN verdict means the scan itself failed on that node.
  if [ -z "${got}" ] || [ "${got}" = "UNKNOWN" ]; then
    FAIL=$((FAIL + 1))
  fi
  printf '%-12s %-12s %-6s %s\n' \
    "${role}" "${got:-?}" "${vbmi:-?}" "${count:-?}"

  # Per-JDK breakdown — proves the detector judged every installed train.
  #   JVM|installed|<home>|<version>|<verdict>|<reason>
  echo "${out}" | sed -n 's/^JVM|installed|[^|]*|\([^|]*\)|\([^|]*\)|.*/                 \1  ->  \2/p'

  if [ "${got}" = "UNKNOWN" ]; then
    echo "      ^ JDK install failed on ${role}. A vulnerable Corretto build URL is likely"
    echo "        pulled. Check 'terraform -chdir=${CHDIR} output affected_jdks', confirm each"
    echo "        returns HTTP 200, or set corretto_affected_url_override."
  fi
done

T_DONE=$(date +%s)
echo ""
echo "================================================================================="
echo "  Java4Shell (CVE-2026-114938) — lab validation"
echo "================================================================================="
echo "  Deployment        : ${DEPLOYMENT}"
echo "  Resource group    : ${RG}"
echo "  Nodes checked     : ${#ROLES[@]}"
echo "---------------------------------------------------------------------------------"
echo "  Time to validated : $((T_DONE - T_ANCHOR))s"
if [ -z "${DEPLOY_START:-}" ]; then
  echo "  WARNING: DEPLOY_START unset — timed from validate.sh only. Run ./apply.sh"
  echo "           for the full deploy-to-verdict number."
else
  echo "  VM agent wait     : $((T_ONLINE - T_START))s"
fi
echo "================================================================================="

if [ "${FAIL}" -ne 0 ]; then
  echo "  ERROR: ${FAIL} node(s) returned no verdict — see table above."
  echo "================================================================================="
  exit 1
fi
