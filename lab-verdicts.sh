#!/bin/bash
set -euo pipefail

# ================================================================================
# lab-verdicts.sh — report each node's live CVE-2026-114938 verdict
#
# Usage:
#   ./lab-verdicts.sh                 # all three nodes
#   ./lab-verdicts.sh vuln-x86          # one (or several) named nodes
#
# For each node it runs the on-box /opt/java4shell/exposure-check.sh over Azure
# Run Command and prints the result. This is only the operator fan-out: the
# verdict comes from the portable check-exposure.sh detector on each node.
# Nothing is reached over the network — everything goes through the Azure VM
# agent's outbound channel.
# ================================================================================

CHDIR="01-java4shell"
POLL=10
TIMEOUT=300

RG=$(terraform -chdir="$CHDIR" output -raw resource_group 2>/dev/null || true)
if [ -z "${RG}" ]; then
  echo "ERROR: could not read Terraform outputs. Run ./apply.sh first."
  exit 1
fi

NODE_IDS_JSON=$(terraform -chdir="$CHDIR" output -json node_ids)

# Roles to check: args if given, else all keys in the output (stable order).
if [ "$#" -gt 0 ]; then
  ROLES=("$@")
else
  mapfile -t ROLES < <(echo "${NODE_IDS_JSON}" | jq -r 'keys_unsorted[]')
fi

# Wait until a node's Azure VM agent reports Ready; Run Command goes through it.
wait_online() {
  local vm="$1" elapsed=0 status
  while true; do
    status=$(az vm get-instance-view --resource-group "${RG}" --name "${vm}" \
      --query 'instanceView.vmAgent.statuses[0].displayStatus' --output tsv 2>/dev/null || echo "None")
    [ "${status}" = "Ready" ] && return 0
    elapsed=$((elapsed + POLL))
    [ "${elapsed}" -ge "${TIMEOUT}" ] && return 1
    sleep "${POLL}"
  done
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

printf '\n%-14s %-12s %-10s %-6s %-6s %s\n' "NODE" "VERDICT" "JAVA" "ARCH" "VBMI" "REASON"
printf -- '---------------------------------------------------------------------------------------\n'

rc=0
for role in "${ROLES[@]}"; do
  id=$(echo "${NODE_IDS_JSON}" | jq -r --arg r "${role}" '.[$r] // empty')
  if [ -z "${id}" ]; then
    printf '%-14s %s\n' "${role}" "ERROR: unknown node (not in this deployment)"
    rc=1
    continue
  fi

  if ! wait_online "${id}"; then
    printf '%-14s %s\n' "${role}" "ERROR: VM agent not Ready after ${TIMEOUT}s (${id})"
    rc=1
    continue
  fi

  out=$(run_onbox "${id}" "/opt/java4shell/exposure-check.sh")
  verdict=$(echo "${out}" | sed -n 's/^VERDICT=//p')
  java=$(echo "${out}"    | sed -n 's/^JAVA_VERSION=//p')
  arch=$(echo "${out}"    | sed -n 's/^ARCH=//p')
  vbmi=$(echo "${out}"    | sed -n 's/^AVX512_VBMI=//p')
  reason=$(echo "${out}"  | sed -n 's/^REASON=//p')

  printf '%-14s %-12s %-10s %-6s %-6s %s\n' \
    "${role}" "${verdict:-?}" "${java:-?}" "${arch:-?}" "${vbmi:-?}" "${reason:-?}"

  # Per-JDK breakdown: JVM|installed|<home>|<version>|<verdict>|<reason>
  echo "${out}" | sed -n 's/^JVM|installed|[^|]*|\([^|]*\)|\([^|]*\)|.*/                 \1  ->  \2/p'
done

echo ""
exit "${rc}"
