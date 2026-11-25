#!/bin/bash
set -euo pipefail

# ================================================================================
# Environment Check
# Validates required tools are installed and Azure credentials are active. This
# lab drives the nodes entirely over Azure Run Command, so jq is required (the
# operator scripts parse Terraform's JSON outputs with it).
# ================================================================================

echo "NOTE: Validating that required commands are found in your PATH."

for cmd in az terraform jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: $cmd is not found in PATH."
    exit 1
  fi
  echo "NOTE: $cmd is found in the current PATH."
done

echo "NOTE: All required commands are available."

# ------------------------------------------------------------------------------
# Azure Credentials
# Terraform authenticates with the ARM_* service principal variables; the az
# CLI (used by the operator scripts) logs in with the same service principal.
# ------------------------------------------------------------------------------

echo "NOTE: Validating that required environment variables are set."

for var in ARM_CLIENT_ID ARM_CLIENT_SECRET ARM_SUBSCRIPTION_ID ARM_TENANT_ID; do
  if [ -z "${!var:-}" ]; then
    echo "ERROR: $var is not set or is empty."
    exit 1
  fi
  echo "NOTE: $var is set."
done

echo "NOTE: Logging in to Azure using Service Principal..."
if ! az login --service-principal --username "$ARM_CLIENT_ID" \
    --password "$ARM_CLIENT_SECRET" --tenant "$ARM_TENANT_ID" > /dev/null 2>&1; then
  echo "ERROR: Failed to log into Azure. Please check your credentials and environment variables."
  exit 1
fi
az account set --subscription "$ARM_SUBSCRIPTION_ID"

echo "NOTE: Successfully logged into Azure."

# ------------------------------------------------------------------------------
# Corretto build preflight (WARNING only, never blocks apply)
# The nodes download pinned Corretto builds, and Amazon can pull a vulnerable
# build from the public archive at any time (that is how 17.0.21.0.3 vanished,
# leaving a node with no JDK). HEAD-check every affected AND patch build here so
# a pulled build is an obvious warning BEFORE apply — not a silent JAVA=none or
# a patch that never flips. Runs before `terraform init`, so the build strings
# are read from variables.tf defaults rather than Terraform state.
# ------------------------------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
  echo "NOTE: Checking that the pinned Corretto build URLs still resolve."
  VARS="01-java4shell/variables.tf"
  BASE="https://corretto.aws/downloads/resources"

  dflt() { grep -A4 "variable \"$1\"" "$VARS" | grep -m1 'default' \
             | sed 's/.*default *= *"\([^"]*\)".*/\1/'; }
  u() { echo "$BASE/$1/amazon-corretto-$1-linux-$2.tar.gz"; }
  http() { curl -s -o /dev/null -w '%{http_code}' -I --max-time 20 "$1" 2>/dev/null || echo 000; }

  AFF=$(dflt corretto_affected_build)
  FIX21=$(dflt corretto_fixed_build)
  AFF17=$(dflt corretto_jdk17_build)
  FIX17=$(dflt corretto_jdk17_fixed_build)
  AFF25=$(dflt corretto_jdk25_build)
  FIX25=$(dflt corretto_jdk25_fixed_build)
  OVERRIDE=$(dflt corretto_affected_url_override)
  AFF_X64_URL="$([ -n "$OVERRIDE" ] && echo "$OVERRIDE" || u "$AFF" x64)"

  warned=0
  check() {  # label  url
    local code
    code=$(http "$2")
    if [ "$code" = "200" ]; then
      echo "NOTE:    ok ($code)  $1"
    else
      echo "WARNING: $1 returned HTTP $code"
      echo "WARNING:   $2"
      echo "WARNING:   build may be pulled - fix the build string in variables.tf or set an override."
      warned=1
    fi
  }

  check "vuln-jdk21 / safe-intel affected (x64)" "$AFF_X64_URL"
  check "safe-arm affected (aarch64)"            "$(u "$AFF" aarch64)"
  check "vuln-jdk17 affected (x64)"              "$(u "$AFF17" x64)"
  check "vuln-jdk25 affected (x64)"              "$(u "$AFF25" x64)"
  check "patch 21 fixed (x64)"                   "$(u "$FIX21" x64)"
  check "patch 17 fixed (x64)"                   "$(u "$FIX17" x64)"
  check "patch 25 fixed (x64)"                   "$(u "$FIX25" x64)"

  if [ "$warned" -eq 0 ]; then
    echo "NOTE: all pinned Corretto builds resolve."
  else
    echo "WARNING: one or more Corretto builds did not resolve (see above)."
    echo "WARNING: apply will continue - affected nodes read UNKNOWN; patch may not flip."
  fi
else
  echo "NOTE: curl not found - skipping the Corretto build-URL preflight."
fi
