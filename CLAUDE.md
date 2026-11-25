# CLAUDE.md — azure-java4shell

## What This Project Does

An **intentionally vulnerable** educational lab for **CVE-2026-114938**
("Java4Shell"), the AVX-512 `java.util.Base64` decode-intrinsic memory
corruption in OpenJDK. Three Azure VMs demonstrate that exploitability is
CPU-bound: a vulnerable JDK is EXPOSED on an x86-64 AVX-512 VBMI CPU but immune
on ARM64. The repo covers the defensive workflow — exposure detection,
mitigation, and patch verification.

**No exploit code lives here by design.** The repo builds the infrastructure
and the (benign) exposure surface; the user runs the researchers' external PoC
(`calif.io/java4shell`) against their own isolated lab.

## Commands

```bash
./apply.sh                      # check env, terraform init + apply, then validate
./validate.sh                   # wait for boot, print each node's live verdict, with per-JDK rows
./lab-verdicts.sh [node...]     # print live verdict(s) + per-JDK breakdown over Run Command
./patch.sh [node] [train...]    # upgrade a node's JDKs in place to the fixed builds, re-check
                                #   (all 3 trains by default; name trains for a partial/mixed patch)
./destroy.sh                    # teardown
```

## Architecture

Single Terraform phase in `01-java4shell/`, ported from aws-java4shell. No
modules, no workspaces, no Bastion.

- **Region:** Central US (var.location), one resource group per deployment
- **Nodes:** three, one per CPU class, and **every node installs all three
  affected trains (17.0.13 + 21.0.13 + 25.0.5)** arch-matched:
  `vuln-x86` (Standard_D2s_v6, AVX-512 VBMI → EXPOSED, all three JDKs exposed),
  `safe-arm` (Standard_D2pls_v6, Cobalt 100 ARM → immune), `safe-intel`
  (Standard_B1s, x86 without VBMI → immune). Dsv6 sizes are NVMe-only, so that
  node sets `disk_controller_type = "NVMe"` (`local.nodes[*].disk_ctl`). The detector judges every installed JDK (worst-wins), so a
  node's verdict rolls up its per-train verdicts. No pre-patched node;
  `patch.sh` upgrades all three trains on a node live (or a named subset, which
  leaves a mixed EXPOSED host). Defined once in `locals.tf` → `local.trains`
  (the 3 trains) and `local.nodes` (the 3 machines); `var.decoder_train` picks
  which train the decoder runs on (default 21).
- **OS:** Ubuntu 24.04 LTS from Canonical's Marketplace offer `ubuntu-24_04-lts`
  — SKU `server` for the x86 nodes, `server-arm64` for the ARM node.
- **Access:** Azure Run Command only — one private subnet with default outbound
  access off, NAT gateway egress, no public IP, an NSG that denies all inbound
  (overriding Azure's default allow-VNet rule). Azure requires an SSH key on
  Linux VMs; a generated, unused key satisfies it.
- **Exposure surface:** a minimal Java Base64-decode HTTP service
  (`scripts/custom-data.sh.tftpl` writes `Decoder.java`), run as
  `java4shell-decoder.service` on the decoder train's JDK.
- **Verdict:** `/opt/java4shell/exposure-check.sh` (written by cloud-init) is the
  single source of truth; it writes the verdict page + `verdict.json`.
- **Boot log:** `/root/custom-data.log` on each node.

## JDK Sourcing (important)

JDK builds are Amazon Corretto tarballs, pinned by **build string** in
`variables.tf` and assembled into URLs in `locals.tf`:

- `corretto_fixed_build` (default `21.0.13.1.2`) — current, downloads fine.
- `corretto_affected_build` (default `21.0.13.11.1`) — the **vulnerable** build;
  **a best guess that must be verified**, since Amazon is pulling vulnerable
  builds post-patch. Confirm `output affected_jdk_url` returns HTTP 200, or set
  `corretto_affected_url_override` to a self-hosted artifact.

The verdict logic keys off the **upstream** version (`21.0.13` vs `21.0.13.1`),
which is vendor-independent, so changing vendor/build is a one-line edit.

If the affected download fails at boot, the node still comes up over Run Command and its
verdict reads `UNKNOWN` ("JDK INSTALL FAILED"), never a false `NOT_EXPOSED`.

## Instance Access

Private, no SSH, no Bastion. Everything goes through Azure Run Command, which
runs a script as root under /bin/sh and returns stdout and stderr in one
message (`[stdout]` / `[stderr]` sections; the scripts' `run_onbox` keeps
stdout). Each call takes roughly 20–40 s.

```bash
RG=$(terraform -chdir=01-java4shell output -raw resource_group)
terraform -chdir=01-java4shell output -json node_ids     # role -> VM name
az vm run-command invoke -g "$RG" -n <vm name> --command-id RunShellScript \
  --scripts 'curl -s localhost/verdict.json' --query 'value[0].message' -o tsv
```

## Verdict Logic

EXPOSED requires all three: vulnerable JDK (`version < fixed_version`),
AVX-512 VBMI present, and no mitigation flag on the running JVM. A patched JDK
or a missing VBMI intrinsic is NOT_EXPOSED outright; a vulnerable JDK+CPU with
`-XX:-UseBASE64Intrinsics` or `-XX:UseAVX=2` is MITIGATED.

## Multi-Deployment

Every resource name derives from `local.name` (`java4shell-<suffix>`) so the
stack can deploy more than once per subscription. Scripts resolve resources
through `terraform output`, never a hardcoded name. Each concurrent deployment
needs its own state (separate clone or `terraform workspace`).

## Key Files

| File | Purpose |
|------|---------|
| `01-java4shell/main.tf` | providers, resource group, Ubuntu image references (x86, arm64) |
| `01-java4shell/variables.tf` | JDK build strings/URLs, VM sizes, location, ports |
| `01-java4shell/locals.tf` | name suffix, derived Corretto URLs, `local.nodes` map |
| `01-java4shell/instances.tf` | the three VMs and NICs, rendered from the shared cloud-init template |
| `01-java4shell/networking.tf` | VNet, private subnet, NAT gateway |
| `01-java4shell/security.tf` | NSG denying all inbound |
| `01-java4shell/outputs.tf` | resource group, VM names/IPs, expected verdicts, JDK URLs, Run Command hint |
| `01-java4shell/scripts/custom-data.sh.tftpl` | installs Corretto, writes Decoder.java + exposure-check.sh, serves verdict |
