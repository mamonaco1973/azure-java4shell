# ================================================================================
# Outputs
# Resource names carry a per-deployment suffix, so the harness scripts cannot
# look anything up by a hardcoded name. These outputs are how check-exposure.sh,
# patch.sh, validate.sh, and lab-verdicts.sh find the right nodes for THIS
# deployment. Everything is keyed by role name.
# ================================================================================

output "deployment_name" {
  description = "Base name shared by every resource in this deployment"
  value       = local.name
}

output "resource_group" {
  description = "Resource group holding the whole lab"
  value       = azurerm_resource_group.lab.name
}

output "location" {
  description = "Azure region the stack is deployed in"
  value       = azurerm_resource_group.lab.location
}

# Map of role -> VM name, e.g. {"vuln-x86" = "java4shell-k3n8q2-vuln-x86", ...}
# The operator scripts pass these to `az vm run-command invoke`.
output "node_ids" {
  description = "VM name for each lab node, keyed by role"
  value       = { for role, vm in azurerm_linux_virtual_machine.node : role => vm.name }
}

# Map of role -> private IP
output "node_private_ips" {
  description = "Private IP for each lab node, keyed by role"
  value       = { for role, vm in azurerm_linux_virtual_machine.node : role => vm.private_ip_address }
}

# Map of role -> the verdict the lab is designed to produce. patch.sh patches
# the EXPOSED ones by default.
output "node_expected" {
  description = "Intended exposure verdict for each node, keyed by role"
  value       = { for role, node in local.nodes : role => node.expected }
}

# Which train the decoder runs on, and therefore the JDK symlink patch.sh
# repoints to the fixed build.
output "decoder_major" {
  description = "Major version the exposure-surface decoder service runs on"
  value       = local.decoder_major
}

# Map of role -> the AFFECTED JDK list that node installs (major/version/url).
# Print it to confirm every vulnerable build still resolves (HTTP 200) before
# trusting the verdicts. check_env.sh HEAD-checks these before apply.
output "affected_jdks" {
  description = "Affected JDK trains installed on each node (major, version, url)"
  value       = { for role, node in local.nodes : role => node.jdks }
}

# Map of role -> the FIXED JDK list patch.sh installs on that node, arch-matched.
# patch.sh upgrades every train and removes the vulnerable builds.
output "patch_jdks" {
  description = "Fixed Corretto builds patch.sh installs on each node (major, url)"
  value       = local.patch_jdks
}

output "run_command_hint" {
  description = "How to read a node's verdict page over Run Command (no port is exposed)"
  value       = "az vm run-command invoke -g ${azurerm_resource_group.lab.name} -n <vm name> --command-id RunShellScript --scripts 'curl -s localhost/verdict.json' --query 'value[0].message' -o tsv"
}
