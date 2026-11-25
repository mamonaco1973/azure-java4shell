# ================================================================================
# Lab Nodes
# Three standalone VMs — no scale set, because this lab is about comparing
# three fixed, individually-identifiable machines, not elasticity. Every node
# installs ALL THREE affected trains (17 / 21 / 25); only the CPU differs, which
# is the whole lesson:
#
#   vuln-x86     Standard_D2s_v6     x86-64 AVX-512 VBMI   -> EXPOSED
#   safe-arm     Standard_D2pls_v6   ARM64 (no VBMI)       -> NOT EXPOSED (CPU-immune)
#   safe-intel   Standard_B1s        x86-64 without VBMI   -> NOT EXPOSED (CPU-immune)
#
# All three are described once in local.nodes (locals.tf); this file just
# iterates that map so adding or resizing a node is a one-line change there.
#
# Each node's cloud-init script is the shared template rendered with that
# node's values, through templatefile() rather than three near-identical
# copies — the nodes differ only in architecture, their JDK list, and the
# expected verdict, so a single reviewed template avoids drift.
# ================================================================================

# Azure insists on an SSH key or a password for every Linux VM. This key is
# never output or used: the NSG blocks port 22 along with everything else.
resource "tls_private_key" "unused" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Private NIC — no public IP. Run Command is the only way in.
resource "azurerm_network_interface" "node" {
  for_each = local.nodes

  name                = "${local.name}-${each.key}-nic"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.nodes.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "node" {
  for_each = local.nodes

  name                  = "${local.name}-${each.key}"
  computer_name         = each.key
  location              = azurerm_resource_group.lab.location
  resource_group_name   = azurerm_resource_group.lab.name
  size                  = each.value.size
  network_interface_ids = [azurerm_network_interface.node[each.key].id]
  disk_controller_type  = each.value.disk_ctl

  admin_username                  = "azureuser"
  disable_password_authentication = true

  admin_ssh_key {
    username   = "azureuser"
    public_key = tls_private_key.unused.public_key_openssh
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = 30
  }

  source_image_reference {
    publisher = each.value.image.publisher
    offer     = each.value.image.offer
    sku       = each.value.image.sku
    version   = each.value.image.version
  }

  # Do not boot until egress exists. With default outbound access off, a node
  # that starts before the NAT gateway is attached to its subnet has no route
  # out, and cloud-init's apt and JDK downloads would fail.
  depends_on = [
    azurerm_subnet_nat_gateway_association.nodes,
    azurerm_nat_gateway_public_ip_association.main,
    azurerm_subnet_network_security_group_association.nodes,
  ]

  # Cloud-init runs this script on first boot. The full check-exposure.sh
  # detector is injected into it; the rendered result stays well under Azure's
  # 64 KB custom_data limit, so no compression is needed.
  custom_data = base64encode(templatefile(
    "${path.module}/scripts/custom-data.sh.tftpl", {
      node_role        = each.value.role
      expected_verdict = each.value.expected
      expected_reason  = each.value.reason
      arch             = each.value.arch
      decoder_major    = local.decoder_major
      decoder_port     = var.decoder_port
      deployment_name  = local.name
      # All three affected trains this node installs, one per line as
      # "major|version|url"; the script loops over it and installs each.
      jdks = join("\n", [for j in each.value.jdks : "${j.major}|${j.version}|${j.url}"])
      # The portable detector, injected verbatim so the node runs the exact
      # same script we ship in the repo and viewers run on their own hosts.
      detector = file("${path.module}/../check-exposure.sh")
  }))

  tags = {
    Role            = each.value.role
    Lab             = "java4shell"
    CVE             = "CVE-2026-114938"
    ExpectedVerdict = each.value.expected
  }
}
