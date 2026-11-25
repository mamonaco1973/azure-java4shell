# ================================================================================
# Network Security Group
# One group on the nodes subnet. Azure's default rules allow inbound traffic
# from anywhere in the VNet, so an explicit deny overrides them: nothing, not
# even another VM in the VNet, can open a connection to these nodes. Operator
# access is exclusively through Azure Run Command, which the VM agent fetches
# as an OUTBOUND connection, so it needs no inbound rule.
#
# The sample Base64 decode service and the verdict page listen on the nodes
# but are reached only from the node itself, over Run Command (curl localhost).
#
# This closed posture is deliberate for an intentionally-vulnerable lab: the
# only thing that should ever drive the vulnerable decoder is your own PoC,
# run on the node through Run Command.
# ================================================================================

resource "azurerm_network_security_group" "nodes" {
  name                = "${local.name}-nodes-nsg"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name

  # Overrides the default AllowVnetInBound (65000) and
  # AllowAzureLoadBalancerInBound (65001) rules.
  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # Outbound is left at Azure's defaults (allow): apt, the Corretto downloads
  # and the VM agent all go out through the NAT gateway.
}

resource "azurerm_subnet_network_security_group_association" "nodes" {
  subnet_id                 = azurerm_subnet.nodes.id
  network_security_group_id = azurerm_network_security_group.nodes.id
}
