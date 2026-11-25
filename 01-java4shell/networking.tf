# ================================================================================
# Networking
# One VNet with a single private subnet for the three lab nodes. The subnet has
# Azure's default outbound access turned off, so the ONLY way out is the NAT
# gateway below, and nothing has a public IP. Nothing comes in at all: the
# operator reaches the nodes through Azure Run Command, which the VM agent
# collects over its own outbound connection.
#
#   10.0.0.0/24   VNet
#   10.0.0.0/26   nodes subnet (private, NAT egress only)
# ================================================================================

resource "azurerm_virtual_network" "main" {
  name                = "${local.name}-vnet"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  address_space       = ["10.0.0.0/24"]
}

resource "azurerm_subnet" "nodes" {
  name                 = "${local.name}-nodes"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.0.0/26"]

  # No implicit internet egress: outbound must go through the NAT gateway.
  default_outbound_access_enabled = false
}

# ================================================================================
# NAT Gateway — egress for apt, the Corretto JDK downloads, and the VM agent
# (which is how Run Command reaches the nodes). Outbound only; a NAT gateway
# never accepts inbound connections.
# ================================================================================

resource "azurerm_public_ip" "nat" {
  name                = "${local.name}-nat-ip"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_nat_gateway" "main" {
  name                = "${local.name}-nat"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  sku_name            = "Standard"
}

resource "azurerm_nat_gateway_public_ip_association" "main" {
  nat_gateway_id       = azurerm_nat_gateway.main.id
  public_ip_address_id = azurerm_public_ip.nat.id
}

resource "azurerm_subnet_nat_gateway_association" "nodes" {
  subnet_id      = azurerm_subnet.nodes.id
  nat_gateway_id = azurerm_nat_gateway.main.id
}
