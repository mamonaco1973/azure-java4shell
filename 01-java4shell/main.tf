# ================================================================================
# Provider Configuration
# Pins the AzureRM provider to the 5.x major version. The ~> constraint allows
# minor-version upgrades but blocks 6.x, preventing breaking changes from
# entering the build silently. Credentials come from the ARM_* environment
# variables (check_env.sh confirms they are set).
# ================================================================================

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.0"
    }

    # Supplies the per-deployment name suffix defined in locals.tf
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }

    # Azure requires an SSH key (or password) on every Linux VM. The key is
    # generated, never output, and never used: nothing can reach port 22.
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# ================================================================================
# Resource Group
# Every resource in the lab lives here, so destroy.sh (terraform destroy)
# removes the whole stack in one pass.
# ================================================================================

resource "azurerm_resource_group" "lab" {
  name     = "${local.name}-rg"
  location = var.location

  tags = {
    Lab = "java4shell"
    CVE = "CVE-2026-114938"
  }
}

# ================================================================================
# Images — two architectures
# This lab deliberately mixes architectures: the x86-64 nodes can carry the
# AVX-512 VBMI Base64 intrinsic (where CVE-2026-114938 is reachable), and the
# ARM64 node (Azure Cobalt 100) cannot run it at all. Both are Canonical's
# Ubuntu 24.04 LTS from the Marketplace, always the latest version; the only
# difference is the SKU.
# ================================================================================

locals {
  image_x86 = {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  image_arm = {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server-arm64"
    version   = "latest"
  }
}
