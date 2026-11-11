# Songbird environment on Scaleway (France, second EU provider): the same topology as Hetzner.
# Private network with IPAM-reserved static addresses, one security group per host (default drop,
# only the public ports its roles need), instances in a max-availability placement group.

terraform {
  required_version = ">= 1.9.0"
  required_providers {
    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.89"
    }
  }
}

variable "topology" {
  description = "Output of the topology module."
  type = object({
    environment  = string
    private_cidr = string
    subnet_cidr  = string
    cloud_init   = string
    hosts = map(object({
      roles      = list(string)
      class      = string
      private_ip = string
      fqdn       = string
      rules = list(object({
        protocol    = string
        port        = string
        sources     = list(string)
        description = string
      }))
    }))
  })
}

variable "region" {
  type        = string
  description = "Scaleway region, EU only (fr-par, nl-ams, pl-waw)."
  validation {
    condition     = contains(["fr-par", "nl-ams", "pl-waw"], var.region)
    error_message = "EU regions only: fr-par, nl-ams, pl-waw."
  }
}

variable "zone" {
  type        = string
  description = "Zone inside the region, e.g. fr-par-2."
}

variable "server_types" {
  type        = map(string)
  description = "Size class => Scaleway commercial type."
}

variable "image" {
  type    = string
  default = "debian_trixie"
}

variable "ssh_public_key" {
  type = string
}

locals {
  env  = var.topology.environment
  tags = ["songbird-env=${local.env}", "managed-by=opentofu"]
  # Scaleway rules take one source range per rule.
  rules = {
    for name, h in var.topology.hosts : name => flatten([
      for r in h.rules : [for src in r.sources : merge(r, { source = src })]
    ])
  }
}

resource "scaleway_iam_ssh_key" "deploy" {
  name       = "songbird-${local.env}-deploy"
  public_key = var.ssh_public_key
}

resource "scaleway_vpc" "main" {
  name   = "songbird-${local.env}"
  region = var.region
  tags   = local.tags
}

resource "scaleway_vpc_private_network" "private" {
  name   = "songbird-${local.env}"
  vpc_id = scaleway_vpc.main.id
  region = var.region
  tags   = local.tags
  ipv4_subnet {
    subnet = var.topology.subnet_cidr
  }
}

resource "scaleway_ipam_ip" "host" {
  for_each = var.topology.hosts
  address  = each.value.private_ip
  region   = var.region
  tags     = local.tags
  source {
    private_network_id = scaleway_vpc_private_network.private.id
  }
}

resource "scaleway_instance_security_group" "host" {
  for_each                = var.topology.hosts
  name                    = "songbird-${local.env}-${each.key}"
  zone                    = var.zone
  stateful                = true
  inbound_default_policy  = "drop"
  outbound_default_policy = "accept"
  tags                    = local.tags

  inbound_rule {
    action   = "accept"
    protocol = "ICMP"
    ip_range = "0.0.0.0/0"
  }

  dynamic "inbound_rule" {
    for_each = local.rules[each.key]
    content {
      action     = "accept"
      protocol   = upper(inbound_rule.value.protocol)
      port_range = strcontains(inbound_rule.value.port, "-") ? inbound_rule.value.port : "${inbound_rule.value.port}-${inbound_rule.value.port}"
      ip_range   = inbound_rule.value.source
    }
  }
}

resource "scaleway_instance_placement_group" "spread" {
  name        = "songbird-${local.env}"
  zone        = var.zone
  policy_type = "max_availability"
  tags        = local.tags
}

resource "scaleway_instance_ip" "host" {
  for_each = var.topology.hosts
  zone     = var.zone
  tags     = local.tags
}

resource "scaleway_instance_server" "host" {
  for_each           = var.topology.hosts
  name               = "songbird-${local.env}-${each.key}"
  type               = var.server_types[each.value.class]
  image              = var.image
  zone               = var.zone
  ip_id              = scaleway_instance_ip.host[each.key].id
  security_group_id  = scaleway_instance_security_group.host[each.key].id
  placement_group_id = scaleway_instance_placement_group.spread.id
  tags               = concat(local.tags, ["songbird-host=${each.key}"])
  user_data = {
    cloud-init = var.topology.cloud_init
  }

  depends_on = [scaleway_iam_ssh_key.deploy]

  lifecycle {
    ignore_changes = [image, user_data]
  }
}

resource "scaleway_instance_private_nic" "host" {
  for_each           = var.topology.hosts
  server_id          = scaleway_instance_server.host[each.key].id
  private_network_id = scaleway_vpc_private_network.private.id
  ipam_ip_ids        = [scaleway_ipam_ip.host[each.key].id]
  zone               = var.zone
}

output "inventory" {
  description = "Host name => addresses and roles, consumed by deploy/ansible."
  value = {
    for name, h in var.topology.hosts : name => {
      public_ipv4 = scaleway_instance_ip.host[name].address
      private_ip  = h.private_ip
      fqdn        = h.fqdn
      roles       = h.roles
    }
  }
}
