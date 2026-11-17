# Songbird environment on Hetzner Cloud: private network, one firewall per host (only the public
# ports its roles need), servers spread across hosts, static private addresses.

terraform {
  required_version = ">= 1.9.0"
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.70"
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

variable "location" {
  type        = string
  description = "Hetzner location, EU only (fsn1, nbg1, hel1)."
  validation {
    condition     = contains(["fsn1", "nbg1", "hel1"], var.location)
    error_message = "EU locations only: fsn1, nbg1, hel1."
  }
}

variable "network_zone" {
  type    = string
  default = "eu-central"
}

variable "server_types" {
  type        = map(string)
  description = "Size class => Hetzner server type."
}

variable "image" {
  type    = string
  default = "debian-13"
}

variable "ssh_public_key" {
  type = string
}

locals {
  env    = var.topology.environment
  labels = { songbird-env = local.env, managed-by = "opentofu" }
}

resource "hcloud_ssh_key" "deploy" {
  name       = "songbird-${local.env}-deploy"
  public_key = var.ssh_public_key
  labels     = local.labels
}

resource "hcloud_network" "private" {
  name     = "songbird-${local.env}"
  ip_range = var.topology.private_cidr
  labels   = local.labels
}

resource "hcloud_network_subnet" "hosts" {
  network_id   = hcloud_network.private.id
  type         = "cloud"
  network_zone = var.network_zone
  ip_range     = var.topology.subnet_cidr
}

resource "hcloud_placement_group" "spread" {
  name   = "songbird-${local.env}"
  type   = "spread"
  labels = local.labels
}

resource "hcloud_firewall" "host" {
  for_each = var.topology.hosts
  name     = "songbird-${local.env}-${each.key}"
  labels   = local.labels

  # Path MTU discovery and diagnostics.
  rule {
    direction   = "in"
    protocol    = "icmp"
    source_ips  = ["0.0.0.0/0", "::/0"]
    description = "icmp"
  }

  dynamic "rule" {
    for_each = each.value.rules
    content {
      direction   = "in"
      protocol    = rule.value.protocol
      port        = rule.value.port
      source_ips  = rule.value.sources
      description = rule.value.description
    }
  }
}

resource "hcloud_server" "host" {
  for_each           = var.topology.hosts
  name               = "songbird-${local.env}-${each.key}"
  server_type        = var.server_types[each.value.class]
  image              = var.image
  location           = var.location
  ssh_keys           = [hcloud_ssh_key.deploy.id]
  placement_group_id = hcloud_placement_group.spread.id
  firewall_ids       = [hcloud_firewall.host[each.key].id]
  user_data          = var.topology.cloud_init
  labels             = merge(local.labels, { songbird-host = each.key })

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  network {
    network_id = hcloud_network.private.id
    ip         = each.value.private_ip
  }

  depends_on = [hcloud_network_subnet.hosts]

  lifecycle {
    # A new image or user_data must not silently replace a running data host.
    ignore_changes = [image, user_data, ssh_keys]
  }
}

# A second public IPv4 on every calls host, for TURN/TLS on 443 beside signalling on 443 (D-0085
# §4). Ansible adds it to the interface.
resource "hcloud_floating_ip" "turn" {
  for_each      = { for name, h in var.topology.hosts : name => h if contains(h.roles, "calls") }
  type          = "ipv4"
  name          = "songbird-${local.env}-${each.key}-turn"
  home_location = var.location
  server_id     = hcloud_server.host[each.key].id
  labels        = local.labels
}

output "inventory" {
  description = "Host name => addresses and roles, consumed by deploy/ansible."
  value = {
    for name, h in var.topology.hosts : name => {
      public_ipv4 = hcloud_server.host[name].ipv4_address
      turn_ipv4   = try(hcloud_floating_ip.turn[name].ip_address, null)
      private_ip  = h.private_ip
      fqdn        = h.fqdn
      roles       = h.roles
    }
  }
}
