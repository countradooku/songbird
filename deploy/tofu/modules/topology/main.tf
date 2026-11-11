# Provider-independent description of a Songbird environment: hosts, roles, private addresses and
# the public firewall rules each role needs. Both provider modules consume this, so an environment
# is the same at Hetzner and at Scaleway apart from provider variables (regions, machine types,
# images).

variable "environment" {
  type        = string
  description = "Environment name, e.g. staging."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.environment))
    error_message = "environment must be 2-21 chars of [a-z0-9-], starting with a letter."
  }
}

variable "hosts" {
  description = <<-EOT
    Host name => roles, size class and address index. Roles: bastion, edge, calls, data, worker.
    `index` fixes the host's private address (subnet host number 10 + index). It must never change
    for an existing host: a new address replaces the server. Give new hosts unused indices.
  EOT
  type = map(object({
    roles = list(string)
    class = string
    index = number
  }))
  validation {
    condition = alltrue([
      for h in values(var.hosts) : h.index == floor(h.index) && h.index >= 0 && h.index <= 200
    ])
    error_message = "index must be an integer in 0..200."
  }
  validation {
    condition     = length(distinct([for h in values(var.hosts) : h.index])) == length(var.hosts)
    error_message = "Every host needs a distinct index."
  }
  validation {
    condition = alltrue([
      for h in values(var.hosts) : alltrue([
        for r in h.roles : contains(["bastion", "edge", "calls", "data", "worker"], r)
      ])
    ])
    error_message = "Unknown role. Allowed: bastion, edge, calls, data, worker."
  }
  validation {
    condition     = alltrue([for h in values(var.hosts) : contains(["small", "medium", "large"], h.class)])
    error_message = "class must be small, medium or large."
  }
  validation {
    condition     = length([for h in values(var.hosts) : h if contains(h.roles, "bastion")]) == 1
    error_message = "Exactly one host must have the bastion role (the only SSH entry point)."
  }
  validation {
    condition     = alltrue([for n in keys(var.hosts) : can(regex("^[a-z][a-z0-9-]{1,30}$", n))])
    error_message = "Host names must be [a-z][a-z0-9-]{1,30}."
  }
}

variable "private_cidr" {
  type        = string
  default     = "10.42.0.0/16"
  description = "Private network range. Internal services listen only here."
}

variable "subnet_cidr" {
  type    = string
  default = "10.42.1.0/24"
}

variable "admin_cidrs" {
  type        = list(string)
  description = "Source ranges allowed to reach the bastion over SSH. Empty means no SSH at all."
  validation {
    condition     = alltrue([for c in var.admin_cidrs : can(cidrhost(c, 0)) && c != "0.0.0.0/0" && c != "::/0"])
    error_message = "admin_cidrs must be specific ranges, never the whole internet."
  }
}

locals {
  # Public, client-facing ports per role. Everything else is closed at the provider firewall and
  # again on the host (nftables, deploy/ansible/roles/firewall).
  role_rules = {
    bastion = [for c in var.admin_cidrs : { protocol = "tcp", port = "22", sources = [c], description = "ssh from admin range" }]
    edge = [
      { protocol = "tcp", port = "443", sources = ["0.0.0.0/0", "::/0"], description = "delivery (WSS) and api (HTTPS)" },
    ]
    calls = [
      { protocol = "tcp", port = "7881", sources = ["0.0.0.0/0", "::/0"], description = "LiveKit ICE/TCP" },
      { protocol = "udp", port = "3478", sources = ["0.0.0.0/0", "::/0"], description = "LiveKit TURN/UDP" },
      { protocol = "tcp", port = "5349", sources = ["0.0.0.0/0", "::/0"], description = "LiveKit TURN/TLS" },
      { protocol = "udp", port = "50000-60000", sources = ["0.0.0.0/0", "::/0"], description = "LiveKit media" },
    ]
    data   = []
    worker = []
  }

  hosts = {
    for name, h in var.hosts : name => {
      roles      = h.roles
      class      = h.class
      private_ip = cidrhost(var.subnet_cidr, 10 + h.index)
      fqdn       = "${name}.${var.environment}.songbird.internal"
      rules      = flatten([for r in h.roles : local.role_rules[r]])
    }
  }
}

output "environment" {
  value = var.environment
}

output "hosts" {
  description = "Host name => roles, class, private IP, internal FQDN and public firewall rules."
  value       = local.hosts
}

output "private_cidr" {
  value = var.private_cidr
}

output "subnet_cidr" {
  value = var.subnet_cidr
}

output "cloud_init" {
  description = "Minimal first-boot configuration; Ansible does the rest."
  value       = <<-EOT
    #cloud-config
    ssh_pwauth: false
    disable_root: false
    package_update: true
    packages: [python3, nftables]
    write_files:
      - path: /etc/ssh/sshd_config.d/10-songbird.conf
        content: |
          PasswordAuthentication no
          KbdInteractiveAuthentication no
          PermitRootLogin prohibit-password
          AllowTcpForwarding yes
          X11Forwarding no
  EOT
}

terraform {
  required_version = ">= 1.9.0"
}
