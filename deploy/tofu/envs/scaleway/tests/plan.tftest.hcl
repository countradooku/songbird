# tofu test: the full scaleway environment plans with a mocked provider (no credentials, nothing
# created). Proves the topology -> provider wiring for both shapes (beta and staging).

mock_provider "scaleway" {}

variables {
  state_passphrase = "test-passphrase-not-used-for-anything-real"
  ssh_public_key   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq5Yv7S7qkJYm8bm5Zg2VkHqgq0nTnU9H6xW3h4nY0k test"
  admin_cidrs      = ["198.51.100.0/24"]
  region           = "fr-par"
  zone             = "fr-par-2"
  server_types     = { small = "PRO2-XXS", medium = "PRO2-S", large = "PRO2-M" }
}

run "beta_single_server" {
  command = plan
  variables {
    environment = "beta"
    hosts       = { core-1 = { roles = ["bastion", "edge", "calls", "data", "worker"], class = "large", index = 0 } }
  }
  assert {
    condition     = length(output.inventory) == 1 && output.inventory["core-1"].private_ip == "10.42.1.10"
    error_message = "one host with a static private address"
  }
}

run "staging_shape" {
  command = plan
  variables {
    environment = "staging"
    hosts = {
      bastion-1 = { roles = ["bastion"], class = "small", index = 0 }
      edge-1    = { roles = ["edge"], class = "medium", index = 1 }
      edge-2    = { roles = ["edge"], class = "medium", index = 2 }
      calls-1   = { roles = ["calls"], class = "medium", index = 3 }
      data-1    = { roles = ["data"], class = "large", index = 4 }
      worker-1  = { roles = ["worker"], class = "small", index = 5 }
    }
  }
  assert {
    condition     = length(output.inventory) == 6
    error_message = "six hosts"
  }
  assert {
    condition     = contains(output.inventory["data-1"].roles, "data")
    error_message = "roles carried to the inventory"
  }
}
