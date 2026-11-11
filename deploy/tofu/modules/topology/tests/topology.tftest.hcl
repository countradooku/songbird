# tofu test: topology rules (no provider, no credentials).

variables {
  environment = "staging"
  admin_cidrs = ["198.51.100.0/24"]
  hosts = {
    bastion-1 = { roles = ["bastion"], class = "small", index = 0 }
    edge-1    = { roles = ["edge"], class = "medium", index = 1 }
    data-1    = { roles = ["data"], class = "large", index = 2 }
  }
}

run "addresses_and_rules" {
  command = plan

  assert {
    condition     = output.hosts["bastion-1"].private_ip == "10.42.1.10"
    error_message = "private IP is .10 + index"
  }
  assert {
    condition     = output.hosts["edge-1"].fqdn == "edge-1.staging.songbird.internal"
    error_message = "internal FQDN"
  }
  assert {
    condition     = length(output.hosts["data-1"].rules) == 0
    error_message = "data hosts expose no public port"
  }
  assert {
    condition     = output.hosts["edge-1"].rules[0].port == "443" && length(output.hosts["edge-1"].rules) == 1
    error_message = "edge exposes only 443"
  }
  assert {
    condition     = output.hosts["bastion-1"].rules[0].sources == ["198.51.100.0/24"]
    error_message = "ssh only from the admin range"
  }
}

run "rejects_ssh_from_everywhere" {
  command = plan
  variables {
    admin_cidrs = ["0.0.0.0/0"]
  }
  expect_failures = [var.admin_cidrs]
}

run "requires_exactly_one_bastion" {
  command = plan
  variables {
    hosts = { edge-1 = { roles = ["edge"], class = "small", index = 0 } }
  }
  expect_failures = [var.hosts]
}

run "rejects_unknown_roles" {
  command = plan
  variables {
    hosts = { bastion-1 = { roles = ["bastion", "database"], class = "small", index = 0 } }
  }
  expect_failures = [var.hosts]
}

run "adding_a_host_keeps_existing_addresses" {
  command = plan
  variables {
    hosts = {
      aaa-1     = { roles = ["worker"], class = "small", index = 7 }
      bastion-1 = { roles = ["bastion"], class = "small", index = 0 }
      edge-1    = { roles = ["edge"], class = "medium", index = 1 }
      data-1    = { roles = ["data"], class = "large", index = 2 }
    }
  }
  assert {
    condition = (
      output.hosts["bastion-1"].private_ip == "10.42.1.10" &&
      output.hosts["edge-1"].private_ip == "10.42.1.11" &&
      output.hosts["data-1"].private_ip == "10.42.1.12" &&
      output.hosts["aaa-1"].private_ip == "10.42.1.17"
    )
    error_message = "a new host that sorts first must not move any existing host"
  }
}

run "rejects_duplicate_indices" {
  command = plan
  variables {
    hosts = {
      bastion-1 = { roles = ["bastion"], class = "small", index = 0 }
      edge-1    = { roles = ["edge"], class = "medium", index = 0 }
    }
  }
  expect_failures = [var.hosts]
}
