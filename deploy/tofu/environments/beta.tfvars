# Beta: a single server sized for 20,000 accounts (Prompt 2a), running every role.
environment = "beta"
hosts = {
  core-1 = { roles = ["bastion", "edge", "calls", "data", "worker"], class = "large", index = 0 }
}
