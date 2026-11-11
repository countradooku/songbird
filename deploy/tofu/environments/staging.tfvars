# Staging: the production shape at minimum size, used for rollouts and the provider-switch drill.
environment = "staging"
hosts = {
  bastion-1 = { roles = ["bastion"], class = "small", index = 0 }
  edge-1    = { roles = ["edge"], class = "medium", index = 1 }
  edge-2    = { roles = ["edge"], class = "medium", index = 2 }
  calls-1   = { roles = ["calls"], class = "medium", index = 3 }
  data-1    = { roles = ["data"], class = "large", index = 4 }
  worker-1  = { roles = ["worker"], class = "small", index = 5 }
}
