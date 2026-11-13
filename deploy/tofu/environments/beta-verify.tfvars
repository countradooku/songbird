# Daily restore verification of beta's backups (D-0040): one small server in an environment of
# its own, with no route to beta's private network. It holds the identity that can decrypt
# backups and a key that can only read them; production holds neither.
environment = "beta-verify"
hosts = {
  verify-1 = { roles = ["bastion", "verify"], class = "small", index = 0 }
}
