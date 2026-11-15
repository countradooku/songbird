# GitHub setup scripts

Re-runnable setup for `songbirdchat/songbird`. Both scripts check what exists before changing anything.

- `gen.py <input_dir> <repo_dir> <out.json>`: splits `PROMPT_SET.md` into `docs/prompts/NN-<slug>.md`,
  copies `MASTER_BUILD_PROMPT.md` to `docs/prompts/02a-realtime-master.md` (links rewritten), and writes
  the epic issue specs to `out.json`. The two source files are kept outside the repository.
- `setup.py <out.json>`: security settings, branch protection, labels, milestones, epics, issue
  dependencies, the pinned "Start here" issue and the "Songbird Backend" project board.
  Needs `gh` logged in as the owner with the `project` scope (`gh auth refresh -s project`).
