# Developing the privacy layer

Read this before changing anything under `privacy/`. The user guide is
`README.md`, and the decision and test log is `PROGRESS.md`, which also has
the next steps. The design drafts in `docs/fork/` are untracked.

## Ground rules

- **Synthetic data only.** Never read, print or copy the owner's real
  identity, `private/`, `documents/` (except its README), `.env` files or
  real CLI logins. Tests use the fixtures in `privacy/tests/fixtures.py` and
  random canaries.
- **The owner's passphrase is never seen.** Use `TEST_PASSPHRASE` in tests;
  the owner runs `identity init` themselves.
- **Upstream files change as little as possible**, to keep upstream sync
  easy. Use one pointer line per spec (`patches/0001-…`) and the fork-owned
  `AGENTS.override.md` (Codex) and `GEMINI.md` (agy). Upstream's
  `tools/check_framework_version.py` fails on any `AGENTS.md` change without
  a version bump, so leave `AGENTS.md` alone. Fork code goes in `privacy/`,
  because `Edit(tools/**)` is an upstream ask rule.
- **Git:** commits and other git commands on `feature/privacy-layer` are
  pre-approved. `git push` and PRs always need the owner's approval.
- **Owner decisions:** `documents/` stays agent-readable. Final PDFs live
  in `private/final/<co_role>/`, plus a link from
  `documents/applications/<co_role>/final`. The tracker is unchanged.
  Copilot is deferred. Runtimes are unranked, with Claude Code first.

## Layout

| Path | Role |
|---|---|
| `identity.py` | file format (`JSID` v1, scrypt N=2^17, AES-256-GCM, header as AAD), tokens, validation |
| `texsubst.py` | token → TeX-escaped value; `\href`/`\url` targets use URL escaping |
| `finalize.py` | copies drafts to `private/.work/`, substitutes, compiles in an offline no-home bwrap jail, checks, installs; all output redacted |
| `migrate.py` | real values → tokens in workspace files |
| `identity_cli.py` | `init`, `check`, `rekey`, `tokens` |
| `launcher/jobsearch.py` | agent jail: see its docstring for the full mount policy |
| `AGENT-RULES.md` | what agents must do; every token must appear here (tested) |
| `dev/jobsearch-gates` | the gate runner (below) |
| `tests/` | unit, build, red-team and patch tests |

## Testing

**Unit layer, anywhere:**
`.venv/bin/python -m unittest discover -s privacy/tests -t .`
The jail, build and red-team tests skip outside the gate.

**The gate runner.** The coding agent's own sandbox forbids user namespaces,
so it cannot run bubblewrap. `privacy/dev/jobsearch-gates` is excluded from
that sandbox and builds its own jail around a fresh clone of the committed
HEAD. It has an empty home, no host `/tmp` and no Windows drives.

| Mode | What it proves | Cost |
|---|---|---|
| `test` | upstream suite plus the privacy suite with nested bwrap; no network | free |
| `e2e CLI` | the real CLI through the launcher cannot read the `private/` canaries; it can still read and write drafts | one model call |
| `rules CLI` | given a synthetic email and phone, the agent writes `ZZEMAILZZ`/`ZZPHONEZZ`, and neither value lands in any file | one model call |
| `creds CLI` | the owner's config denies the CLI's own login file, and a covered canary stays hidden from the file tool and from `cat`/Python in a script; the oracle is on disk or in tool events | one or two model calls |

CLI is `claude`, `codex`, `copilot` or `agy`; `creds` supports
`claude|codex|agy`.

Gate rules learned the hard way:

- **Commit first.** The gate tests HEAD, not the working tree.
- **Run it as its own Bash call:** `jobsearch-gates test`. Only exact
  commands in `.claude/settings.local.json` `sandbox.excludedCommands`
  leave the sandbox. Any pipe, `&&`, redirect or `cd` keeps it sandboxed,
  and it then fails or prints nothing.
- **A runner change only takes effect when the owner reinstalls it.** After
  editing `dev/jobsearch-gates`, ask the owner to review the diff and run
  `install -m 755 privacy/dev/jobsearch-gates ~/.local/bin/jobsearch-gates`.
  A new mode also needs new `excludedCommands` entries, which only the owner
  can write: show them the full `printf` replacement of the file.
- **Test data must live outside `/tmp`.** Every jail replaces it, so tests
  use `.gate-scratch/` (git-ignored).

**Mutation checks.** For a security property, commit a mutant that breaks
it, run `jobsearch-gates test`, expect `GATE FAIL`, then
`git reset --hard HEAD~1`. Killed so far: no fd close, no PID namespace, no
mask, writable root, jail exposes host, no redaction, no home mask, no env
filter.

**Behaviour tests are samples.** LLM runs are not deterministic. One PASS
in `rules` is evidence, not proof. finalize's workspace scan is the backstop
when an agent ignores the rules.

## Gotchas

- WSL `/etc/resolv.conf` links into `/mnt/wsl/`. The launcher hides `/mnt`
  and re-binds that one file.
- Codex loads one instruction file per directory, and `AGENTS.override.md`
  wins. It finds helper binaries next to its resolved binary, so binds keep
  symlinks.
- `codex exec --sandbox …` replaces the owner's `default_permissions`
  profile and its deny rules.
- agy rewrites `~/.gemini/antigravity-cli/bin/agentapi` at every start, so
  the launcher checks its content. agy's terminal sandbox makes the workspace
  read-only for the shell, and `--dangerously-skip-permissions` disables
  neither its deny rules nor its sandbox.
- Claude Code in auto mode: the classifier may refuse test scripts, so
  `creds claude` uses `--permission-mode dontAsk`.
- Copilot unpacks itself into `~/.cache`, and its login is in the keyring or
  in `~/.config/gh`, which the gate does not expose.
- The model provider's safeguards refuse adversarial e2e prompts. Use plain
  workflow prompts and put the attacks in deterministic red-team tests.
- moderncv splits first and last name into separate boxes, so finalize
  compares names without whitespace and accepts the full name in metadata
  only.
- Untracked empty dotfiles in the repo root, such as `.bashrc` and
  `.gitconfig`, are mount points of the coding agent's own sandbox. Never
  stage them: add explicit paths, not `git add -A`.
