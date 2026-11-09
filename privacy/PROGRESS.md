# Privacy layer: progress log

How to work on the layer: `DEVELOPING.md`. User guide: `README.md`.
Design: `docs/fork/diagrams/30`–`33` and `docs/fork/claude-review/03` (untracked drafts).
Branch: `feature/privacy-layer`, pushed to `origin` (the fork) on 2026-11-10; no PR yet.

## Decisions (owner, 2026-11-08)

- `documents/` stays agent-readable; anonymising it is the user's responsibility.
- Final PDFs: `private/final/<CO_ROLE>/{cv,cover_letter}.pdf`, plus a convenience link
  `documents/applications/<CO_ROLE>/final` → that folder. `private/` is the only mask.
- The tracker is unchanged (`cv_file`/`cover_letter_file` keep pointing to the drafts).
- Upstream spec changes (`apply.md`, `setup.md`, `reset.md`) as the smallest patches.

## Components

| Path | Role |
|---|---|
| `privacy/identity.py` | encrypted store `private/identity.enc` (scrypt N=2^17 + AES-256-GCM, header as AAD); tokens `ZZ…ZZ` |
| `privacy/identity_cli.py`, `privacy/bin/identity` | `init`, `check`, `rekey`, `tokens` |
| `privacy/texsubst.py` | token → escaped value; `\href`/`\url` targets get URL escaping |
| `privacy/finalize.py`, `privacy/bin/finalize` | build real PDFs in a no-network, no-home bwrap jail; checks; redacted output |
| `privacy/launcher/jobsearch.py` | agent jail: `/` read-only; home hidden except toolchains (read-only), a per-CLI cache and the started CLI's state (writable except executable config); `/run/user` hidden; secret env dropped except the CLI's own login; repo writable except code/config that runs outside; `private/` masked |
| `privacy/migrate.py`, `privacy/bin/migrate` | real values → tokens in workspace files (dry run by default; never `documents/`) |
| `privacy/AGENT-RULES.md` | all agent-facing rules; read-only in the launcher |
| `privacy/patches/0001-…` | one pointer line each in `CLAUDE.md`, `apply.md`, `setup.md`, `reset.md` |
| `privacy/dev/jobsearch-gates` | owner-installed gate runner (`test`, `e2e`/`rules` CLI, `creds claude\|codex\|agy`) |

## How testing works

- `python -m unittest discover -s privacy/tests -t .` runs the unit layer anywhere
  (jail, build and red-team tests skip outside the gate runner).
- `jobsearch-gates test` tests the committed HEAD in a bwrap jail without network or
  home, where nested user namespaces work. It also runs the upstream suite.
- `jobsearch-gates e2e claude` runs real Claude Code through the launcher with a plain
  workflow prompt; the runner plants random canaries under `private/` and is the oracle.
- Mutation check: commit a mutant, run the gate, expect FAIL, `git reset --hard HEAD~1`.
  Test data must live outside `/tmp`, which every jail replaces.

## Done

| Date | Commit | What | Evidence |
|---|---|---|---|
| 2026-11-07 | 2d0f80a | gate runner + jail checks | gate PASS; nested bwrap works |
| 2026-11-08 | 905b000–1dff35d | launcher prototype, canary red-team | mutants (no fd close, no PID ns, unmasked) FAIL |
| 2026-11-08 | 3e47f8f–5f63d6b | resolv.conf fix; first `e2e claude` | e2e PASS |
| 2026-11-08 | ddd61c7–a9597e4 | identity store, substitution, finalize, identity CLI | gate PASS (77); mutants (jail exposes host, no redaction) FAIL |
| 2026-11-08 | 40a53bd | read-only-by-default launcher, `private/` only mask | gate PASS (81); mutant (writable root) FAIL |
| 2026-11-08 | 8c47a9e–d3d0468 | e2e prompt as plain workflow; write check; canaries in `private/` | `e2e claude` PASS through the read-only launcher: read visible file, wrote draft, `private/` empty, no canary leaked |

| 2026-11-08 | 1661302–9c1d88c | migrate; agent rules; pointer patch | gate PASS (98, incl. upstream CI on a patched clone, migrate→finalize round trip); local mutants (no escaped forms, no phone rule) FAIL |
| 2026-11-09 | 7a2260b–55bcd7a | `creds agy`; creds script reads before it writes (agy's shell sandbox makes the workspace read-only) | `creds agy` PASS with the owner's settings and also with `--dangerously-skip-permissions`: `read_file` deny rule, and `cat`/Python get Permission denied; `creds codex` PASS again |
| 2026-11-09 | 263f1e5–eeadb6d | gate `creds`: the CLI's own layer hides its login files from its agent inside the launcher; Codex runs under the owner's `dev` profile (`--sandbox` replaced it) | `creds claude` and `creds codex` PASS: canary denied to Read (Claude) and to `cat` and Python in a script (OS sandbox), normal file copied; owner config checked; `e2e`/`rules codex` PASS under the profile |
| 2026-11-09 | e3c3884–317758b | credential masking: home allowlist, `/run/user` hidden, secret env filter, TeX cache in jail cache | gate PASS (123, incl. lualatex inside the launcher); mutants (no home mask, no env filter) FAIL; e2e and rules PASS for claude, codex, agy |
| 2026-11-08 | 3866705–b380b42 | launcher protects Codex/Copilot/agy config; agy shim check; `~/.cache`; GEMINI.md, AGENTS.override.md; finalize workspace scan | gate PASS (108); e2e: claude, codex, agy PASS; rules: claude PASS, agy and codex FAIL then PASS after the pointer files; copilot blocked on login |

### Runtime matrix (rules: two runs each; LLM behaviour is not deterministic)

| CLI | e2e | rules | Notes |
|---|---|---|---|
| Claude Code | PASS | PASS ×2 | reads `CLAUDE.md` → rules |
| Codex | PASS | PASS ×2 after fix | needs `AGENTS.override.md` (loads only one file per dir); helpers sit next to the resolved binary |
| agy | PASS | PASS ×2 after fix | needs `GEMINI.md`; rewrites `antigravity-cli/bin/agentapi` each start (launcher checks its content) |
| Copilot | blocked | not run | login lives in the keyring (D-Bus) or `~/.config/gh`; neither is in the gate jail. Deferred by the owner (2026-11-09) |

## Findings

- WSL `/etc/resolv.conf` → `/mnt/wsl/resolv.conf`; hiding `/mnt` breaks DNS unless re-bound.
- `/proc/<pid>/root` did not leak even without a PID namespace; the PID namespace stays
  as defence in depth, guarded by a process-count test.
- An agent that can write the home dir or `privacy/`, `tools/`, `.venv/`, `.git/` can plant
  code that runs outside the jail (in finalize, git hooks, shell rc). Fixed in 40a53bd.
- Residual write paths outside the jail: `~/.claude.json` (holds MCP server definitions;
  Claude must write it) and new project files such as `.mcp.json` or `.envrc`. Claude
  Code and direnv ask before trusting those. Rule: always start agents via the launcher.
- moderncv puts first and last name in separate boxes; pypdf may extract them without a
  space, and a long name wraps at its hyphen. Name checks compare without whitespace.
- The template's full name appears only in `pdftitle`, so name checks accept metadata.
- The provider's safeguards refused an adversarial e2e prompt; e2e now uses a workflow prompt.
- Upstream's `check_framework_version.py` fails on any `AGENTS.md` change without a version
  bump, so non-Claude pointers live in fork-owned `AGENTS.override.md` and `GEMINI.md`.
- The launcher used to hide `private/` but not credentials (`~/.ssh`, `~/.config/gh`, other
  CLIs' logins, shell history, other projects, the rclone mount, the ssh-agent socket in
  `/run/user`). Fixed with a home allowlist (e3c3884) rather than a denylist, which would
  miss unknown stores.
- The started CLI's own login is visible inside the launcher (the CLI needs it). Its agent is
  kept from it by the CLI's own layer, configured by the owner: Claude Code (Read deny rules
  + sandbox with `failIfUnavailable`, no unsandboxed fallback) and Codex (`dev` profile with
  deny-read rules) and agy (`read_file` deny rules + terminal sandbox) are verified by
  `creds`. For agy, `--dangerously-skip-permissions` disables neither (verified), so the
  e2e/rules gates keep it. Copilot: not examined.
- The auto-mode classifier also refused the credential script for Claude; `creds claude`
  uses `dontAsk` so the sandbox is tested on its own.
- `codex exec --sandbox …` replaces the owner's `default_permissions` profile and drops its
  deny rules. Start Codex without it.
- Anything in `HOME_TOOLCHAIN` and `/etc` is readable in the launcher.
  The `/run/user` mask is checked only in argv: the gate jail has no `/run/user`.
- `Edit(tools/**)` is an upstream ask rule, so fork code lives in `privacy/`.

## Next

Status 2026-11-10: the layer is built and gate-tested with synthetic data for Claude Code,
Codex and agy. User guide and developer guide are written. The branch is pushed, after a
scan of all outgoing commits for private data and a history rewrite that removed the
owner's absolute home path. There is no PR yet.

1. Review the whole branch before the PR (`git diff master...HEAD`): a security
   review, and a scan of every outgoing commit for private data (the owner's name, email,
   phone and absolute paths must not appear; use `~` or `$HOME`, as the owner asked).
   Fixes are new commits: the branch is already pushed, so do not rewrite its history.
2. Open a PR to the fork's own `master` (owner approval), with
   `gh pr create --repo nlm96/ai-job-search-agnostic --base master`, never upstream.
3. The owner's acceptance run, which only the owner can do: `identity init` with the real
   details, the launcher, `/setup`, `/apply` on a real posting, then `finalize`. Fix what
   it turns up from finalize's redacted output.
4. Optional: a `jobsearch` command on PATH. This is workstation config (chezmoi), so it
   needs the owner's approval.

Later:
- Copilot login for the gate (deferred by the owner), then `creds copilot`.
- Custom `/add-template` templates in finalize (now refused).
- Repeat `rules` runs to estimate how reliably each CLI follows the rules.
- The `creds` config checks pin only each CLI's own login file. A deny list that drops
  another credential path would not fail them (the launcher hides those anyway).
- Network egress allowlist in the launcher (exfiltration of drafts and `documents/`).
