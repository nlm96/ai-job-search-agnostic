# Privacy layer: progress log

Design: `docs/fork/diagrams/30`–`33` and `docs/fork/claude-review/03` (untracked drafts).
Branch: `feature/privacy-layer`.

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
| `privacy/launcher/jobsearch.py` | agent jail: `/` read-only, repo writable except code/config that runs outside, CLI state writable except executable config, `private/` masked |
| `privacy/migrate.py`, `privacy/bin/migrate` | real values → tokens in workspace files (dry run by default; never `documents/`) |
| `privacy/AGENT-RULES.md` | all agent-facing rules; read-only in the launcher |
| `privacy/patches/0001-…` | one pointer line each in `CLAUDE.md`, `apply.md`, `setup.md`, `reset.md` |
| `privacy/dev/jobsearch-gates` | owner-installed gate runner (`test`, `e2e claude`) |

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
| 2026-11-08 | 3866705–b380b42 | launcher protects Codex/Copilot/agy config; agy shim check; `~/.cache`; GEMINI.md, AGENTS.override.md; finalize workspace scan | gate PASS (108); e2e: claude, codex, agy PASS; rules: claude PASS, agy and codex FAIL then PASS after the pointer files; copilot blocked on login |

### Runtime matrix (one run each; LLM behaviour is not deterministic)

| CLI | e2e | rules | Notes |
|---|---|---|---|
| Claude Code | PASS | PASS | reads `CLAUDE.md` → rules |
| Codex | PASS | PASS | needs `AGENTS.override.md` (loads only one file per dir); helpers sit next to the resolved binary |
| agy | PASS | PASS | needs `GEMINI.md`; rewrites `antigravity-cli/bin/agentapi` each start (launcher checks its content) |
| Copilot | blocked | not run | login lives in the keyring (D-Bus) or `~/.config/gh`; neither is in the gate jail. Owner decision |

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
- The launcher hides `private/` but not credentials: `~/.ssh`, `~/.config/gh` and other CLIs'
  logins are readable (read-only) inside it. Not an identity leak, but worth masking per CLI.
- `Edit(tools/**)` is an upstream ask rule, so fork code lives in `privacy/`.

## Next

1. Copilot login for the gate (owner decision), then `e2e`/`rules copilot`.
2. Mask other credentials in the launcher (`~/.ssh`, `~/.config/gh`, other CLIs' auth).
3. Repeat `rules` runs to estimate how reliably each CLI follows the rules.
4. Custom `/add-template` templates in finalize (now refused).
