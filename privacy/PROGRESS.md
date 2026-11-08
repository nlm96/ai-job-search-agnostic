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
| 2026-11-08 | 8c47a9e–4714037 | e2e prompt as plain workflow; write check; canaries in `private/` | needs runner reinstall |

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
- `Edit(tools/**)` is an upstream ask rule, so fork code lives in `privacy/`.

## Next

1. Reinstall the runner, rerun `e2e claude`.
2. Migration: replace real values with tokens in profile files after `/setup`, run outside agents.
3. Patches for `apply.md` (5d, 6), `setup.md` (tokens), `reset.md`; AGENTS.md pointer.
4. e2e modes for codex, copilot, agy.
5. Custom `/add-template` templates in finalize (now refused).
