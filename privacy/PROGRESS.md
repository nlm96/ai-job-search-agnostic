# Privacy layer: progress log

Design: `docs/fork/diagrams/30`–`33` and `docs/fork/claude-review/03` (untracked drafts).
Branch: `feature/privacy-layer`.

## How testing works

- `python -m unittest discover -s privacy/tests -t .` runs the unit layer anywhere
  (red-team and jail tests skip outside the gate runner).
- `jobsearch-gates test` (installed copy of `privacy/dev/jobsearch-gates`) tests the
  committed HEAD in a bwrap jail without network or home, where nested user
  namespaces work. It also runs the upstream suite.
- `jobsearch-gates e2e claude` runs real Claude Code through the launcher with a
  fixed red-team prompt; the runner plants random canaries and is the oracle.
- Mutation check: commit a mutant, run the gate, expect FAIL, `git reset --hard HEAD~1`.

## Done

| Date | Commit | What | Evidence |
|---|---|---|---|
| 2026-11-07 | 2d0f80a | gate runner + jail checks | gate PASS; 2-level nested bwrap works in the jail |
| 2026-11-08 | 905b000–1dff35d | launcher prototype, canary red-team tests | gate PASS; mutants (no fd close, no PID ns, private unmasked) each FAIL |
| 2026-11-08 | 3e47f8f | resolv.conf stays visible when /mnt is hidden; e2e mode | gate PASS; e2e not yet run (needs reinstall) |

## Findings

- On WSL `/etc/resolv.conf` → `/mnt/wsl/resolv.conf`; hiding `/mnt` breaks DNS unless re-bound.
- `/proc/<pid>/root` of host processes did not leak even without a PID namespace in the
  gate jail; the PID namespace stays as defence in depth, guarded by a process-count test.
- `Edit(tools/**)` is an upstream ask rule, so fork code lives in `privacy/`.

## Next

1. Run `jobsearch-gates e2e claude` (owner reinstalls the runner and adds the exclusion).
2. e2e modes for codex, copilot, agy.
3. Open decisions for the owner: `documents/` handling, tracker paths, upstream-edit route.
4. Identity store (scrypt + AES-GCM), tokens, finalize, migration, `/apply` integration.
