# Privacy layer

This fork keeps your name, email, phone, address and profile links away from
the AI agents. The agents work on your CV and cover letters with placeholder
tokens such as `ZZEMAILZZ`. Your real details are stored encrypted in
`private/identity.enc`, and only `privacy/bin/finalize` puts them in. It runs
outside the agent session and asks for your passphrase.

```
you ──▶ jobsearch launcher ──▶ agent (Claude Code, Codex, agy)
                                 │ sees: drafts with tokens, documents/, profile
                                 │ cannot see: private/, your logins, ~/.ssh, …
                                 ▼
                       cv/main_acme_dev.tex  (tokens)
                                 │
you ──▶ privacy/bin/finalize acme_dev   (passphrase; no agent, no network)
                                 ▼
             private/final/acme_dev/{cv,cover_letter}.pdf   (real details)
```

Linux and WSL only: the launcher and finalize use bubblewrap.

## One-time setup

1. Install the main README's prerequisites (a TeX distribution with
   `lualatex` and `xelatex`, the agent CLI), plus bubblewrap, for example on
   Ubuntu:

   ```sh
   sudo apt install bubblewrap
   ```

2. Install the Python dependencies in the repo's venv:

   ```sh
   uv venv .venv          # or: python3 -m venv .venv
   uv pip install --python .venv/bin/python cryptography pypdf
   ```

3. In a normal terminal, **not** inside an agent session, store your details:

   ```sh
   privacy/bin/identity init
   ```

   It asks for each field (Enter skips the optional ones) and then for a
   passphrase of at least 12 characters. There is no recovery: if you forget
   the passphrase, run `init --force` and enter everything again.

   `privacy/bin/identity check` shows which fields are set, `rekey` changes
   the passphrase, and `tokens` lists the tokens.

4. If your profile files or CVs already contain real details (for example
   from before you used this fork), replace them with tokens:

   ```sh
   privacy/bin/migrate            # dry run: shows what it would replace
   privacy/bin/migrate --apply
   ```

   It never touches `documents/`. It also warns if real values are in the git
   history, which `migrate` cannot fix. If you have pushed them, treat them as
   public.

## Daily use

Always start the agent through the launcher:

```sh
python3 privacy/launcher/jobsearch.py claude     # or codex, agy (copilot: untested)
```

Extra arguments are passed to the CLI, for example `... claude --continue`.
Then work as usual: `/setup`, `/apply <posting>` and so on. The agent writes
tokens and tells you when to finalize.

To get the PDFs you send, run this in a normal terminal:

```sh
privacy/bin/finalize acme_dev     # the <company>_<role> part of cv/main_acme_dev.tex
```

It compiles the CV and cover letter with your real details in an offline
sandbox. It then checks the page count, that no token is left, and that your
email and phone appear as text. It writes:

- `private/final/acme_dev/cv.pdf` and `cover_letter.pdf`, and
- a link `documents/applications/acme_dev/final` to that folder.

Its output never contains your details. If it prints `FAIL`, paste the output
to the agent, for example to shorten a CV that came out at 3 pages. The
PDFs in `cv/` and `cover_letters/` are token previews, not for sending.

## What is protected, and what is not

Inside the launcher the agent:

- **cannot read** `private/` (it looks empty) or the rest of your home
  directory. That covers `~/.ssh`, `~/.config/gh`, shell history, other
  projects, mounted drives, and the logins of the CLIs you did not start;
- **cannot use** your ssh or gpg agent or the keyring (`/run/user` is hidden);
- **does not get** environment variables that look like secrets, except the
  started CLI's own login variables;
- **cannot change** `privacy/`, `tools/`, `.venv/`, `.git/`, the Claude Code
  permission files, or the CLIs' own settings and hooks. Code it plants there
  would otherwise run with your full rights later.

Not covered:

- **The started CLI's own login** is visible to the CLI. What keeps its agent
  from reading it is the CLI's own sandbox and deny rules, so keep them on:
  - Claude Code: `Read(...)` deny rules plus `sandbox.enabled`,
    `failIfUnavailable: true` and `allowUnsandboxedCommands: false`;
  - Codex: a `default_permissions` profile with deny-read rules. Do not start
    it with `--sandbox`, which replaces the profile;
  - agy: `read_file(...)` deny rules plus `enableTerminalSandbox`.

  These settings have been tested to hold inside the launcher.
- **The network** is open, because the agents need their model provider. A
  prompt-injected agent could send out what it can read: your drafts, profile
  and `documents/`.
- **`documents/`** is readable by design. Remove your details from what you
  put there.
- **Other people's details** (references, recruiters) are not tokenised.
- **Agents started without the launcher** get none of this protection.

## Where things are

| Path | What |
|---|---|
| `private/identity.enc` | your details: scrypt + AES-256-GCM, git-ignored |
| `private/final/<co_role>/` | the PDFs to send, git-ignored |
| `privacy/AGENT-RULES.md` | the rules the agents follow (tokens, what not to touch) |
| `privacy/launcher/jobsearch.py` | the launcher |
| `privacy/bin/` | `identity`, `migrate`, `finalize` |
| `privacy/DEVELOPING.md` | for working on the layer itself |

To start over, delete `private/identity.enc` by hand. No agent command does
that.
