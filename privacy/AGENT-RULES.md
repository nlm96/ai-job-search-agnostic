# Privacy layer: rules for agents

This fork keeps the candidate's direct identifiers (name, email, phone,
address, profile links) out of every agent's reach. Where these rules
conflict with `CLAUDE.md` or a command spec, these rules win.

## Tokens instead of contact details

Write these tokens wherever a spec, template or checklist asks for the
candidate's own contact details. Never write, ask for or guess the real values.

| Token | Field |
|---|---|
| `ZZFIRSTNAMEZZ` | first name |
| `ZZLASTNAMEZZ` | last name |
| `ZZNAMEZZ` | full name as printed |
| `ZZEMAILZZ` | email |
| `ZZPHONEZZ` | phone |
| `ZZADDRESSZZ` | address line |
| `ZZLINKEDINZZ` | LinkedIn URL |
| `ZZGITHUBZZ` | GitHub URL |
| `ZZWEBSITEZZ` | website URL |

- Use the tokens as plain text, including inside `\href{...}`, `\email{...}`,
  `\name{ZZFIRSTNAMEZZ}{ZZLASTNAMEZZ}` and `pdftitle={ZZNAMEZZ - CV}`. They
  are letters only, so they need no escaping.
- In prose, refer to the candidate as "the candidate" or "you", not by name.
- Other people's details (references, recruiters, hiring managers) are not
  covered by this layer; handle them as the specs say.
- If the user types one of their real values into the chat, do not copy it
  into any file. Write the token and remind them that the real value
  belongs in `privacy/bin/identity init`, which they run outside this session.
- If you meet a real value in `documents/`, do not copy it into profile
  files or drafts; use the token.

## What you cannot see, and should not try to

- `private/` is masked in this session: it looks empty. That is expected.
  It holds the encrypted identity and the final PDFs. Do not try to read it.
- `privacy/`, `tools/`, `.venv/` and `.git/` are read-only here. Do not try
  to change them.

## Command-specific changes

**`/setup`**: keep the privacy-layer line at the top of `CLAUDE.md` when you
rewrite that file. In Section 1 and Path A/B, collect everything except the direct
identifiers above; for those, write the tokens in `CLAUDE.md`,
`01-candidate-profile.md`, the contact block in `05-cv-templates.md`, the
contact line and signature in `06-cover-letter-templates.md` and
`cv/main_example.tex`. City and country are fine to write. In Step 4, add:
"Run `privacy/bin/identity init` in a terminal outside this session to store
your real name and contact details encrypted."

**`/apply`**:
- Step 5d: the contact check becomes "the tokens `ZZEMAILZZ` and `ZZPHONEZZ`
  appear as literal text in the extracted CV text". The real values are
  checked later by `finalize`. Page and layout checks are unchanged, but a
  real name or address may be longer than its token, so leave a little
  slack rather than filling a page to the last line.
- Step 6 report, **Files Created**: say that the PDFs in `cv/` and
  `cover_letters/` are token previews, not for sending.
- Step 6 **Next Steps**, first item: "Outside this session, run
  `privacy/bin/finalize <company>_<role>`. It asks for your passphrase and
  writes the sendable PDFs to `private/final/<company>_<role>/` (also linked
  from `documents/applications/<company>_<role>/final`). If it prints FAIL,
  paste its output here." Its output never contains real values, so you can
  act on it: for example shorten the CV if it reports 3 pages.
- The CLAUDE.md checklist item "Contact details are correct" means "the
  right tokens are in the right places".

**`/reset`**: `private/` is not part of any reset scope. Tell the user that
deleting `private/identity.enc` is done by hand, outside the agent.
