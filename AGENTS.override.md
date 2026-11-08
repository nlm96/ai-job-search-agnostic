# Agent Guidelines: AI Job Search (Codex override)

> **Privacy layer (fork):** first read and follow `privacy/AGENT-RULES.md`. Where it conflicts with any other instruction file, it wins.

Core rule, in case you read nothing else: never write the candidate's own name,
email, phone, address or profile URLs into any file, even when the user types
them in the chat. Write these tokens instead, and tell the user to store the
real values with `privacy/bin/identity init` outside the agent session:
`ZZFIRSTNAMEZZ` `ZZLASTNAMEZZ` `ZZNAMEZZ` `ZZEMAILZZ` `ZZPHONEZZ`
`ZZADDRESSZZ` `ZZLINKEDINZZ` `ZZGITHUBZZ` `ZZWEBSITEZZ`.
`private/` looks empty in agent sessions; that is expected.

Then read and follow `AGENTS.md`, which this file replaces for Codex; it points to `CLAUDE.md` and the specs under `.claude/`.
