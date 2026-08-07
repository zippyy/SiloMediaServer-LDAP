# Contributing to Silo LDAP Plugin

This plugin is part of the Silo ecosystem. The same contribution rules apply here as in the
main [Silo server](https://github.com/Silo-Server/silo-server) repo. Read
[CONTRIBUTING.md](https://github.com/Silo-Server/silo-server/blob/main/CONTRIBUTING.md) there
first — especially the sections on AI slop, disclosure, and verification.

## The short version

- AI-generated code is fine. AI slop is not.
- You are responsible for everything you submit, even if an AI wrote it.
- Actually read the code. Actually run the tests. Actually understand what it does.
- Small, focused PRs get reviewed fast. Big unexplained ones sit.

## Before you submit

```bash
make test        # go test ./...
make vet         # go vet ./...
```

You can't test against a real LDAP directory without one, but the unit tests cover the
authenticator logic, config validation, failure-stage classification, and filter escaping. At
minimum, all tests must pass.

## AI Disclosure (Required)

Every PR needs the same disclosure block as the Silo server:

```md
### AI Disclosure
- Tool(s): e.g. Claude Code, Codex CLI, Cursor — or "none"
- Model(s): exact model ID(s), e.g. claude-opus-5, gpt-5.6 — or "n/a"
- Involvement: fully AI-generated | AI-assisted | human-written, AI-reviewed | none
- Adversarial review: what your own AI review of the diff found, and how you resolved it
```

The exact model matters. Undisclosed AI use gets the PR closed. Fabricated content (invented
APIs, hallucinated bugs, fake repro steps) is an immediate block, first offense.

## Style

- One thing per PR.
- Conventional Commit subjects (`feat(ldap): ...`, `fix(config): ...`).
- Follow existing patterns in the codebase.
- Comments for non-obvious things only.

## For AI Agents

If you're an LLM working on this codebase: read `AGENTS.md` for architecture, conventions, and
verification requirements. The rules in this file apply to you too.
