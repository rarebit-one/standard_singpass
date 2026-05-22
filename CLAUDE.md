# CLAUDE.md

## Worktree-Only Workflow (Enforced)

**All file modifications are blocked in the main checkout.** A PreToolUse hook (`enforce-worktree.sh`) rejects Edit, Write, and NotebookEdit operations targeting files outside a worktree. There are no opt-outs. Do not use Bash to write files in the main checkout either (e.g., `echo >`, `sed -i`, `tee`, `cp`) — the hook cannot intercept shell commands, so this rule is instruction-enforced.

Before writing any code, create a worktree:

```bash
DEFAULT_BRANCH=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@refs/remotes/origin/@@')
DEFAULT_BRANCH=${DEFAULT_BRANCH:-main}
git fetch origin "$DEFAULT_BRANCH"
git worktree add .worktrees/<name> -b <branch-name> "origin/$DEFAULT_BRANCH"
```

Then work inside `.worktrees/<name>/` for the rest of the session.

**Naming:** Use the Linear issue identifier if available (e.g., `.worktrees/<identifier>`), a task slug (e.g., `.worktrees/fix-auth-timeout`), or today's date (e.g., `.worktrees/2026-04-01`) as fallback.

See the `/worktree` and `/start` skills for full conventions and flags.

## Scope

`standard_singpass` packages Singpass MyInfo (and, in future, Sign-in-with-Singpass) primitives as a reusable Rails engine:

- FAPI 2.0 OAuth client with PKCE + DPoP + `private_key_jwt`
- Native ECDH-ES JWE decryption (the `jwt` gem does not support ECDH-ES)
- JWS signature verification with JWKS caching and one-shot rotation retry
- Person-data parser (40+ fields from FAPI 2.0 v5 userinfo)
- JWKS generation + validation tooling

**Not in scope:** persistence (the host owns the MyInfo record model), business orchestration (callback handling, biodata forms), UI, or any domain-specific identity/loan logic. The gem is deliberately library-only.

## Consumers

`standard_singpass` is consumed by the rarebit-one workspace's web apps. After publishing a new version via `/publish-gem`, roll it out with the workspace-level `/rollout-gem standard_singpass [<version>]` skill (defined at the rarebit-one workspace root). The canonical consumer matrix lives in that skill's `SKILL.md`; the list there is the single source of truth so version pins don't drift between two files.
