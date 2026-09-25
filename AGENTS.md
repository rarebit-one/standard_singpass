# AGENTS.md — AI Agent Guide for StandardSingpass

StandardSingpass packages the Singpass MyInfo (FAPI 2.0) OAuth client and
companion primitives — DPoP, PKCE, native ECDH-ES JWE decryption, JWS
verification with JWKS caching, person-data parsing, and JWKS generation
tooling. It is designed as a reusable Rails engine; the host owns
persistence, callback orchestration, forms, and UI.

The top-level namespace is `StandardSingpass`; MyInfo lives at
`StandardSingpass::Myinfo::*` to leave room for a future
`StandardSingpass::Auth::*` (Sign-in-with-Singpass) submodule.

## Scope

`standard_singpass` packages Singpass MyInfo (and, in future, Sign-in-with-Singpass) primitives as a reusable Rails engine:

- FAPI 2.0 OAuth client with PKCE + DPoP + `private_key_jwt`
- Native ECDH-ES JWE decryption (the `jwt` gem does not support ECDH-ES)
- JWS signature verification with JWKS caching and one-shot rotation retry
- Person-data parser (40+ fields from FAPI 2.0 v5 userinfo)
- JWKS generation + validation tooling

**Not in scope:** persistence (the host owns the MyInfo record model), business orchestration (callback handling, biodata forms), UI, or any domain-specific identity/loan logic. The gem is deliberately library-only.

## Public API

- `lib/standard_singpass/myinfo.rb`: `Myinfo.configure`, `public_jwks`, `reset_configuration!`.
- `lib/standard_singpass/myinfo/client.rb`: `push_authorization_request`,
  `build_authorize_redirect`, `get_person_data` (PAR, token, userinfo).
- `lib/standard_singpass/myinfo/security.rb`: PKCE, DPoP, JWE dispatch, JWS validation.
- `lib/standard_singpass/myinfo/person_data_parser.rb`: `PersonDataParser.call`.
- `lib/standard_singpass/myinfo/failure_classifier.rb`: `FailureClassifier`.
- `lib/standard_singpass/testing.rb`: test-only JWE encryptor, not loaded by default.
- `lib/tasks/standard_singpass.rake` and `lib/generators/standard_singpass/install/`.

## Commands

```bash
bundle exec rspec          # dummy app, in-memory SQLite; the gem has no migrations
bundle exec srb tc         # Sorbet; RBIs are committed under sorbet/rbi/gems/
bundle exec tapioca gems   # regenerate gem RBIs after a bundle update
bin/rubocop -A
bundle exec brakeman --no-pager
bundle exec bundler-audit --update
```

## Invariants

- **No hardcoded Singpass URLs.** The configuration object does the
  env-vs-staging endpoint selection from `environment`.
- **No resilience layer of its own.** Hosts pass `network_wrapper`, which sees
  Faraday calls only, so JWE/JWS errors propagate untouched and a breaker does
  not trip on key/cert misconfiguration.
- `SAFE_ERROR_FIELDS` is the load-bearing allowlist; do not widen it
  without auditing what Singpass returns in error bodies.
  (Singpass error payloads can carry NRIC / email / other PII.)
- Private JWKS keys live in env vars / secret managers — never the repo.
  The `validate_jwks` rake task refuses public-only keys (missing `d`).
- `sorbet-runtime` is a runtime dependency so consumers need not adopt Sorbet;
  keep `# typed: strict` + `sig {}` on lib files.
- All errors descend from `StandardSingpass::Myinfo::Error`, which descends
  from the gem-wide `StandardSingpass::Error`. The pre-0.4.0
  `Security::DecryptionError` / `Security::ValidationError` aliases are gone
  (since 0.5.0); rescue `DecryptionError` / `SignatureError`.

## Footguns

- A JWKS-host outage also surfaces as `SignatureError` (with `status` /
  `transport?` set), not only key misconfiguration: classify with `FailureClassifier`.
- `bin/rails standard_singpass:myinfo:generate_jwks` prints private key material;
  run it on a trusted machine only.
- The full-flow spec at `spec/standard_singpass/myinfo/full_flow_spec.rb` must be
  updated whenever the public surface of `Client` changes.
- Specs that mutate the global `Myinfo.configuration` should call
  `reset_configuration!` in an `after` block.
- Pre-push lefthook (`lefthook.yml`) runs rubocop, brakeman and rspec;
  bundler-audit runs only in CI. SimpleCov enforces 90% line / 75% branch.

## Workspace rules

- **Worktrees only.** Edit in `.worktrees/<name>/`, never in the main checkout.
  `.agents/hooks.toml` registers `enforce-worktree` (Edit/Write/NotebookEdit) and
  `enforce-worktree-bash` (Bash writes into the main checkout: `sed -i`, `tee`,
  redirects, `cp`/`mv`, `git apply`, `rsync`); scripts are in `.agents/hooks/`.
  There are no opt-outs; CI checkouts are the only exception.

```bash
DEFAULT_BRANCH=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@refs/remotes/origin/@@')
DEFAULT_BRANCH=${DEFAULT_BRANCH:-main}
git fetch origin "$DEFAULT_BRANCH"
git worktree add .worktrees/<name> -b <branch-name> "origin/$DEFAULT_BRANCH"
```

Then work inside `.worktrees/<name>/` for the rest of the session.

**Naming:** Use a task slug (e.g., `.worktrees/fix-auth-timeout`) or today's date (e.g., `.worktrees/2026-04-01`).

- **Signed commits only.** `enforce-signed-commits` adds `-S` to `git commit`; if
  signing fails, stop and report it, and never pass `--no-gpg-sign`.

See the `/worktree` and `/start` skills for full conventions and flags.

## Where to look

- `docs/agents/architecture.md`: layout, configuration DSL, error taxonomy, key files, dependencies.
- `docs/agents/workflows.md`: initiating a flow, handling the callback, rotating the JWKS.
- `docs/agents/development.md`: the full command reference and test conventions.
- `docs/agents/security.md`: PII allowlist, key handling, security gates.
- `README.md`: host-facing installation and configuration.

## Consumers

`standard_singpass` is consumed by one app:

- `fundbright-web` (in the sibling `~/Workspace/fundbright/` workspace, org `fundbright` — not beside this repo)

Singpass MyInfo is a fundbright-only integration. **This list is deliberately narrower than "the workspace's web apps"**, which is what this section used to say — that phrasing reads as "all five" and would send a rollout at four apps that do not consume the gem at all.

After publishing a new version via `/publish-gem`, roll it out with the workspace-level `/rollout-gem standard_singpass [<version>]` skill (defined at the rarebit-one workspace root). The canonical consumer matrix — including version constraints — lives in that skill's `SKILL.md`; the list here is a summary of it, kept in the bulleted form that `.claude/scripts/check-gem-family-drift.sh` compares against the matrix.
