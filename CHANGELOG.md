# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-07-30

### Added

- **`StandardSingpass::Myinfo::FailureClassifier.upstream_unavailable?(error)`** — one answer to the question every host asks in its rescue: is Singpass unavailable, or is our request wrong? It decides what the user is told, and the two answers are not interchangeable — an unavailable upstream clears itself within minutes ("try again shortly"), while "contact support and quote this reference" is a dead end for a transient blip. True for 502/503/504, HTTP 429, and transport failures on any leg; false for authentication, decryption, signature, and configuration errors. `FailureClassifier::UPSTREAM_UNAVAILABLE_STATUSES` is the documented status list, and `Client::RETRYABLE_USERINFO_STATUSES` is now an alias of it rather than a second copy — the statuses worth one more automatic attempt are exactly the statuses that mean "their side, transient".
- **`StandardSingpass::Myinfo::Error#transport?`** — true when the request never reached Singpass at all (DNS, connection refused, TLS, read timeout). Set on the PAR, token, and userinfo transport-failure paths. Previously the only way to recover this was to match `"unreachable"` in the message, which is the same trap `ApiError#status` was added in 0.2.0 to close: the message is not a stable interface.
- **`StandardSingpass::Myinfo::Noa.history(parsed)`** / **`.basic_history(parsed)`** — normalise Notice-of-Assessment data into a single list regardless of which NOA scope the Singpass app was approved for. The width is a property of the app registration, not the request: `noa` yields the latest year only, `noahistory` the last two, and `PersonDataParser` mirrors that as `:noa` (one record) or `:noa_history` (an array). The records share a shape, so every consumer ended up writing the same "array, or wrap the single record" branch. Prefers the 2-year history when both are present (it is a superset), returns `nil` when neither scope yielded data, and reads both Symbol and String keys so a hash round-tripped through JSON or a database column works unchanged.
- **`config.production_env_detector`** — an optional callable deciding whether the current deploy is real production, for the mock-mode guard below. Takes no arguments, returns a boolean; `nil` (the default) falls back to `Rails.env.production?`. Mirrors `StandardId`'s option of the same name. Staging and preview deploys routinely run `RAILS_ENV=production`, so hosts that distinguish a physical deploy environment from `RAILS_ENV` can supply `-> { AppEnv.production? }`.

### Changed

- **`Security::ValidationError` and `Security::DecryptionError` now descend from `StandardSingpass::Myinfo::Error`** (previously bare `StandardError`), and JWKS-fetch failures carry the JWKS response's status — or `transport?` when the endpoint was unreachable. Verifying a signature requires fetching Singpass's JWKS, so a JWKS host that is down previously surfaced as a statusless `SignatureError` (or `AuthenticationError` on the ID-token leg), indistinguishable from a genuinely bad signature and classified as our own bug. The client now propagates both attributes across those re-raises.
- **`status` moved from `ApiError` up to the base `Error` class, and is now set on every leg of the flow.** 0.2.0 put it on `ApiError`, which covers the token and userinfo legs — but PAR raises `PARError`, so a 502 from the PAR endpoint carried no status and any classification keyed on `ApiError` reported a Singpass-side outage as our own bug. `status` and `transport?` now both live on `Error`, are populated on the PAR and authentication paths as well, and `FailureClassifier` keys on the base class. `ApiError#status` is unchanged for existing callers; `Error#initialize` takes both keywords optionally, so `raise SomeError, "msg"` still works.

- **`config.mock_mode` is now guarded at boot (`StandardSingpass::Myinfo::MockModeGuard`).** Mock mode serves fixture persona data instead of running the real FAPI 2.0 flow — right for development, CI, and staging rehearsals, catastrophic in production, where real users would submit fabricated identity data that is indistinguishable from verified MyInfo data downstream. A mis-set environment variable is all it takes, and nothing about the running app looks wrong afterwards, so it is checked at boot rather than per request. Three outcomes: a **production deploy raises `ConfigurationError` and refuses to boot**; a **production-*like* deploy** (`RAILS_ENV=production` but not production per `production_env_detector`) logs and reports via `Rails.error`, then boots; anything else is silent. Wired from the engine's `after_initialize` with no opt-out — a guard you can forget to invoke is a guard that isn't there.

  **Upgrade note:** a host that sets `mock_mode` on a deploy running `RAILS_ENV=production` will now either fail to boot or emit a reported error. If that deploy is a staging or preview box, set `config.production_env_detector` so the gem can tell the difference. Hosts that leave `mock_mode` at its default (`false`) are unaffected.

  Reporting goes through `Rails.error` rather than any specific error tracker, so whatever the host has subscribed (Sentry included) picks it up.

### Notes

- All three additions are promotions of knowledge that had accumulated in a consumer app. Each is MyInfo protocol or scope-grant knowledge that any Singpass client needs — which statuses Singpass uses for upstream-agency outages, how the two NOA scope widths differ in shape, and that the gem's own mock mode must never reach real users — rather than host policy. Host policy (what copy to show a user, where to read an environment variable from) stays in the host: the gem still never reads `ENV` itself, and `production_env_detector` is the seam for the one environment opinion it does hold.

## [0.2.0] - 2026-07-22

### Added

- `StandardSingpass::Myinfo::ApiError#status` — the HTTP status of the Myinfo response that produced the error (`nil` for transport failures and for errors a host raises itself). Hosts need this to separate "Myinfo or one of its upstream agencies is unavailable" (502/503/504 — tell the user to retry shortly) from "we sent something wrong" (4xx — a bug worth surfacing to support). Previously the only way to recover the status was to parse it back out of the message, which is not a stable interface. Set on both the userinfo and token-exchange failure paths.
- Bounded retry with jittered exponential backoff on the **userinfo** fetch for transient upstream statuses (502/503/504), 3 attempts total. Singpass returns `502 upstream_dependency_error` whenever a Myinfo upstream (CPF Board, IRAS, MOM, …) is unavailable — including throughout their [published maintenance windows](https://docs.developer.singpass.gov.sg/docs/products/singpass-myinfo/scheduled-downtimes) — and a single transient one previously failed the whole flow. Because the authorization code is already spent by that point, the user's only recovery was a **full Singpass re-login**, so a momentary blip cost a complete re-authentication.

### Notes

- The retry is scoped deliberately:
  - **Userinfo only.** The token exchange is never retried — it consumes a single-use authorization code, and replaying it earns an `invalid_grant`. Userinfo is an idempotent GET against an access token already in hand.
  - **Status-based failures only, never timeouts.** A 5xx returns in well under a second; a timed-out attempt has already spent the request budget, and retrying it risks turning a slow page into a gateway error.
  - **Inside `network_wrapper`, not outside.** A host's wrapper is typically a circuit breaker; keeping retries inside means one user attempt counts as one failure against the breaker rather than three, so a single unlucky user can't trip a shared circuit alone.
- The DPoP proof is rebuilt on every attempt — RFC 9449 proofs carry a one-shot `jti`, so a replayed header would be rejected.

## [0.1.0] - 2026-05-24

### Added

- `StandardSingpass::Myinfo::Client` — FAPI 2.0 OAuth client with PKCE, DPoP (RFC 9449), and `private_key_jwt` client assertion. Performs PAR, token exchange, ID-token validation (iss/aud/exp/iat/sub/acr/nonce), and userinfo fetch.
- `StandardSingpass::Myinfo::Security` — PKCE/DPoP primitives, JWE decryption dispatch, JWS validation with JWKS caching and one-shot key-rotation retry.
- `StandardSingpass::Myinfo::EcdhJwe` — native ECDH-ES+A128KW / +A256KW JWE implementation covering A128GCM, A256GCM, A128CBC-HS256, A256CBC-HS512. Exists because the `jwt` gem does not support ECDH-ES key agreement.
- `StandardSingpass::Myinfo::PersonDataParser` — extracts 40+ structured fields (identity, contact, address, pass info, income, employment, assets, housing, vehicles) from FAPI 2.0 v5 userinfo responses, unwrapping the `person_info` envelope.
- `StandardSingpass::Myinfo::JwksGenerator` — generates and validates the private JWKS document used for signing + ECDH-ES decryption keys. Includes a `standard_singpass:myinfo:generate_jwks` rake task.
- `StandardSingpass::Myinfo::TestPersonas` — loader for the bundled persona fixture set used by mock-callback flows and RSpec helpers; host can override via `config.personas_path`.
- `StandardSingpass::Myinfo::Configuration` — block-style config (`StandardSingpass::Myinfo.configure { |c| ... }`). Host passes `client_id`, `redirect_url`, `private_jwks_json`, optional `minimum_acr`, optional `network_wrapper` (e.g. circuit breaker), and `environment` (`:production` / `:staging` — picks Singpass endpoint URLs).
- `rails generate standard_singpass:install` scaffolds `config/initializers/standard_singpass.rb` with the full configuration surface commented out. Idempotent; `--force` overwrites.
- Full-flow integration spec at `spec/standard_singpass/myinfo/full_flow_spec.rb` walking PAR → token exchange → userinfo → JWE decrypt → JWS validate → parse end to end. Covers happy path, nonce mismatch, and the `minimum_acr` enforcement branch (LOA-3 floor + LOA-2 token → `AuthenticationError`).
- `spec/standard_singpass/myinfo/configuration_spec.rb` covering the global `configure` / `public_jwks` paths and the private-JWKS parser (happy path, malformed JSON, public-only-key rejection).
- Sorbet wired end to end: `bin/tapioca` shim, generated RBIs for runtime deps under `sorbet/rbi/gems/`, hand-edited shims for `OpenSSL::PKey::EC::Point#to_octet_string` and `Faraday.get`, `.github/workflows/typecheck.yml` running `bundle exec srb tc` on every PR, and `bundle exec srb tc` appended to the weekly-maintenance test commands so dependency-update PRs also catch type-sig breakage.
- `AGENTS.md` — quick-reference doc for AI agents and human contributors. Public surface, error taxonomy, key workflows.
- Bundled persona fixture at `fixtures/myinfo-personas.json`.
- Productivity workflows: `.github/workflows/{claude.yml,claude-code-review.yml,weekly-maintenance.yml}` + `.github/dependabot.yml` (matches peer `standard_*` gem setup).

### Notes

- No Rails routes, models, or migrations — gem is library-only by design. The host owns persistence (e.g. a MyInfo record model), orchestration (callback handlers), forms, and UI.
- `lib/standard_singpass/engine.rb` defers its `Rails::Engine` definition behind `if defined?(::Rails::Engine)` so the gem loads cleanly under `tapioca gems` and other no-Rails contexts. The host `Gemfile` should also list `gem "rails"` ahead of `gemspec` so `Bundler.require` loads Rails first.
- Coverage sits at 95.26% line / 84.29% branch with a 90% line / 75% branch floor enforced via SimpleCov.
