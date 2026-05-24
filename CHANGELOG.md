# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
