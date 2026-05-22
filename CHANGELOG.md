# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-23

### Added

- `StandardSingpass::Myinfo::Client` — FAPI 2.0 OAuth client with PKCE, DPoP (RFC 9449), and `private_key_jwt` client assertion. Performs PAR, token exchange, ID-token validation (iss/aud/exp/iat/sub/acr/nonce), and userinfo fetch.
- `StandardSingpass::Myinfo::Security` — PKCE/DPoP primitives, JWE decryption dispatch, JWS validation with JWKS caching and one-shot key-rotation retry.
- `StandardSingpass::Myinfo::EcdhJwe` — native ECDH-ES+A128KW / +A256KW JWE implementation covering A128GCM, A256GCM, A128CBC-HS256, A256CBC-HS512. Exists because the `jwt` gem does not support ECDH-ES key agreement.
- `StandardSingpass::Myinfo::PersonDataParser` — extracts 40+ structured fields (identity, contact, address, pass info, income, employment, assets, housing, vehicles) from FAPI 2.0 v5 userinfo responses, unwrapping the `person_info` envelope.
- `StandardSingpass::Myinfo::JwksGenerator` — generates and validates the private JWKS document used for signing + ECDH-ES decryption keys. Includes a `standard_singpass:myinfo:generate_jwks` rake task.
- `StandardSingpass::Myinfo::TestPersonas` — loader for the bundled persona fixture set used by mock-callback flows and RSpec helpers; host can override via `config.personas_path`.
- `StandardSingpass::Myinfo::Configuration` — block-style config (`StandardSingpass::Myinfo.configure { |c| ... }`). Host passes `client_id`, `redirect_url`, `private_jwks_json`, optional `minimum_acr`, optional `network_wrapper` (e.g. circuit breaker), and `environment` (`:production` / `:staging` — picks Singpass endpoint URLs).
- Bundled persona fixture at `fixtures/myinfo-personas.json`.

### Notes

- No Rails routes, models, or migrations — gem is library-only by design. The host owns persistence (e.g. a MyInfo record model), orchestration (callback handlers), forms, and UI.
