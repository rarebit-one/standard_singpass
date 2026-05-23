# AGENTS.md — AI Agent Guide for StandardSingpass

StandardSingpass packages the Singpass MyInfo (FAPI 2.0) OAuth client and
companion primitives — DPoP, PKCE, native ECDH-ES JWE decryption, JWS
verification with JWKS caching, person-data parsing, and JWKS generation
tooling. It is designed as a reusable Rails engine; the host owns
persistence, callback orchestration, forms, and UI.

The top-level namespace is `StandardSingpass`; MyInfo lives at
`StandardSingpass::Myinfo::*` to leave room for a future
`StandardSingpass::Auth::*` (Sign-in-with-Singpass) submodule.

## Quick Reference

```bash
# Run the full spec suite
bundle exec rspec

# Run a single spec file
bundle exec rspec spec/standard_singpass/myinfo/client_spec.rb

# Sorbet type check (RBIs are committed under sorbet/rbi/gems/)
bundle exec srb tc

# Regenerate gem RBIs after a bundle update
bundle exec tapioca gems

# Lint
bin/rubocop
bin/rubocop -A   # auto-fix

# Security checks
bundle exec brakeman --no-pager
bundle exec bundler-audit --update

# Generate a fresh private JWKS (run on a trusted machine — output contains
# private key material).
bin/rails standard_singpass:myinfo:generate_jwks > private-jwks.json
cat private-jwks.json | bin/rails standard_singpass:myinfo:validate_jwks
```

The dummy app under `spec/dummy/` is in-memory SQLite. The gem has no
migrations of its own.

## Project Structure

```
standard_singpass/
├── lib/standard_singpass/
│   ├── engine.rb                       # Mounts rake tasks at boot
│   ├── version.rb
│   ├── myinfo.rb                       # Top-level configure / public_jwks
│   └── myinfo/
│       ├── configuration.rb            # Block-style config object + DEFAULT_SCOPE
│       ├── client.rb                   # FAPI 2.0 OAuth client (PAR + token + userinfo)
│       ├── security.rb                 # PKCE, DPoP, JWE dispatch, JWS validation
│       ├── ecdh_jwe.rb                 # Native ECDH-ES key agreement + JWE codec
│       ├── person_data_parser.rb       # FAPI 2.0 v5 userinfo → 40+ field hash
│       ├── jwks_generator.rb           # Generate + validate the private JWKS
│       ├── test_personas.rb            # Load persona fixtures for mock flows
│       └── error.rb                    # Error class hierarchy
├── lib/tasks/
│   └── standard_singpass.rake          # generate_jwks / validate_jwks
├── lib/generators/standard_singpass/
│   └── install/                        # `rails g standard_singpass:install`
├── fixtures/myinfo-personas.json       # Default persona set
├── config/
└── spec/
    ├── dummy/                          # Bare Rails app, in-memory SQLite
    ├── standard_singpass/myinfo/       # Per-class specs + full_flow_spec
    ├── generators/standard_singpass/
    ├── spec_helper.rb
    └── rails_helper.rb
```

## Key Patterns

### Configuration DSL

`StandardSingpass::Myinfo.configure { |c| ... }` mutates a single
`StandardSingpass::Myinfo::Configuration` instance held in `@configuration`.
Hosts pass `client_id`, `redirect_url`, `private_jwks_json`, optional
`minimum_acr`, optional `network_wrapper` (e.g. a circuit-breaker lambda),
and `environment` (`:production` / `:staging`). The configuration object
does the env-vs-staging endpoint selection — hosts never hardcode URLs.

Tests can call `StandardSingpass::Myinfo.reset_configuration!` to drop the
memoized config between examples.

### Pluggable network wrapper

The gem ships no resilience layer of its own. Hosts compose one in via
`c.network_wrapper = ->(&blk) { Resilience.run(&blk) }`. The wrapper
sees Faraday calls only — JWE/JWS errors propagate untouched so a
breaker does not trip on key/cert misconfiguration.

### Sorbet sigils

Most lib files declare `# typed: strict` with `sig {}` annotations. The
gem ships `sorbet-runtime` as a runtime dep so consumers do not have to
opt into Sorbet themselves; the sigs become a no-op when consumers do not
run `srb tc`. RBIs for the gem's own runtime deps are committed under
`sorbet/rbi/gems/` and regenerated via `bundle exec tapioca gems`.

## Common Workflows

### Initiating a MyInfo flow

1. Generate per-request artefacts (PKCE, DPoP key, state, nonce) via
   `StandardSingpass::Myinfo::Security.{generate_pkce_pair,
   generate_ephemeral_key_pair}` and `SecureRandom`.
2. `StandardSingpass::Myinfo::Client.new.push_authorization_request(...)`
   returns a `request_uri`.
3. Build the authorize redirect with
   `client.build_authorize_redirect(request_uri:)`.
4. Persist the PKCE verifier, state, nonce, and DPoP key in the session
   so the callback handler can pick them back up.

### Handling the callback

5. `client.get_person_data(auth_code:, code_verifier:, dpop_key_pair:,
   nonce:)` returns `{ person_data:, id_token_acr: }`.
6. `StandardSingpass::Myinfo::PersonDataParser.call(person_data)` flattens
   into a 40+ key hash the host persists (typically encrypted at rest).

### Rotating the private JWKS

7. Run `bin/rails standard_singpass:myinfo:generate_jwks` on a trusted
   machine. Capture the JSON to your secret manager.
8. Update `MYINFO_PRIVATE_JWKS` (or whatever env var the host wires into
   `c.private_jwks_json`).
9. Confirm the host's public JWKS endpoint reflects the new kids with no
   `d` field.

## Testing

- `spec/dummy/` boots a minimal Rails app. No engine routes, no models.
- WebMock disables outbound HTTP (`disable_net_connect!`); specs that
  exercise the client stub Faraday directly.
- `ActiveSupport::Testing::TimeHelpers` is included globally — DPoP /
  client-assertion specs use `freeze_time` to assert iat/exp.
- Specs that mutate the global `Myinfo.configuration` should call
  `reset_configuration!` in an `after` block.
- The full-flow spec at `spec/standard_singpass/myinfo/full_flow_spec.rb`
  walks PAR → token → userinfo → JWE decrypt → JWS validate → parse using
  the gem's own `EcdhJwe.encrypt` to construct payloads. Update it
  whenever the public surface of `Client` changes.

## Error Class Taxonomy

All errors descend from `StandardSingpass::Myinfo::Error`.

| Class                  | Meaning                                                |
|------------------------|--------------------------------------------------------|
| `AuthenticationError`  | ID token / token exchange rejected (caller/config bug) |
| `ApiError`             | Endpoint reachable, non-2xx response                   |
| `PARError`             | Pushed authorization request failed                    |
| `DecryptionError`      | JWE decryption failed (key misconfig)                  |
| `SignatureError`       | JWS verification failed (key misconfig)                |
| `RateLimitError`       | Singpass returned HTTP 429                             |
| `ConfigurationError`   | Gem is misconfigured (e.g. invalid ACR URN)            |

`DecryptionError` and `SignatureError` indicate key/cert misconfiguration,
not an upstream outage. Exclude them from circuit-breaker tracking.

## Security Notes

- Private JWKS keys live in env vars / secret managers — never the repo.
  The `validate_jwks` rake task refuses public-only keys (missing `d`).
- `body_excerpt` in `Client` only surfaces a fixed allowlist of FAPI /
  OAuth error fields (`error`, `error_description`, `trace_id`, `id`,
  `state`) to error messages — Singpass error payloads can carry NRIC /
  email / other PII alongside the OAuth fields.
- `SAFE_ERROR_FIELDS` is the load-bearing allowlist; do not widen it
  without auditing what Singpass returns in error bodies.
- `bundle exec brakeman --no-pager` and `bundle exec bundler-audit --update`
  run as part of the pre-push lefthook checks.

## Key Files

| File                                                  | Purpose                                          |
|-------------------------------------------------------|--------------------------------------------------|
| `lib/standard_singpass.rb`                            | Public entrypoint + version                      |
| `lib/standard_singpass/engine.rb`                     | Rails engine + rake task loader                  |
| `lib/standard_singpass/myinfo.rb`                     | `configure`, `public_jwks`, error classes        |
| `lib/standard_singpass/myinfo/configuration.rb`       | Config object, DEFAULT_SCOPE, private JWKS parser|
| `lib/standard_singpass/myinfo/client.rb`              | FAPI 2.0 OAuth client                            |
| `lib/standard_singpass/myinfo/security.rb`            | PKCE, DPoP, JWE dispatch, JWS validation         |
| `lib/standard_singpass/myinfo/ecdh_jwe.rb`            | Native ECDH-ES JWE codec                         |
| `lib/standard_singpass/myinfo/person_data_parser.rb`  | Userinfo → host-shaped hash                      |
| `lib/standard_singpass/myinfo/jwks_generator.rb`      | Generate + validate private JWKS                 |
| `lib/standard_singpass/myinfo/test_personas.rb`       | Persona fixture loader                           |
| `lib/tasks/standard_singpass.rake`                    | Operational rake tasks                           |
| `lib/generators/standard_singpass/install/`           | Install generator (initializer scaffold)         |

## Dependencies

- **rails** — `>= 8.0`
- **faraday** — `>= 2.0` (HTTP client)
- **jwt** — `>= 2.7` (JWS/JWT signing + verification)
- **aes_key_wrap** — `~> 1.1` (RFC 3394, used by ECDH-ES+A256KW)
- **sorbet-runtime** — `~> 0.5` (sigils evaluated at load time)

Dev / test:

- **rspec-rails** — test framework
- **webmock** — outbound HTTP isolation
- **rubocop-rails-omakase** — linting
- **brakeman**, **bundler-audit** — security scanners
- **simplecov** — coverage reporting (90% line / 75% branch minimum)
- **sorbet**, **tapioca** — type checking + RBI generation
