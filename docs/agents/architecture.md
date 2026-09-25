# Architecture

Moved verbatim from `AGENTS.md` in the P3 trim. `AGENTS.md` keeps the entry points and invariants; the detail lives here.

## Project Structure

```
standard_singpass/
├── lib/standard_singpass/
│   ├── engine.rb                       # Rake tasks + after_initialize hooks
│   ├── version.rb
│   ├── error.rb                        # StandardSingpass::Error (gem-wide root)
│   ├── testing.rb                      # Test-only: Testing::EcdhJwe.encrypt
│   ├── myinfo.rb                       # Myinfo.configure / public_jwks
│   └── myinfo/
│       ├── configuration.rb            # Block-style config object (minimal DEFAULT_SCOPE)
│       ├── client.rb                   # FAPI 2.0 OAuth client (PAR + token + userinfo)
│       ├── security.rb                 # PKCE, DPoP, JWE dispatch, JWS validation
│       ├── ecdh_jwe.rb                 # Native ECDH-ES+A256KW JWE decryption
│       ├── person_data_parser.rb       # FAPI 2.0 v5 userinfo → 40+ field hash
│       ├── jwks_generator.rb           # Generate + validate the private JWKS
│       ├── test_personas.rb            # Load persona fixtures for mock flows
│       └── error.rb                    # Error class hierarchy
├── lib/tasks/
│   └── standard_singpass.rake          # generate_jwks / validate_jwks
├── lib/generators/standard_singpass/
│   └── install/                        # `rails g standard_singpass:install`
├── fixtures/myinfo-personas.json       # Default persona set
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

## Error Class Taxonomy

All errors descend from `StandardSingpass::Myinfo::Error`, which descends
from the gem-wide `StandardSingpass::Error`. `Security` raises these public
classes directly. The pre-0.4.0 `Security::DecryptionError` /
`Security::ValidationError` aliases were removed in 0.5.0 (referencing them
raises `NameError`); rescue `DecryptionError` / `SignatureError`.

| Class                  | Meaning                                                |
|------------------------|--------------------------------------------------------|
| `AuthenticationError`  | ID token / token exchange rejected (caller/config bug) |
| `ApiError`             | Endpoint reachable, non-2xx response                   |
| `PARError`             | Pushed authorization request failed                    |
| `DecryptionError`      | JWE decryption failed (key misconfig)                  |
| `SignatureError`       | JWS verification failed (key misconfig)                |
| `RateLimitError`       | Singpass returned HTTP 429                             |
| `ConfigurationError`   | Gem is misconfigured (e.g. invalid ACR URN)            |

`DecryptionError` and `SignatureError` usually indicate key/cert
misconfiguration, but a JWKS-host outage also surfaces as `SignatureError`
(with `status` / `transport?` set) — classify with `FailureClassifier`.

## Key Files

| File                                                  | Purpose                                          |
|-------------------------------------------------------|--------------------------------------------------|
| `lib/standard_singpass.rb`                            | Entrypoint; `configure` / `config` / `deprecator`|
| `lib/standard_singpass/engine.rb`                     | Rails engine: rake tasks, boot hooks             |
| `lib/standard_singpass/testing.rb`                    | Test-only JWE encryptor (not loaded by default)  |
| `lib/standard_singpass/myinfo.rb`                     | `configure`, `public_jwks`, error classes        |
| `lib/standard_singpass/myinfo/configuration.rb`       | Config object, DEFAULT_SCOPE, private JWKS parser|
| `lib/standard_singpass/myinfo/client.rb`              | FAPI 2.0 OAuth client                            |
| `lib/standard_singpass/myinfo/security.rb`            | PKCE, DPoP, JWE dispatch, JWS validation         |
| `lib/standard_singpass/myinfo/ecdh_jwe.rb`            | Native ECDH-ES JWE decryption                    |
| `lib/standard_singpass/myinfo/person_data_parser.rb`  | Userinfo → host-shaped hash                      |
| `lib/standard_singpass/myinfo/jwks_generator.rb`      | Generate + validate private JWKS                 |
| `lib/standard_singpass/myinfo/test_personas.rb`       | Persona fixture loader                           |
| `lib/tasks/standard_singpass.rake`                    | Operational rake tasks                           |
| `lib/generators/standard_singpass/install/`           | Install generator (initializer scaffold)         |

## Dependencies

- **rails** — `>= 8.1, < 9`
- **faraday** — `>= 2.0, < 3` (HTTP client)
- **jwt** — `>= 2.7, < 4` (JWS/JWT signing + verification)
- **aes_key_wrap** — `~> 1.1` (RFC 3394, used by ECDH-ES+A256KW)
- **sorbet-runtime** — `~> 0.5` (sigils evaluated at load time)

Dev / test:

- **rspec-rails** — test framework
- **webmock** — outbound HTTP isolation
- **rubocop-rails-omakase** — linting
- **brakeman**, **bundler-audit** — security scanners
- **simplecov** — coverage reporting (90% line / 75% branch minimum)
- **sorbet**, **tapioca** — type checking + RBI generation
