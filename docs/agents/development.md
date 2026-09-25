# Development and testing

Moved verbatim from `AGENTS.md` in the P3 trim. `AGENTS.md` keeps a condensed command list.

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
  `StandardSingpass::Testing::EcdhJwe.encrypt` (from
  `require "standard_singpass/testing"`, loaded in `rails_helper.rb`) to
  construct payloads. Update it
  whenever the public surface of `Client` changes.
