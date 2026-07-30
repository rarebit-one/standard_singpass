# StandardSingpass

Singpass MyInfo (FAPI 2.0) client for Rails applications. Packages the OAuth flow, DPoP/PKCE primitives, native ECDH-ES JWE decryption, JWS validation, and person-data parser needed to integrate with Singpass MyInfo.

The gem is intentionally **library-only** — it does not own routes, models, migrations, or UI. The host application owns persistence, orchestration, forms, and presentation.

## Installation

Add to your Gemfile:

```ruby
gem "standard_singpass"
```

## Configuration

```ruby
# config/initializers/standard_singpass.rb
StandardSingpass::Myinfo.configure do |c|
  # Endpoint set. Drives production vs. staging Singpass URLs.
  c.environment = Rails.env.production? ? :production : :staging

  # Client credentials.
  c.client_id        = ENV["MYINFO_CLIENT_ID"]
  c.redirect_url     = ENV["MYINFO_REDIRECT_URL"]

  # Optional: override default scope (defaults to a 36-attribute set covering
  # identity, contact, income, employment, housing, assets, vehicles).
  # c.scope = "openid name email ..."

  # Required: full private JWKS JSON containing both sig (ES256) and enc
  # (ECDH-ES+A256KW) keys with the private scalar `d`.
  c.private_jwks_json = ENV["MYINFO_PRIVATE_JWKS"]

  # Optional: enforce minimum Authentication Context Class Reference. Set to
  # e.g. "urn:singpass:authentication:loa:3" to require high-assurance.
  c.minimum_acr = ENV["MYINFO_MIN_ACR"]

  # Optional: wrap outbound HTTP calls with a circuit breaker / retry layer.
  # Defaults to identity (no wrapper).
  # c.network_wrapper = ->(&block) { StandardCircuit.run(:myinfo, &block) }

  # Optional: path to a JSON file of test personas (for mock callback flows).
  # Defaults to the gem's bundled fixtures/myinfo-personas.json.
  # c.personas_path = Rails.root.join("e2e/fixtures/myinfo-personas.json")

  # Optional: serve fixture persona data instead of running the real FAPI 2.0
  # flow. Refused outright on a production deploy — see "Mock mode" below.
  c.mock_mode = ENV["MYINFO_MOCK_MODE"].present?

  # Optional: how the gem decides whether this deploy is real production, for
  # the mock-mode guard. Defaults to Rails.env.production?.
  # c.production_env_detector = -> { AppEnv.production? }
end
```

## Mock mode

`config.mock_mode` makes the host serve fixture persona data
(`StandardSingpass::Myinfo::TestPersonas`) instead of running the real
Singpass flow — right for development, CI, and staging rehearsals, and
catastrophic in production, where real users would submit fabricated identity
data indistinguishable from verified MyInfo data downstream.

**The gem enforces that.** An `after_initialize` hook runs
`StandardSingpass::Myinfo::MockModeGuard.check!` on every boot. There is no
opt-out — a guard you can forget to wire is a guard that isn't there.

| Deploy | Mock mode on | Behaviour |
|---|---|---|
| Production | yes | **Raises `ConfigurationError` — the app refuses to boot.** |
| `RAILS_ENV=production` but not production | yes | Logs an error and reports via `Rails.error`; boots. |
| Anything else | yes | Silent. |
| Any | no | Silent. |

By default "production" means `Rails.env.production?`. Staging and preview
deploys routinely run `RAILS_ENV=production` while being entirely legitimate
places to enable mock mode, so hosts that distinguish a physical deploy
environment from `RAILS_ENV` should say so:

```ruby
# Mock mode stays legal on a physically-staging box, still refused on real prod.
c.production_env_detector = -> { AppEnv.production? }
```

`production_env_detector` takes no arguments and returns a boolean; when `nil`
(the default) the gem falls back to `Rails.env.production?`, so existing
consumers are unaffected. The production-like tier reports through
`Rails.error` rather than a specific error tracker, so whatever the host has
subscribed (Sentry included) picks it up.

## Initiating the flow

```ruby
pkce       = StandardSingpass::Myinfo::Security.generate_pkce_pair
dpop_key   = StandardSingpass::Myinfo::Security.generate_ephemeral_key_pair
state      = SecureRandom.hex(16)
nonce      = SecureRandom.hex(16)

client = StandardSingpass::Myinfo::Client.new
par    = client.push_authorization_request(
  code_challenge: pkce[:code_challenge],
  state:          state,
  nonce:          nonce,
  dpop_key_pair:  dpop_key
)

# Persist pkce[:code_verifier], state, nonce, and dpop_key in the user session.
redirect_to client.build_authorize_redirect(request_uri: par[:request_uri])
```

## Handling the callback

```ruby
result = client.get_person_data(
  auth_code:     params[:code],
  code_verifier: session[:myinfo_code_verifier],
  dpop_key_pair: session[:myinfo_dpop_key],
  nonce:         session[:myinfo_nonce]
)

parsed = StandardSingpass::Myinfo::PersonDataParser.call(result[:person_data])
acr    = result[:id_token_acr]

# `parsed` is a 40+ key hash: nric, name, email, mobile_number,
# registered_address, cpf_balances, noa, hdb_ownership, etc. Pass it to your
# host-side persistence / projection layer.
```

### Notice-of-Assessment scopes

Singpass approves NOA access at one of two widths, and the width is a property
of the *app registration*, not of the request: `noa` yields the latest year
only, `noahistory` the last two. `PersonDataParser` mirrors that faithfully,
emitting `:noa` (one record) or `:noa_history` (an array) — so consumers that
just want "the NOA records" would each write the same branch.
`StandardSingpass::Myinfo::Noa` is that branch:

```ruby
# An array of NOA records regardless of which scope was granted, or nil when
# neither yielded data. Prefers the 2-year history when both are present.
StandardSingpass::Myinfo::Noa.history(parsed)

# Same, for the narrower `noa-basic` / `noahistory-basic` scope pair.
StandardSingpass::Myinfo::Noa.basic_history(parsed)
```

Keys are read as both Symbols and Strings, so a hash round-tripped through
JSON or a database column works unchanged.

## Generating and serving JWKS

The host application is responsible for serving the public JWKS at
`/.well-known/jwks.json` (or another endpoint Singpass is configured to fetch).

```ruby
# Generate a fresh private JWKS (run locally, never in CI):
bin/rails standard_singpass:myinfo:generate_jwks > private-jwks.json

# Serve the public JWKS from a controller:
render json: StandardSingpass::Myinfo.public_jwks
```

## Error classes

All errors descend from `StandardSingpass::Myinfo::Error`:

- `AuthenticationError` — ID token or token exchange rejected
- `ApiError` — endpoint reachable but returned a non-2xx response
- `PARError` — pushed authorization request failed
- `DecryptionError` — JWE decryption failed
- `SignatureError` — JWS verification failed
- `RateLimitError` — Singpass returned HTTP 429
- `ConfigurationError` — gem is misconfigured (e.g. invalid ACR URN)

`DecryptionError` and `SignatureError` usually indicate a key/cert misconfiguration rather than an upstream outage. **Usually, not always:** verifying a signature requires fetching Singpass's JWKS, so a JWKS host that is down surfaces as a `SignatureError` (or an `AuthenticationError` on the ID-token leg) too. Those carry the JWKS response's `status` / `transport?`, so ask `FailureClassifier` rather than deciding by class — including when choosing what to feed a circuit breaker.

Every error carries two facts, on the base class rather than on any one subclass — a 502 is a 502 whichever leg of the flow returned it:

- `status` — the HTTP status of the offending response (`nil` for transport failures and for errors a host raises itself)
- `transport?` — true when the request never reached Singpass at all (DNS, connection refused, TLS, read timeout)

### Classifying a failure

What the host tells the user turns on one question: is Singpass unavailable, or is our request wrong? An unavailable upstream clears itself within minutes, so "try again shortly" is the honest instruction; "contact support and quote this reference" is a dead end. Get the answer from the gem rather than re-deriving it:

```ruby
if StandardSingpass::Myinfo::FailureClassifier.upstream_unavailable?(error)
  # 502/503/504, HTTP 429, or a transport failure on any leg.
  # Tell the user to retry shortly.
else
  # Our request, our keys, or our config. Surface it to support.
end
```

This covers every leg — PAR, token exchange, userinfo, and the JWKS fetches that back signature verification. 502 is Singpass's documented signal that a MyInfo upstream agency (CPF Board, IRAS, MOM, …) is unavailable — returned both for genuine blips and throughout their [published maintenance windows](https://docs.developer.singpass.gov.sg/docs/products/singpass-myinfo/scheduled-downtimes); 503/504 are the generic equivalents. The list is `FailureClassifier::UPSTREAM_UNAVAILABLE_STATUSES`, and the client's automatic userinfo retry uses that same constant.

**Never classify by matching the message text** — it is not a stable interface. That is exactly what `transport?` and `status` exist to replace.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
