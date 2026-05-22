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
end
```

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

`DecryptionError` and `SignatureError` indicate a key/cert misconfiguration, not an upstream outage — exclude them from circuit-breaker tracking if you use one.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
