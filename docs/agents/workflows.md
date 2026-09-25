# Common workflows

Moved verbatim from `AGENTS.md` in the P3 trim.

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
