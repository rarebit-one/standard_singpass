require "rails_helper"

# Walks the full Singpass MyInfo round-trip end to end — PAR → token exchange
# → userinfo fetch → JWE decrypt → JWS validate → parse — using the gem's own
# EcdhJwe.encrypt + JWT.encode to construct the payloads Singpass would
# normally return. Every public surface of Client is exercised in a single
# spec so a regression anywhere on the happy path surfaces here loudly.
RSpec.describe "StandardSingpass::Myinfo full flow", type: :integration do
  let(:client_signing_key) { OpenSSL::PKey::EC.generate("prime256v1") }
  let(:client_encryption_key) { OpenSSL::PKey::EC.generate("prime256v1") }
  let(:singpass_signing_key) { OpenSSL::PKey::EC.generate("prime256v1") }

  let(:client_signing_kid) { "client-sig-1" }
  let(:client_encryption_kid) { "client-enc-1" }
  let(:singpass_signing_kid) { "singpass-sig-1" }

  let(:client_id) { "test-client-id" }
  let(:redirect_url) { "https://app.test/singpass/callback" }
  let(:issuer) { "https://stg-id.singpass.gov.sg/fapi" }

  let(:authorize_url) { "https://stg-id.singpass.gov.sg/fapi/auth" }
  let(:par_url) { "https://stg-id.singpass.gov.sg/fapi/par" }
  let(:token_url) { "https://stg-id.singpass.gov.sg/fapi/token" }
  let(:userinfo_url) { "https://stg-id.singpass.gov.sg/fapi/userinfo" }
  let(:singpass_jwks_url) { "https://stg-id.singpass.gov.sg/.well-known/keys" }

  let(:dpop_key_pair) { StandardSingpass::Myinfo::Security.generate_ephemeral_key_pair }
  let(:pkce) { StandardSingpass::Myinfo::Security.generate_pkce_pair }
  let(:state) { "state-#{SecureRandom.hex(8)}" }
  let(:nonce) { "nonce-#{SecureRandom.hex(8)}" }

  let(:client_config) do
    {
      client_id: client_id,
      redirect_url: redirect_url,
      scope: "openid uinfin name email mobileno regadd",
      authorize_url: authorize_url,
      par_url: par_url,
      token_url: token_url,
      userinfo_url: userinfo_url,
      jwks_url: singpass_jwks_url,
      userinfo_jwks_url: singpass_jwks_url,
      issuer: issuer,
      signing_key: client_signing_key.to_pem,
      signing_kid: client_signing_kid,
      encryption_keys: [{ kid: client_encryption_kid, key: client_encryption_key }]
    }
  end

  let(:client) { StandardSingpass::Myinfo::Client.new(client_config) }

  # Singpass's signing JWKS (used to verify both the id_token JWS and the
  # userinfo JWS the gem fetches back).
  let(:singpass_jwks) do
    jwk = JWT::JWK.new(singpass_signing_key, kid: singpass_signing_kid)
    { "keys" => [jwk.export.merge("alg" => "ES256")] }.to_json
  end

  # Singpass's userinfo response — JWS-signed then JWE-encrypted to our enc key.
  let(:person_data) do
    {
      "uinfin"   => { "value" => "S1234567A" },
      "name"     => { "value" => "JOHN TAN" },
      "email"    => { "value" => "john.tan@example.com" },
      "mobileno" => {
        "prefix"   => { "value" => "+" },
        "areacode" => { "value" => "65" },
        "nbr"      => { "value" => "91234567" }
      },
      "regadd" => {
        "block"   => { "value" => "123" },
        "street"  => { "value" => "ORCHARD ROAD" },
        "postal"  => { "value" => "238888" },
        "country" => { "code" => "SG" }
      },
      "residentialstatus" => { "code" => "C" }
    }
  end

  before do
    # Provide singpass JWKS — used by Security.validate_jws when verifying
    # the userinfo JWS and the inner id_token JWS.
    stub_request(:get, singpass_jwks_url).to_return(
      status: 200,
      body: singpass_jwks,
      headers: { "Content-Type" => "application/json" }
    )
    Rails.cache.clear
  end

  it "walks PAR → token exchange → userinfo → decrypt → validate → parse" do
    # --- Step 1: PAR ---
    par_response_body = { request_uri: "urn:ietf:params:oauth:request_uri:abc", expires_in: 60 }.to_json
    stub_request(:post, par_url).to_return(
      status: 201,
      body: par_response_body,
      headers: { "Content-Type" => "application/json" }
    )

    par = client.push_authorization_request(
      code_challenge: pkce[:code_challenge],
      state:          state,
      nonce:          nonce,
      dpop_key_pair:  dpop_key_pair
    )

    expect(par[:request_uri]).to eq("urn:ietf:params:oauth:request_uri:abc")
    expect(par[:expires_in]).to eq(60)

    authorize_redirect = client.build_authorize_redirect(request_uri: par[:request_uri])
    expect(authorize_redirect).to include(authorize_url, "request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc")

    # --- Step 2: token + userinfo ---
    # Build the encrypted id_token: a JWS signed by Singpass, then JWE-
    # encrypted to our enc key (FAPI 2.0 mandates this 5-segment shape).
    id_token_payload = {
      "iss"   => issuer,
      "aud"   => client_id,
      "sub"   => "singpass-sub-123",
      "iat"   => Time.now.to_i,
      "exp"   => (Time.now + 5.minutes).to_i,
      "nonce" => nonce,
      "acr"   => "urn:singpass:authentication:loa:3"
    }
    id_token_jws = JWT.encode(id_token_payload, singpass_signing_key, "ES256", { kid: singpass_signing_kid })
    id_token_jwe = StandardSingpass::Myinfo::EcdhJwe.encrypt(
      id_token_jws,
      public_key: client_encryption_key,
      alg:        "ECDH-ES+A256KW",
      enc:        "A256GCM",
      kid:        client_encryption_kid
    )

    stub_request(:post, token_url).to_return(
      status: 200,
      body:   { access_token: "DPoP-bound-access-token", id_token: id_token_jwe }.to_json,
      headers: { "Content-Type" => "application/json" }
    )

    # Build the userinfo response: JWS-signed person_data, then JWE-encrypted
    # to our enc key. Singpass nests person attributes under person_info on
    # FAPI 2.0 v5 — the parser unwraps that envelope automatically.
    userinfo_payload = { "sub" => "singpass-sub-123", "person_info" => person_data }
    userinfo_jws = JWT.encode(userinfo_payload, singpass_signing_key, "ES256", { kid: singpass_signing_kid })
    userinfo_jwe = StandardSingpass::Myinfo::EcdhJwe.encrypt(
      userinfo_jws,
      public_key: client_encryption_key,
      alg:        "ECDH-ES+A256KW",
      enc:        "A256GCM",
      kid:        client_encryption_kid
    )

    stub_request(:get, userinfo_url).to_return(
      status: 200,
      body:   userinfo_jwe,
      headers: { "Content-Type" => "application/jose" }
    )

    result = client.get_person_data(
      auth_code:     "authorization-code-abc",
      code_verifier: pkce[:code_verifier],
      dpop_key_pair: dpop_key_pair,
      nonce:         nonce
    )

    expect(result[:id_token_acr]).to eq("urn:singpass:authentication:loa:3")
    expect(result[:person_data]).to include("person_info")

    # --- Step 3: parse ---
    parsed = StandardSingpass::Myinfo::PersonDataParser.call(result[:person_data])

    expect(parsed).to include(
      nric:          "S1234567A",
      name:          "JOHN TAN",
      email:         "john.tan@example.com",
      mobile_number: "+6591234567",
      residential_status: "C"
    )
    expect(parsed[:registered_address]).to include(
      block:   "123",
      street:  "ORCHARD ROAD",
      postal:  "238888",
      country: "SG"
    )
  end

  it "raises AuthenticationError when the id_token nonce does not match the session nonce" do
    id_token_payload = {
      "iss"   => issuer,
      "aud"   => client_id,
      "sub"   => "singpass-sub-123",
      "iat"   => Time.now.to_i,
      "exp"   => (Time.now + 5.minutes).to_i,
      "nonce" => "different-nonce",
      "acr"   => "urn:singpass:authentication:loa:3"
    }
    id_token_jws = JWT.encode(id_token_payload, singpass_signing_key, "ES256", { kid: singpass_signing_kid })
    id_token_jwe = StandardSingpass::Myinfo::EcdhJwe.encrypt(
      id_token_jws,
      public_key: client_encryption_key,
      alg:        "ECDH-ES+A256KW",
      enc:        "A256GCM",
      kid:        client_encryption_kid
    )

    stub_request(:post, token_url).to_return(
      status:  200,
      body:    { access_token: "tok", id_token: id_token_jwe }.to_json,
      headers: { "Content-Type" => "application/json" }
    )

    expect {
      client.get_person_data(
        auth_code: "code",
        code_verifier: pkce[:code_verifier],
        dpop_key_pair: dpop_key_pair,
        nonce: nonce
      )
    }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /nonce does not match/)
  end

  it "raises AuthenticationError when the id_token acr is below the configured minimum_acr" do
    # New client wired with a LOA-3 floor — Singpass's `acr` URN format is
    # `urn:singpass:authentication:loa:N`, with N restricted to 2 or 3.
    acr_locked_client = StandardSingpass::Myinfo::Client.new(
      client_config.merge(minimum_acr: "urn:singpass:authentication:loa:3")
    )

    id_token_payload = {
      "iss"   => issuer,
      "aud"   => client_id,
      "sub"   => "singpass-sub-123",
      "iat"   => Time.now.to_i,
      "exp"   => (Time.now + 5.minutes).to_i,
      "nonce" => nonce,
      "acr"   => "urn:singpass:authentication:loa:2" # below the configured loa:3 floor
    }
    id_token_jws = JWT.encode(id_token_payload, singpass_signing_key, "ES256", { kid: singpass_signing_kid })
    id_token_jwe = StandardSingpass::Myinfo::EcdhJwe.encrypt(
      id_token_jws,
      public_key: client_encryption_key,
      alg:        "ECDH-ES+A256KW",
      enc:        "A256GCM",
      kid:        client_encryption_kid
    )

    stub_request(:post, token_url).to_return(
      status:  200,
      body:    { access_token: "tok", id_token: id_token_jwe }.to_json,
      headers: { "Content-Type" => "application/json" }
    )

    expect {
      acr_locked_client.get_person_data(
        auth_code: "code",
        code_verifier: pkce[:code_verifier],
        dpop_key_pair: dpop_key_pair,
        nonce: nonce
      )
    }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /below required minimum/)
  end
end
