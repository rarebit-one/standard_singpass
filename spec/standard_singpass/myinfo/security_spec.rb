require "rails_helper"

RSpec.describe StandardSingpass::Myinfo::Security do
  describe ".generate_pkce_pair" do
    it "returns a hash with code_verifier and code_challenge" do
      pair = described_class.generate_pkce_pair
      expect(pair).to have_key(:code_verifier)
      expect(pair).to have_key(:code_challenge)
    end

    it "generates a code_verifier of expected length" do
      pair = described_class.generate_pkce_pair
      expect(pair[:code_verifier].length).to eq(64)
    end

    it "produces a code_challenge that is the S256 hash of the verifier" do
      pair = described_class.generate_pkce_pair
      expected_challenge = Base64.urlsafe_encode64(
        Digest::SHA256.digest(pair[:code_verifier]), padding: false
      )
      expect(pair[:code_challenge]).to eq(expected_challenge)
    end

    it "generates unique pairs on each call" do
      pair1 = described_class.generate_pkce_pair
      pair2 = described_class.generate_pkce_pair
      expect(pair1[:code_verifier]).not_to eq(pair2[:code_verifier])
    end
  end

  describe ".generate_ephemeral_key_pair" do
    it "returns an EC key on the prime256v1 curve" do
      key = described_class.generate_ephemeral_key_pair
      expect(key).to be_a(OpenSSL::PKey::EC)
      expect(key.group.curve_name).to eq("prime256v1")
    end

    it "includes a private key" do
      key = described_class.generate_ephemeral_key_pair
      expect(key.private?).to be true
    end
  end

  describe ".build_dpop_proof" do
    let(:key_pair) { described_class.generate_ephemeral_key_pair }
    let(:url) { "https://stg-id.singpass.gov.sg/fapi/token" }

    it "returns a valid JWT string" do
      proof = described_class.build_dpop_proof(http_method: "POST", url:, key_pair:)
      expect(proof).to be_a(String)
      expect(proof.split(".").length).to eq(3)
    end

    it "sets the correct header fields" do
      proof = described_class.build_dpop_proof(http_method: "POST", url:, key_pair:)
      header = JWT.decode(proof, nil, false).last

      expect(header["typ"]).to eq("dpop+jwt")
      expect(header["alg"]).to eq("ES256")
      expect(header["jwk"]).to be_present
      expect(header["jwk"]["kty"]).to eq("EC")
      expect(header["jwk"]["crv"]).to eq("P-256")
    end

    it "includes the correct claims" do
      freeze_time do
        proof = described_class.build_dpop_proof(http_method: "POST", url:, key_pair:)
        payload = JWT.decode(proof, nil, false).first

        expect(payload["htm"]).to eq("POST")
        expect(payload["htu"]).to eq(url)
        expect(payload["iat"]).to eq(Time.now.to_i)
        expect(payload["exp"]).to eq((Time.current + 2.minutes).to_i)
        expect(payload["jti"]).to be_present
      end
    end

    it "uppercases the HTTP method" do
      proof = described_class.build_dpop_proof(http_method: "get", url:, key_pair:)
      payload = JWT.decode(proof, nil, false).first
      expect(payload["htm"]).to eq("GET")
    end

    it "omits ath claim when no access_token is provided" do
      proof = described_class.build_dpop_proof(http_method: "POST", url:, key_pair:)
      payload = JWT.decode(proof, nil, false).first
      expect(payload).not_to have_key("ath")
    end

    it "includes ath claim when access_token is provided" do
      token = "some-access-token"
      proof = described_class.build_dpop_proof(
        http_method: "GET", url:, key_pair:, access_token: token
      )
      payload = JWT.decode(proof, nil, false).first

      expected_ath = Base64.urlsafe_encode64(
        Digest::SHA256.digest(token), padding: false
      )
      expect(payload["ath"]).to eq(expected_ath)
    end

    it "can be verified with the embedded public key" do
      proof = described_class.build_dpop_proof(http_method: "POST", url:, key_pair:)
      header = JWT.decode(proof, nil, false).last
      jwk = JWT::JWK.new(header["jwk"])

      expect { JWT.decode(proof, jwk.keypair, true, algorithms: [ "ES256" ]) }.not_to raise_error
    end

    it "strips query string and fragment from htu" do
      url_with_params = "https://stg-id.singpass.gov.sg/fapi/token?foo=bar#frag"
      proof = described_class.build_dpop_proof(http_method: "POST", url: url_with_params, key_pair:)
      payload = JWT.decode(proof, nil, false).first
      expect(payload["htu"]).to eq("https://stg-id.singpass.gov.sg/fapi/token")
    end

    it "generates unique jti values" do
      proof1 = described_class.build_dpop_proof(http_method: "POST", url:, key_pair:)
      proof2 = described_class.build_dpop_proof(http_method: "POST", url:, key_pair:)

      jti1 = JWT.decode(proof1, nil, false).first["jti"]
      jti2 = JWT.decode(proof2, nil, false).first["jti"]
      expect(jti1).not_to eq(jti2)
    end
  end

  describe ".build_client_assertion" do
    let(:signing_key) { OpenSSL::PKey::EC.generate("prime256v1") }
    let(:client_id) { "test-client-id" }
    let(:audience) { "https://stg-id.singpass.gov.sg/fapi" }
    let(:signing_kid) { "test-signing-key-1" }

    it "returns a valid JWT string" do
      assertion = described_class.build_client_assertion(
        client_id:, audience:,
        signing_key:, signing_kid:
      )
      expect(assertion).to be_a(String)
      expect(assertion.split(".").length).to eq(3)
    end

    it "sets the correct header" do
      assertion = described_class.build_client_assertion(
        client_id:, audience:,
        signing_key:, signing_kid:
      )
      header = JWT.decode(assertion, nil, false).last

      expect(header["alg"]).to eq("ES256")
      expect(header["kid"]).to eq(signing_kid)
      expect(header["typ"]).to eq("JWT")
    end

    it "includes the correct claims" do
      freeze_time do
        assertion = described_class.build_client_assertion(
          client_id:, audience:,
          signing_key:, signing_kid:
        )
        payload = JWT.decode(assertion, nil, false).first

        expect(payload["iss"]).to eq(client_id)
        expect(payload["sub"]).to eq(client_id)
        expect(payload["aud"]).to eq(audience)
        expect(payload["iat"]).to eq(Time.current.to_i)
        expect(payload["exp"]).to eq((Time.current + 2.minutes).to_i)
        expect(payload["jti"]).to be_present
      end
    end

    it "can be verified with the corresponding public key" do
      assertion = described_class.build_client_assertion(
        client_id:, audience:,
        signing_key:, signing_kid:
      )

      expect {
        JWT.decode(assertion, signing_key, true, algorithms: [ "ES256" ])
      }.not_to raise_error
    end

    it "accepts a PEM string as signing_key" do
      pem = signing_key.to_pem
      assertion = described_class.build_client_assertion(
        client_id:, audience:,
        signing_key: pem, signing_kid:
      )
      payload = JWT.decode(assertion, nil, false).first
      expect(payload["iss"]).to eq(client_id)
    end

    it "generates unique jti values" do
      a1 = described_class.build_client_assertion(
        client_id:, audience:,
        signing_key:, signing_kid:
      )
      a2 = described_class.build_client_assertion(
        client_id:, audience:,
        signing_key:, signing_kid:
      )

      jti1 = JWT.decode(a1, nil, false).first["jti"]
      jti2 = JWT.decode(a2, nil, false).first["jti"]
      expect(jti1).not_to eq(jti2)
    end

    it "includes code claim when provided" do
      assertion = described_class.build_client_assertion(
        client_id:, audience:,
        signing_key:, signing_kid:,
        code: "auth-code-123"
      )
      payload = JWT.decode(assertion, nil, false).first
      expect(payload["code"]).to eq("auth-code-123")
    end

    it "omits code claim when not provided" do
      assertion = described_class.build_client_assertion(
        client_id:, audience:,
        signing_key:, signing_kid:
      )
      payload = JWT.decode(assertion, nil, false).first
      expect(payload).not_to have_key("code")
    end
  end

  describe ".decrypt_jwe" do
    let(:ec_key_1) { OpenSSL::PKey::EC.generate("prime256v1") }
    let(:ec_key_2) { OpenSSL::PKey::EC.generate("prime256v1") }
    let(:payload) { '{"sub":"S1234567A","name":"John Doe"}' }

    def build_jwe(payload, public_key, kid)
      StandardSingpass::Myinfo::EcdhJwe.encrypt(
        payload,
        public_key:,
        alg: "ECDH-ES+A256KW",
        enc: "A256CBC-HS512",
        kid:
      )
    end

    it "decrypts a JWE with the matching key" do
      jwe_string = build_jwe(payload, ec_key_1, "key-1")

      result = described_class.decrypt_jwe(
        jwe_string,
        private_keys: [ { kid: "key-1", key: ec_key_1 } ]
      )
      expect(result).to eq(payload)
    end

    it "selects the correct key from multiple private keys" do
      jwe_string = build_jwe(payload, ec_key_2, "key-2")

      result = described_class.decrypt_jwe(
        jwe_string,
        private_keys: [
          { kid: "key-1", key: ec_key_1 },
          { kid: "key-2", key: ec_key_2 }
        ]
      )
      expect(result).to eq(payload)
    end

    it "raises DecryptionError when no matching kid is found" do
      jwe_string = build_jwe(payload, ec_key_1, "unknown-kid")

      expect {
        described_class.decrypt_jwe(
          jwe_string,
          private_keys: [ { kid: "key-1", key: ec_key_1 } ]
        )
      }.to raise_error(StandardSingpass::Myinfo::Security::DecryptionError, /No matching decryption key found/)
    end

    it "raises DecryptionError when the wrong key is used" do
      jwe_string = build_jwe(payload, ec_key_1, "key-2")

      expect {
        described_class.decrypt_jwe(
          jwe_string,
          private_keys: [ { kid: "key-2", key: ec_key_2 } ]
        )
      }.to raise_error(StandardSingpass::Myinfo::Security::DecryptionError)
    end

    it "accepts PEM string keys" do
      jwe_string = build_jwe(payload, ec_key_1, "key-1")

      result = described_class.decrypt_jwe(
        jwe_string,
        private_keys: [ { kid: "key-1", key: ec_key_1.to_pem } ]
      )
      expect(result).to eq(payload)
    end

    it "raises DecryptionError for malformed JWE" do
      expect {
        described_class.decrypt_jwe(
          "not.a.valid.jwe.string",
          private_keys: [ { kid: "key-1", key: ec_key_1 } ]
        )
      }.to raise_error(StandardSingpass::Myinfo::Security::DecryptionError)
    end

    it "raises DecryptionError when JWE header is missing kid field" do
      header = Base64.urlsafe_encode64({ "alg" => "ECDH-ES+A256KW", "enc" => "A256CBC-HS512" }.to_json, padding: false)
      jwe_string = "#{header}.fake.fake.fake.fake"

      expect {
        described_class.decrypt_jwe(
          jwe_string,
          private_keys: [ { kid: "key-1", key: ec_key_1 } ]
        )
      }.to raise_error(StandardSingpass::Myinfo::Security::DecryptionError, /JWE header missing kid field/)
    end

    it "rejects non-FAPI-2.0 algs (e.g. RSA-OAEP)" do
      header = Base64.urlsafe_encode64({ "alg" => "RSA-OAEP", "enc" => "A256GCM", "kid" => "key-1" }.to_json, padding: false)
      jwe_string = "#{header}.fake.fake.fake.fake"

      expect {
        described_class.decrypt_jwe(
          jwe_string,
          private_keys: [ { kid: "key-1", key: ec_key_1 } ]
        )
      }.to raise_error(StandardSingpass::Myinfo::Security::DecryptionError, /Unsupported JWE alg.*FAPI 2\.0 requires/)
    end
  end

  describe ".validate_jws" do
    let(:ec_key) { OpenSSL::PKey::EC.generate("prime256v1") }
    let(:kid) { "test-jwks-key-1" }
    let(:jwks_url) { "https://test.api.myinfo.gov.sg/.well-known/keys" }
    let(:payload) { { "sub" => "S1234567A", "name" => "John Doe" } }

    let(:jwks_json) do
      jwk = JWT::JWK.new(ec_key, kid:)
      { "keys" => [ jwk.export.merge("alg" => "ES256") ] }.to_json
    end

    def sign_jws(payload, key, kid)
      JWT.encode(payload, key, "ES256", { kid: })
    end

    def stub_jwks_request(status:, body:)
      stub_jwks_request_for(jwks_url, status:, body:)
    end

    def stub_jwks_request_for(url, status:, body:)
      faraday_response = instance_double(Faraday::Response, status:, body:, success?: status == 200)
      allow(Faraday).to receive(:get).with(url).and_return(faraday_response)
    end

    before do
      Rails.cache.clear
      stub_jwks_request(status: 200, body: jwks_json)
    end

    it "validates and decodes a valid JWS" do
      jws = sign_jws(payload, ec_key, kid)
      result = described_class.validate_jws(jws, jwks_url:)
      expect(result).to include("sub" => "S1234567A", "name" => "John Doe")
    end

    it "raises ValidationError for an invalid signature" do
      other_key = OpenSSL::PKey::EC.generate("prime256v1")
      jws = sign_jws(payload, other_key, kid)

      expect {
        described_class.validate_jws(jws, jwks_url:)
      }.to raise_error(StandardSingpass::Myinfo::Security::ValidationError, /JWS validation failed/)
    end

    it "raises ValidationError when JWKS fetch fails" do
      stub_jwks_request(status: 500, body: "error")

      jws = sign_jws(payload, ec_key, kid)
      expect {
        described_class.validate_jws(jws, jwks_url:)
      }.to raise_error(StandardSingpass::Myinfo::Security::ValidationError, /Failed to fetch JWKS/)
    end

    it "caches JWKS responses" do
      memory_store = ActiveSupport::Cache::MemoryStore.new
      allow(Rails).to receive(:cache).and_return(memory_store)

      call_count = 0
      faraday_response = instance_double(Faraday::Response, status: 200, body: jwks_json, success?: true)
      cache_url = "https://test.api.myinfo.gov.sg/.well-known/keys/#{SecureRandom.hex(4)}"

      allow(Faraday).to receive(:get).with(cache_url) do
        call_count += 1
        faraday_response
      end

      jws = sign_jws(payload, ec_key, kid)

      described_class.validate_jws(jws, jwks_url: cache_url)
      described_class.validate_jws(jws, jwks_url: cache_url)

      expect(call_count).to eq(1)
    end

    it "raises ValidationError when JWKS endpoint is unreachable" do
      allow(Faraday).to receive(:get).and_raise(Faraday::ConnectionFailed.new("Connection refused"))

      jws = sign_jws(payload, ec_key, kid)
      expect {
        described_class.validate_jws(jws, jwks_url:)
      }.to raise_error(StandardSingpass::Myinfo::Security::ValidationError, /Connection refused/)
    end

    it "raises ValidationError for a malformed JWS" do
      expect {
        described_class.validate_jws("not.a.valid.jws", jwks_url:)
      }.to raise_error(StandardSingpass::Myinfo::Security::ValidationError)
    end

    it "raises ValidationError for an expired JWT" do
      expired_payload = payload.merge("exp" => (Time.now - 1.hour).to_i)
      jws = sign_jws(expired_payload, ec_key, kid)

      expect {
        described_class.validate_jws(jws, jwks_url:)
      }.to raise_error(StandardSingpass::Myinfo::Security::ValidationError, /Signature has expired/)
    end

    context "when JWKS keys are rotated" do
      let(:old_key) { OpenSSL::PKey::EC.generate("prime256v1") }
      let(:new_key) { ec_key }

      let(:old_jwks_json) do
        jwk = JWT::JWK.new(old_key, kid:)
        { "keys" => [ jwk.export.merge("alg" => "ES256") ] }.to_json
      end

      it "retries with fresh JWKS on signature verification failure" do
        memory_store = ActiveSupport::Cache::MemoryStore.new
        allow(Rails).to receive(:cache).and_return(memory_store)

        rotation_url = "https://test.api.myinfo.gov.sg/.well-known/keys/#{SecureRandom.hex(4)}"
        call_count = 0

        old_response = instance_double(Faraday::Response, status: 200, body: old_jwks_json, success?: true)
        new_response = instance_double(Faraday::Response, status: 200, body: jwks_json, success?: true)

        allow(Faraday).to receive(:get).with(rotation_url) do
          call_count += 1
          call_count == 1 ? old_response : new_response
        end

        jws = sign_jws(payload, new_key, kid)
        result = described_class.validate_jws(jws, jwks_url: rotation_url)

        expect(result).to include("sub" => "S1234567A", "name" => "John Doe")
        expect(call_count).to eq(2)
      end

      it "does not retry when the token is expired" do
        memory_store = ActiveSupport::Cache::MemoryStore.new
        allow(Rails).to receive(:cache).and_return(memory_store)

        rotation_url = "https://test.api.myinfo.gov.sg/.well-known/keys/#{SecureRandom.hex(4)}"

        correct_response = instance_double(Faraday::Response, status: 200, body: jwks_json, success?: true)
        allow(Faraday).to receive(:get).with(rotation_url).and_return(correct_response)

        expired_payload = payload.merge("exp" => (Time.now - 1.hour).to_i)
        jws = sign_jws(expired_payload, ec_key, kid)

        expect {
          described_class.validate_jws(jws, jwks_url: rotation_url)
        }.to raise_error(StandardSingpass::Myinfo::Security::ValidationError, /expired/i)

        expect(Faraday).to have_received(:get).with(rotation_url).once
      end

      it "raises ValidationError when retry also fails" do
        memory_store = ActiveSupport::Cache::MemoryStore.new
        allow(Rails).to receive(:cache).and_return(memory_store)

        rotation_url = "https://test.api.myinfo.gov.sg/.well-known/keys/#{SecureRandom.hex(4)}"
        old_response = instance_double(Faraday::Response, status: 200, body: old_jwks_json, success?: true)

        allow(Faraday).to receive(:get).with(rotation_url).and_return(old_response)

        jws = sign_jws(payload, new_key, kid)

        expect {
          described_class.validate_jws(jws, jwks_url: rotation_url)
        }.to raise_error(StandardSingpass::Myinfo::Security::ValidationError, /JWS validation failed/)
      end
    end

    context "when JWKS keys omit the alg field" do
      let(:ec_key_no_alg) { OpenSSL::PKey::EC.generate("prime256v1") }
      let(:ec_kid) { "test-ec-key-1" }

      let(:jwks_without_alg) do
        jwk = JWT::JWK.new(ec_key_no_alg, kid: ec_kid)
        { "keys" => [ jwk.export ] }.to_json
      end

      before do
        stub_jwks_request(status: 200, body: jwks_without_alg)
      end

      it "defaults to ES256 (FAPI 2.0 mandate)" do
        jws = JWT.encode(payload, ec_key_no_alg, "ES256", { kid: ec_kid })
        result = described_class.validate_jws(jws, jwks_url:)
        expect(result).to include("sub" => "S1234567A", "name" => "John Doe")
      end
    end

    # Regression pin: even if a future Singpass JWKS happens to advertise
    # an RSA key, the validator must refuse RS256 tokens — FAPI 2.0
    # mandates ES256 and we narrowed ALLOWED_ALGORITHMS accordingly.
    context "when JWKS contains an RSA key and the token is RS256-signed" do
      let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
      let(:rsa_kid) { "test-rsa-key-1" }

      let(:rsa_jwks_json) do
        jwk = JWT::JWK.new(rsa_key, kid: rsa_kid)
        { "keys" => [ jwk.export.merge("alg" => "RS256") ] }.to_json
      end

      before do
        stub_jwks_request(status: 200, body: rsa_jwks_json)
      end

      it "rejects the token as a ValidationError" do
        rs_jws = JWT.encode(payload, rsa_key, "RS256", { kid: rsa_kid })
        expect {
          described_class.validate_jws(rs_jws, jwks_url:)
        }.to raise_error(StandardSingpass::Myinfo::Security::ValidationError)
      end
    end
  end
end
