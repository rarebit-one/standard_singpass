require "rails_helper"

RSpec.describe StandardSingpass::Myinfo::Client do
  let(:config) do
    {
      client_id: "test-client-id",
      redirect_url: "https://app.test/callback",
      scope: "openid uinfin name sex race nationality dob email mobileno regadd",
      token_url: "https://stg-id.singpass.gov.sg/fapi/token",
      userinfo_url: "https://stg-id.singpass.gov.sg/fapi/userinfo",
      authorize_url: "https://stg-id.singpass.gov.sg/fapi/auth",
      par_url: "https://stg-id.singpass.gov.sg/fapi/par",
      signing_key: "test-signing-key",
      signing_kid: "test-signing-kid",
      encryption_keys: [{ kid: "test-enc-kid", key: "test-encryption-key" }],
      jwks_url: "https://stg-id.singpass.gov.sg/.well-known/keys",
      userinfo_jwks_url: "https://stg-id.singpass.gov.sg/.well-known/keys",
      issuer: "https://stg-id.singpass.gov.sg/fapi"
    }
  end

  let(:client) { described_class.new(config) }
  let(:dpop_key_pair) { OpenSSL::PKey::EC.generate("prime256v1") }
  let(:token_url) { config[:token_url] }
  let(:userinfo_url) { config[:userinfo_url] }

  let(:nonce) { "test-nonce-value" }

  let(:access_token) do
    payload = { "sub" => "S1234567A", "exp" => Time.now.to_i + 300 }
    JWT.encode(payload, nil, "none")
  end

  let(:id_token_claims) do
    {
      "nonce" => nonce,
      "sub" => "opaque-app-uuid",
      "iss" => "https://stg-id.singpass.gov.sg/fapi",
      "aud" => "test-client-id",
      "exp" => Time.now.to_i + 300,
      "iat" => Time.now.to_i
    }
  end

  # FAPI 2.0 always returns id_tokens as 5-segment JWE. Tests use a sentinel
  # string and stub Security.decrypt_jwe / Security.validate_jws to return the
  # claims hash — we test the client's orchestration here, not crypto.
  let(:id_token) { "header.key.iv.ciphertext.tag" }

  let(:person_data) do
    {
      "uinfin" => { "value" => "S1234567A" },
      "name" => { "value" => "John Doe" },
      "sex" => { "code" => "M" }
    }
  end

  before do
    allow(StandardSingpass::Myinfo::Security).to receive(:build_client_assertion).and_return("mock-client-assertion")
    allow(StandardSingpass::Myinfo::Security).to receive(:build_dpop_proof).and_return("mock-dpop-proof")
  end

  describe "#push_authorization_request" do
    let(:par_url) { config[:par_url] }

    before do
      stub_request(:post, par_url)
        .to_return(status: 201, body: { request_uri: "urn:ietf:params:oauth:request_uri:abc123", expires_in: 60 }.to_json,
                   headers: { "Content-Type" => "application/json" })
    end

    it "returns request_uri and expires_in from PAR response" do
      result = client.push_authorization_request(
        code_challenge: "test-challenge", state: "test-state", nonce: "test-nonce", dpop_key_pair:
      )
      expect(result[:request_uri]).to eq("urn:ietf:params:oauth:request_uri:abc123")
      expect(result[:expires_in]).to eq(60)
    end

    it "sends required form parameters to the PAR endpoint" do
      client.push_authorization_request(
        code_challenge: "test-challenge", state: "test-state", nonce: "test-nonce", dpop_key_pair:
      )

      expect(WebMock).to have_requested(:post, par_url).with { |req|
        body = URI.decode_www_form(req.body).to_h
        body["response_type"] == "code" &&
          body["client_id"] == "test-client-id" &&
          body["redirect_uri"] == "https://app.test/callback" &&
          body["code_challenge"] == "test-challenge" &&
          body["code_challenge_method"] == "S256" &&
          body["state"] == "test-state" &&
          body["nonce"] == "test-nonce" &&
          body["client_assertion_type"] == StandardSingpass::Myinfo::Client::CLIENT_ASSERTION_TYPE &&
          body["client_assertion"] == "mock-client-assertion"
      }
    end

    it "sends a DPoP proof header to the PAR endpoint" do
      client.push_authorization_request(
        code_challenge: "test-challenge", state: "test-state", nonce: "test-nonce", dpop_key_pair:
      )

      expect(StandardSingpass::Myinfo::Security).to have_received(:build_dpop_proof).with(
        http_method: "POST",
        url: par_url,
        key_pair: dpop_key_pair
      )
    end

    it "builds client assertion with issuer as audience" do
      client.push_authorization_request(
        code_challenge: "test-challenge", state: "test-state", nonce: "test-nonce", dpop_key_pair:
      )

      expect(StandardSingpass::Myinfo::Security).to have_received(:build_client_assertion).with(
        client_id: "test-client-id",
        audience: config[:issuer],
        signing_key: "test-signing-key",
        signing_kid: "test-signing-kid"
      )
    end

    context "minimum acr enforcement (minimum_acr)" do
      before do
        allow(ENV).to receive(:[]).and_call_original
      end

      it "omits acr_values from the PAR request body when env var is unset" do
        allow(StandardSingpass::Myinfo.configuration).to receive(:minimum_acr).and_return(nil)

        client.push_authorization_request(
          code_challenge: "c", state: "s", nonce: "n", dpop_key_pair:
        )

        expect(WebMock).to have_requested(:post, par_url).with { |req|
          body = URI.decode_www_form(req.body).to_h
          !body.key?("acr_values")
        }
      end

      it "omits acr_values from the PAR request body when env var is blank" do
        allow(StandardSingpass::Myinfo.configuration).to receive(:minimum_acr).and_return("")

        client.push_authorization_request(
          code_challenge: "c", state: "s", nonce: "n", dpop_key_pair:
        )

        expect(WebMock).to have_requested(:post, par_url).with { |req|
          body = URI.decode_www_form(req.body).to_h
          !body.key?("acr_values")
        }
      end

      it "sends acr_values in the PAR request body when env var is set" do
        allow(StandardSingpass::Myinfo.configuration).to receive(:minimum_acr).and_return("urn:singpass:authentication:loa:2")

        client.push_authorization_request(
          code_challenge: "c", state: "s", nonce: "n", dpop_key_pair:
        )

        expect(WebMock).to have_requested(:post, par_url).with { |req|
          body = URI.decode_www_form(req.body).to_h
          body["acr_values"] == "urn:singpass:authentication:loa:2"
        }
      end
    end

    context "when the PAR endpoint returns an error" do
      it "raises PARError on 401" do
        stub_request(:post, par_url).to_return(status: 401, body: '{"error":"invalid_client"}')

        expect {
          client.push_authorization_request(
            code_challenge: "c", state: "s", nonce: "n", dpop_key_pair:
          )
        }.to raise_error(StandardSingpass::Myinfo::PARError, /rejected/)
      end

      it "raises PARError on 400" do
        stub_request(:post, par_url).to_return(status: 400, body: '{"error":"invalid_request"}')

        expect {
          client.push_authorization_request(
            code_challenge: "c", state: "s", nonce: "n", dpop_key_pair:
          )
        }.to raise_error(StandardSingpass::Myinfo::PARError, /PAR failed/)
      end

      it "raises RateLimitError on 429" do
        stub_request(:post, par_url).to_return(status: 429, body: "rate limited")

        expect {
          client.push_authorization_request(
            code_challenge: "c", state: "s", nonce: "n", dpop_key_pair:
          )
        }.to raise_error(StandardSingpass::Myinfo::RateLimitError)
      end

      it "raises PARError on network failure" do
        stub_request(:post, par_url).to_timeout

        expect {
          client.push_authorization_request(
            code_challenge: "c", state: "s", nonce: "n", dpop_key_pair:
          )
        }.to raise_error(StandardSingpass::Myinfo::PARError, /unreachable/)
      end

      it "raises PARError when response is missing request_uri" do
        stub_request(:post, par_url)
          .to_return(status: 201, body: { expires_in: 60 }.to_json)

        expect {
          client.push_authorization_request(
            code_challenge: "c", state: "s", nonce: "n", dpop_key_pair:
          )
        }.to raise_error(StandardSingpass::Myinfo::PARError, /missing required fields/)
      end

      it "raises PARError when response body is not valid JSON" do
        stub_request(:post, par_url)
          .to_return(status: 201, body: "not-json")

        expect {
          client.push_authorization_request(
            code_challenge: "c", state: "s", nonce: "n", dpop_key_pair:
          )
        }.to raise_error(StandardSingpass::Myinfo::PARError, /Invalid PAR response format/)
      end
    end
  end

  describe "#build_authorize_redirect" do
    it "builds a URL with only client_id and request_uri" do
      url = client.build_authorize_redirect(request_uri: "urn:ietf:params:oauth:request_uri:abc123")

      expect(url).to start_with("https://stg-id.singpass.gov.sg/fapi/auth?")
      expect(url).to include("client_id=test-client-id")
      expect(url).to include("request_uri=#{CGI.escape('urn:ietf:params:oauth:request_uri:abc123')}")
    end

    it "does not include any other OAuth params" do
      url = client.build_authorize_redirect(request_uri: "urn:ietf:params:oauth:request_uri:abc123")

      expect(url).not_to include("response_type")
      expect(url).not_to include("scope")
      expect(url).not_to include("code_challenge")
      expect(url).not_to include("redirect_uri")
    end
  end

  describe "#get_person_data" do
    let(:decrypted_id_token_jws) { "id-token-jws" }

    before do
      stub_request(:post, token_url)
        .to_return(status: 200, body: { access_token:, id_token: }.to_json,
                   headers: { "Content-Type" => "application/json" })

      stub_request(:get, userinfo_url)
        .to_return(status: 200, body: "encrypted-userinfo-jwe")

      # decrypt_jwe is called twice per flow: once for the id_token JWE,
      # once for the userinfo JWE.
      allow(StandardSingpass::Myinfo::Security).to receive(:decrypt_jwe) do |jwe, **_kwargs|
        jwe == id_token ? decrypted_id_token_jws : "userinfo-jws"
      end

      allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
        case jws
        when decrypted_id_token_jws then id_token_claims
        when "userinfo-jws" then person_data
        end
      end
    end

    it "returns the decrypted and validated person data" do
      result = client.get_person_data(auth_code: "auth-code", code_verifier: "verifier", dpop_key_pair:)
      expect(result[:person_data]).to eq(person_data)
    end

    context "id_token acr claim" do
      it "returns the acr value when present" do
        allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
          if jws == decrypted_id_token_jws
            id_token_claims.merge("acr" => "https://www.singpass.gov.sg/2fa/strong")
          else
            person_data
          end
        end

        result = client.get_person_data(auth_code: "auth-code", code_verifier: "verifier", dpop_key_pair:)
        expect(result[:id_token_acr]).to eq("https://www.singpass.gov.sg/2fa/strong")
      end

      it "returns nil when acr is absent (claim is optional per OIDC core)" do
        result = client.get_person_data(auth_code: "auth-code", code_verifier: "verifier", dpop_key_pair:)
        expect(result[:id_token_acr]).to be_nil
      end
    end

    it "uses the provided DPoP key pair for both token and userinfo requests" do
      client.get_person_data(auth_code: "auth-code", code_verifier: "verifier", dpop_key_pair:)

      expect(StandardSingpass::Myinfo::Security).to have_received(:build_dpop_proof).with(
        hash_including(key_pair: dpop_key_pair)
      ).twice
    end

    it "sends a DPoP proof with the userinfo URL as htu (RFC 9449 §4.2)" do
      client.get_person_data(auth_code: "auth-code", code_verifier: "verifier", dpop_key_pair:)

      expect(StandardSingpass::Myinfo::Security).to have_received(:build_dpop_proof).with(
        http_method: "GET",
        url: userinfo_url,
        key_pair: dpop_key_pair,
        access_token:
      )
    end

    it "builds client assertion with code for token exchange" do
      client.get_person_data(auth_code: "auth-code-123", code_verifier: "verifier", dpop_key_pair:)

      expect(StandardSingpass::Myinfo::Security).to have_received(:build_client_assertion).with(
        client_id: "test-client-id",
        audience: config[:issuer],
        signing_key: "test-signing-key",
        signing_kid: "test-signing-kid",
        code: "auth-code-123"
      )
    end

    it "sends required form parameters in the token exchange" do
      client.get_person_data(auth_code: "auth-code-123", code_verifier: "verifier-123", dpop_key_pair:)

      expect(WebMock).to have_requested(:post, token_url).with { |req|
        body = URI.decode_www_form(req.body).to_h
        body["grant_type"] == "authorization_code" &&
          body["code"] == "auth-code-123" &&
          body["code_verifier"] == "verifier-123" &&
          body["client_id"] == "test-client-id" &&
          body["client_assertion_type"] == StandardSingpass::Myinfo::Client::CLIENT_ASSERTION_TYPE &&
          body["client_assertion"] == "mock-client-assertion"
      }
    end

    it "sends DPoP authorization header for the userinfo request" do
      client.get_person_data(auth_code: "auth-code", code_verifier: "verifier", dpop_key_pair:)

      expect(WebMock).to have_requested(:get, userinfo_url)
        .with(headers: { "Authorization" => "DPoP #{access_token}" })
    end

    it "decrypts the userinfo JWE and validates the JWS" do
      client.get_person_data(auth_code: "auth-code", code_verifier: "verifier", dpop_key_pair:)

      expect(StandardSingpass::Myinfo::Security).to have_received(:decrypt_jwe)
        .with("encrypted-userinfo-jwe", private_keys: [{ kid: "test-enc-kid", key: "test-encryption-key" }])
      expect(StandardSingpass::Myinfo::Security).to have_received(:validate_jws)
        .with("userinfo-jws", jwks_url: config[:userinfo_jwks_url])
    end

    it "decrypts the id_token JWE and validates the JWS" do
      client.get_person_data(auth_code: "auth-code", code_verifier: "verifier", dpop_key_pair:)

      expect(StandardSingpass::Myinfo::Security).to have_received(:decrypt_jwe)
        .with(id_token, private_keys: [{ kid: "test-enc-kid", key: "test-encryption-key" }])
      expect(StandardSingpass::Myinfo::Security).to have_received(:validate_jws)
        .with(decrypted_id_token_jws, jwks_url: config[:jwks_url])
    end

    context "when the token endpoint returns an error" do
      it "raises AuthenticationError on 401" do
        stub_request(:post, token_url).to_return(status: 401, body: "unauthorized")

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /rejected/)
      end

      it "raises ApiError on 500" do
        stub_request(:post, token_url).to_return(status: 500, body: "server error")

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::ApiError, /Token exchange failed/)
      end

      it "raises RateLimitError on 429" do
        stub_request(:post, token_url).to_return(status: 429, body: "rate limited")

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::RateLimitError)
      end

      it "raises ApiError on network failure" do
        stub_request(:post, token_url).to_timeout

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::ApiError, /unreachable/)
      end

      it "does not include PII (NRIC, etc.) in error messages even when Singpass returns it in the body" do
        stub_request(:post, token_url)
          .to_return(status: 401, body: '{"error":"invalid_grant","nric":"S1234567A","email":"x@y.z"}')

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::AuthenticationError) { |e|
          expect(e.message).not_to include("S1234567A")
          expect(e.message).not_to include("x@y.z")
          expect(e.message).not_to include("nric")
          expect(e.message).to include("invalid_grant")
        }
      end
    end

    # A transient 502 (`upstream_dependency_error`) is Singpass's signal that a
    # Myinfo upstream agency is unavailable. Retrying the userinfo GET is safe —
    # it is idempotent against an access token we already hold — and it spares
    # the user a full Singpass re-login, since the authorization code is already
    # spent by the time we get here.
    context "when the userinfo endpoint returns a transient upstream error" do
      # Keep the suite fast: assert the backoff is asked for, don't actually wait.
      before { allow(client).to receive(:sleep) }

      it "retries and succeeds when a 502 is followed by a 200" do
        stub_request(:get, userinfo_url)
          .to_return(status: 502, body: '{"error":"upstream_dependency_error"}')
          .then.to_return(status: 200, body: "encrypted-userinfo-jwe")

        result = client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)

        expect(result[:person_data]).to eq(person_data)
        expect(WebMock).to have_requested(:get, userinfo_url).twice
      end

      it "gives up after the attempt cap and surfaces the last status" do
        stub_request(:get, userinfo_url)
          .to_return(status: 502, body: '{"error":"upstream_dependency_error"}')

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::ApiError) { |e|
          expect(e.status).to eq(502)
        }

        expect(WebMock).to have_requested(:get, userinfo_url)
          .times(described_class::USERINFO_MAX_ATTEMPTS)
      end

      it "backs off between attempts rather than hammering the upstream" do
        stub_request(:get, userinfo_url).to_return(status: 503, body: "unavailable")

        expect(client).to receive(:sleep).with(a_value > 0)
          .exactly(described_class::USERINFO_MAX_ATTEMPTS - 1).times

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::ApiError)
      end

      # RFC 9449 proofs carry a one-shot jti; replaying the first attempt's
      # header would be rejected. The suite stubs build_dpop_proof to a constant,
      # so the observable invariant is that a proof is *built* per attempt.
      it "rebuilds the DPoP proof on each attempt (a replayed jti is rejected)" do
        stub_request(:get, userinfo_url)
          .to_return(status: 502, body: "bad gateway")
          .then.to_return(status: 200, body: "encrypted-userinfo-jwe")

        client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)

        expect(StandardSingpass::Myinfo::Security).to have_received(:build_dpop_proof).with(
          http_method: "GET",
          url: userinfo_url,
          key_pair: dpop_key_pair,
          access_token: anything
        ).twice
      end

      it "does not retry a 4xx — that is our bug, not their outage" do
        stub_request(:get, userinfo_url).to_return(status: 400, body: "bad request")

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::ApiError)

        expect(WebMock).to have_requested(:get, userinfo_url).once
      end

      it "does not retry a timeout — the request budget is already spent" do
        stub_request(:get, userinfo_url).to_timeout

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::ApiError, /unreachable/)

        expect(WebMock).to have_requested(:get, userinfo_url).once
      end

      it "never retries the token exchange — the auth code is single-use" do
        stub_request(:post, token_url)
          .to_return(status: 502, body: "bad gateway")

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::ApiError)

        expect(WebMock).to have_requested(:post, token_url).once
      end
    end

    context "when the userinfo endpoint returns an error" do
      it "raises AuthenticationError on 403" do
        stub_request(:get, userinfo_url).to_return(status: 403, body: "forbidden")

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /forbidden/)
      end

      it "raises ApiError on 500" do
        stub_request(:get, userinfo_url).to_return(status: 500, body: "server error")

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::ApiError, /Person data fetch failed/)
      end

      it "exposes the HTTP status on ApiError so hosts don't parse the message" do
        stub_request(:get, userinfo_url).to_return(status: 500, body: "server error")

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::ApiError) { |e|
          expect(e.status).to eq(500)
        }
      end

      it "surfaces FAPI error/error_description so Singpass's reason is grep-able" do
        body = '{"error":"invalid_dpop_proof","error_description":"htu mismatch","trace_id":"1-abc"}'
        stub_request(:get, userinfo_url).to_return(status: 400, body:)

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::ApiError) { |e|
          expect(e.message).to include("invalid_dpop_proof")
          expect(e.message).to include("htu mismatch")
          expect(e.message).to include("1-abc")
        }
      end

      it "raises RateLimitError on 429" do
        stub_request(:get, userinfo_url).to_return(status: 429, body: "rate limited")

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::RateLimitError)
      end

      it "raises ApiError on network failure" do
        stub_request(:get, userinfo_url).to_timeout

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::ApiError, /unreachable/)
      end

      it "raises DecryptionError when JWE decryption fails on userinfo" do
        stub_request(:get, userinfo_url).to_return(status: 200, body: "bad-jwe")
        allow(StandardSingpass::Myinfo::Security).to receive(:decrypt_jwe) do |jwe, **_kwargs|
          jwe == id_token ? decrypted_id_token_jws : raise(StandardSingpass::Myinfo::Security::DecryptionError, "Decryption failed")
        end

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::DecryptionError)
      end

      it "raises SignatureError when userinfo JWS validation fails" do
        allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
          if jws == decrypted_id_token_jws
            id_token_claims
          else
            raise StandardSingpass::Myinfo::Security::ValidationError, "Signature invalid"
          end
        end

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::SignatureError)
      end

      it "does not include PII in error messages" do
        stub_request(:get, userinfo_url).to_return(status: 500, body: '{"nric":"S1234567A"}')

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::ApiError) { |e|
          expect(e.message).not_to include("S1234567A")
        }
      end
    end

    context "ID token validation" do
      it "raises AuthenticationError when id_token is not a 5-segment JWE" do
        stub_request(:post, token_url)
          .to_return(status: 200, body: { access_token:, id_token: "header.payload.sig" }.to_json,
                     headers: { "Content-Type" => "application/json" })

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /must be a 5-segment JWE/)
      end

      it "raises AuthenticationError when JWE decryption fails on id_token" do
        allow(StandardSingpass::Myinfo::Security).to receive(:decrypt_jwe) do |jwe, **_kwargs|
          raise StandardSingpass::Myinfo::Security::DecryptionError, "bad key" if jwe == id_token
          "userinfo-jws"
        end

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /ID token decryption failed/)
      end

      it "raises AuthenticationError when JWS signature verification fails on id_token" do
        allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
          if jws == decrypted_id_token_jws
            raise StandardSingpass::Myinfo::Security::ValidationError, "bad sig"
          else
            person_data
          end
        end

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /ID token signature verification failed/)
      end

      context "when sub claim is missing" do
        before do
          allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
            jws == decrypted_id_token_jws ? id_token_claims.except("sub") : person_data
          end
        end

        it "raises AuthenticationError" do
          expect {
            client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
          }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /sub claim is missing/)
        end
      end

      context "acr (assurance level) validation" do
        before do
          allow(ENV).to receive(:[]).and_call_original
        end

        def stub_id_token_acr(value)
          payload = value.equal?(:missing) ? id_token_claims : id_token_claims.merge("acr" => value)
          allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
            jws == decrypted_id_token_jws ? payload : person_data
          end
        end

        context "when minimum_acr is unset" do
          before { allow(StandardSingpass::Myinfo.configuration).to receive(:minimum_acr).and_return(nil) }

          it "passes when payload has a valid acr" do
            stub_id_token_acr("urn:singpass:authentication:loa:2")

            result = client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
            expect(result[:person_data]).to eq(person_data)
          end

          it "passes when payload has no acr claim" do
            stub_id_token_acr(:missing)

            result = client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
            expect(result[:person_data]).to eq(person_data)
          end
        end

        context "when minimum_acr is blank" do
          before { allow(StandardSingpass::Myinfo.configuration).to receive(:minimum_acr).and_return("") }

          it "passes regardless of payload acr" do
            stub_id_token_acr(:missing)

            result = client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
            expect(result[:person_data]).to eq(person_data)
          end
        end

        context "when minimum_acr is set to an unparseable value" do
          before { allow(StandardSingpass::Myinfo.configuration).to receive(:minimum_acr).and_return("not-a-valid-urn") }

          it "raises a configuration error distinct from the assurance-level failure" do
            # The payload acr value is irrelevant — the config error fires
            # before we look at it.
            stub_id_token_acr("urn:singpass:authentication:loa:2")

            expect {
              client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
            }.to raise_error(StandardSingpass::Myinfo::ConfigurationError, /minimum_acr.*not a recognised Singpass LOA URN/)
          end
        end

        context "when minimum_acr=urn:singpass:authentication:loa:2" do
          before { allow(StandardSingpass::Myinfo.configuration).to receive(:minimum_acr).and_return("urn:singpass:authentication:loa:2") }

          it "passes when acr exactly matches the floor" do
            stub_id_token_acr("urn:singpass:authentication:loa:2")

            result = client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
            expect(result[:person_data]).to eq(person_data)
          end

          it "passes when acr is above the floor" do
            stub_id_token_acr("urn:singpass:authentication:loa:3")

            result = client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
            expect(result[:person_data]).to eq(person_data)
          end

          it "raises AuthenticationError when acr is below the floor" do
            stub_id_token_acr("urn:singpass:authentication:loa:1")

            expect {
              client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
            }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /is below required minimum/)
          end

          it "raises AuthenticationError when acr is missing" do
            stub_id_token_acr(:missing)

            expect {
              client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
            }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /is below required minimum/)
          end

          it "raises AuthenticationError when acr is unparseable" do
            stub_id_token_acr("garbage")

            expect {
              client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
            }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /is below required minimum/)
          end
        end

        context "when minimum_acr=urn:singpass:authentication:loa:3" do
          before { allow(StandardSingpass::Myinfo.configuration).to receive(:minimum_acr).and_return("urn:singpass:authentication:loa:3") }

          it "raises AuthenticationError when acr is loa:2 (below loa:3)" do
            stub_id_token_acr("urn:singpass:authentication:loa:2")

            expect {
              client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
            }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /is below required minimum/)
          end
        end
      end

      context "when iss claim is missing" do
        before do
          allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
            jws == decrypted_id_token_jws ? id_token_claims.except("iss") : person_data
          end
        end

        it "raises AuthenticationError" do
          expect {
            client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
          }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /iss claim is missing/)
        end
      end

      context "when iss claim does not match" do
        before do
          allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
            jws == decrypted_id_token_jws ? id_token_claims.merge("iss" => "https://evil.example.com") : person_data
          end
        end

        it "raises AuthenticationError" do
          expect {
            client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
          }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /issuer does not match/)
        end
      end

      context "when aud claim is missing" do
        before do
          allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
            jws == decrypted_id_token_jws ? id_token_claims.except("aud") : person_data
          end
        end

        it "raises AuthenticationError" do
          expect {
            client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
          }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /aud claim is missing/)
        end
      end

      context "when aud claim does not match client_id" do
        before do
          allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
            jws == decrypted_id_token_jws ? id_token_claims.merge("aud" => "wrong-client-id") : person_data
          end
        end

        it "raises AuthenticationError" do
          expect {
            client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
          }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /audience does not match/)
        end
      end

      context "when aud claim is an array containing client_id" do
        before do
          allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
            jws == decrypted_id_token_jws ? id_token_claims.merge("aud" => ["test-client-id"]) : person_data
          end
        end

        it "accepts the array aud per OIDC spec" do
          result = client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
          expect(result[:person_data]).to eq(person_data)
        end
      end

      context "when exp claim is missing" do
        before do
          allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
            jws == decrypted_id_token_jws ? id_token_claims.except("exp") : person_data
          end
        end

        it "raises AuthenticationError" do
          expect {
            client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
          }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /exp claim is missing/)
        end
      end

      context "when ID token has expired" do
        before do
          allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
            jws == decrypted_id_token_jws ? id_token_claims.merge("exp" => Time.now.to_i - 60) : person_data
          end
        end

        it "raises AuthenticationError" do
          expect {
            client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
          }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /ID token has expired/)
        end
      end

      context "when ID token exp is within clock skew leeway" do
        before do
          allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
            jws == decrypted_id_token_jws ? id_token_claims.merge("exp" => Time.now.to_i - 15) : person_data
          end
        end

        it "accepts ID token within clock skew leeway" do
          result = client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
          expect(result[:person_data]).to eq(person_data)
        end
      end

      context "iat (issued-at) validation" do
        context "when iat is too old" do
          before do
            allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
              jws == decrypted_id_token_jws ? id_token_claims.merge("iat" => Time.now.to_i - 600) : person_data
            end
          end

          it "raises AuthenticationError" do
            expect {
              client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
            }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /iat is too old/)
          end
        end

        context "when iat is within window" do
          before do
            allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
              jws == decrypted_id_token_jws ? id_token_claims.merge("iat" => Time.now.to_i - 120) : person_data
            end
          end

          it "accepts the token" do
            result = client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
            expect(result[:person_data]).to eq(person_data)
          end
        end

        context "when iat is missing" do
          before do
            allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
              jws == decrypted_id_token_jws ? id_token_claims.except("iat") : person_data
            end
          end

          it "raises AuthenticationError" do
            expect {
              client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
            }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /iat claim is missing/)
          end
        end

        context "when iat is in the future" do
          before do
            allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
              jws == decrypted_id_token_jws ? id_token_claims.merge("iat" => Time.now.to_i + 120) : person_data
            end
          end

          it "raises AuthenticationError" do
            expect {
              client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
            }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /iat is in the future/)
          end
        end
      end

      context "when ID token is missing from response" do
        before do
          stub_request(:post, token_url)
            .to_return(status: 200, body: { access_token: }.to_json,
                       headers: { "Content-Type" => "application/json" })
        end

        it "raises AuthenticationError" do
          expect {
            client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
          }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /ID token missing/)
        end
      end
    end

    context "when nonce is provided" do
      it "succeeds when nonce matches the ID token claim" do
        result = client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:, nonce:)
        expect(result[:person_data]).to eq(person_data)
      end

      it "raises AuthenticationError when nonce does not match" do
        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:, nonce: "wrong-nonce")
        }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /nonce/)
      end

      it "raises AuthenticationError when ID token has no nonce claim" do
        allow(StandardSingpass::Myinfo::Security).to receive(:validate_jws) do |jws, **_kwargs|
          jws == decrypted_id_token_jws ? id_token_claims.except("nonce") : person_data
        end

        expect {
          client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:, nonce:)
        }.to raise_error(StandardSingpass::Myinfo::AuthenticationError, /nonce claim is missing/)
      end
    end

    context "when nonce is not provided" do
      it "skips nonce validation" do
        result = client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:)
        expect(result[:person_data]).to eq(person_data)
      end

      it "skips nonce validation for empty string nonce" do
        result = client.get_person_data(auth_code: "code", code_verifier: "verifier", dpop_key_pair:, nonce: "")
        expect(result[:person_data]).to eq(person_data)
      end
    end
  end

  describe "config validation" do
    it "raises ArgumentError when required config is missing" do
      expect {
        described_class.new(config.except(:client_id))
      }.to raise_error(ArgumentError, /client_id/)
    end

    it "raises ArgumentError when required config is blank" do
      expect {
        described_class.new(config.merge(signing_key: ""))
      }.to raise_error(ArgumentError, /signing_key/)
    end

    it "accepts empty encryption_keys" do
      expect {
        described_class.new(config.merge(encryption_keys: []))
      }.not_to raise_error
    end

    it "raises ArgumentError when issuer is missing" do
      allow(StandardSingpass::Myinfo.configuration).to receive(:issuer).and_return(nil)
      expect {
        described_class.new(config.except(:issuer))
      }.to raise_error(ArgumentError, /issuer/)
    end

    it "raises ArgumentError when userinfo_url is missing" do
      allow(StandardSingpass::Myinfo.configuration).to receive(:userinfo_url).and_return(nil)
      expect {
        described_class.new(config.except(:userinfo_url))
      }.to raise_error(ArgumentError, /userinfo_url/)
    end

    it "raises ArgumentError when userinfo_jwks_url is missing" do
      allow(StandardSingpass::Myinfo.configuration).to receive(:userinfo_jwks_url).and_return(nil)
      expect {
        described_class.new(config.except(:userinfo_jwks_url))
      }.to raise_error(ArgumentError, /userinfo_jwks_url/)
    end
  end
end
