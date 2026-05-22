require "rails_helper"

RSpec.describe StandardSingpass::Myinfo::JwksGenerator do
  describe ".generate" do
    subject(:jwks) { described_class.generate(sig_kid: "test-sig", enc_kid: "test-enc") }

    it "produces exactly two keys" do
      expect(jwks[:keys].size).to eq(2)
    end

    it "produces a private signing key with ES256 / EC P-256" do
      sig = jwks[:keys].find { |k| k[:use] == "sig" }
      expect(sig).to include(kid: "test-sig", use: "sig", alg: "ES256", kty: "EC", crv: "P-256")
      expect(sig[:d]).to be_present
    end

    it "produces a private encryption key with ECDH-ES+A256KW / EC P-256" do
      enc = jwks[:keys].find { |k| k[:use] == "enc" }
      expect(enc).to include(kid: "test-enc", use: "enc", alg: "ECDH-ES+A256KW", kty: "EC", crv: "P-256")
      expect(enc[:d]).to be_present
    end

    it "self-validates the output (defensive — would fail loudly if a future bug emitted public-only)" do
      expect(described_class.validate(jwks)).to be_empty
    end

    it "produces distinct keys per invocation" do
      one = described_class.generate(sig_kid: "a", enc_kid: "b")
      two = described_class.generate(sig_kid: "a", enc_kid: "b")
      sig_one = one[:keys].find { |k| k[:use] == "sig" }[:d]
      sig_two = two[:keys].find { |k| k[:use] == "sig" }[:d]
      expect(sig_one).not_to eq(sig_two)
    end
  end

  describe ".validate" do
    let(:valid_jwks) { described_class.generate(sig_kid: "s", enc_kid: "e") }

    it "passes a freshly generated JWKS" do
      expect(described_class.validate(valid_jwks)).to be_empty
    end

    it "passes a JWKS round-tripped through JSON (string keys)" do
      round_tripped = JSON.parse(JSON.generate(valid_jwks))
      expect(described_class.validate(round_tripped)).to be_empty
    end

    it "rejects a public-only signing key" do
      valid_jwks[:keys].find { |k| k[:use] == "sig" }.delete(:d)
      issues = described_class.validate(valid_jwks)
      expect(issues).to include(a_string_matching(/kid="s".*public-only/))
    end

    it "rejects a public-only encryption key" do
      valid_jwks[:keys].find { |k| k[:use] == "enc" }.delete(:d)
      issues = described_class.validate(valid_jwks)
      expect(issues).to include(a_string_matching(/kid="e".*public-only/))
    end

    it "rejects when no signing key is present" do
      valid_jwks[:keys].reject! { |k| k[:use] == "sig" }
      issues = described_class.validate(valid_jwks)
      expect(issues).to include(a_string_matching(/expected exactly one sig key.*got 0/))
    end

    it "rejects when more than one signing key is present" do
      sig = valid_jwks[:keys].find { |k| k[:use] == "sig" }
      valid_jwks[:keys] << sig.merge(kid: "s2")
      issues = described_class.validate(valid_jwks)
      expect(issues).to include(a_string_matching(/expected exactly one sig key.*got 2/))
    end

    it "rejects duplicate kid values across keys (RFC 7517 §4.5)" do
      # Operator copy/paste mistake — same kid on both sig and enc.
      valid_jwks[:keys].each { |k| k[:kid] = "dup" }
      issues = described_class.validate(valid_jwks)
      expect(issues).to include(a_string_matching(/duplicate kid "dup" appears 2 times/))
    end

    it "rejects when no encryption key is present" do
      valid_jwks[:keys].reject! { |k| k[:use] == "enc" }
      issues = described_class.validate(valid_jwks)
      expect(issues).to include(a_string_matching(/expected at least one enc key.*got 0/))
    end

    it "rejects wrong sig alg" do
      valid_jwks[:keys].find { |k| k[:use] == "sig" }[:alg] = "RS256"
      issues = described_class.validate(valid_jwks)
      expect(issues).to include(a_string_matching(/expected "ES256"/))
    end

    it "rejects wrong enc alg" do
      valid_jwks[:keys].find { |k| k[:use] == "enc" }[:alg] = "RSA-OAEP"
      issues = described_class.validate(valid_jwks)
      expect(issues).to include(a_string_matching(/expected "ECDH-ES\+A256KW"/))
    end

    it "rejects non-EC kty" do
      valid_jwks[:keys].first[:kty] = "RSA"
      issues = described_class.validate(valid_jwks)
      expect(issues).to include(a_string_matching(/kty="RSA" expected "EC"/))
    end

    it "rejects non-P-256 curve (FAPI 2.0 requires EC P-256)" do
      valid_jwks[:keys].first[:crv] = "P-384"
      issues = described_class.validate(valid_jwks)
      expect(issues).to include(a_string_matching(/crv="P-384" expected "P-256"/))
    end

    it "rejects unknown 'use' value" do
      valid_jwks[:keys].first[:use] = "deriveKey"
      issues = described_class.validate(valid_jwks)
      expect(issues).to include(a_string_matching(/use="deriveKey" expected "sig" or "enc"/))
    end

    it "rejects a non-hash root" do
      expect(described_class.validate("not a hash")).to include(a_string_matching(/root is not a JSON object/))
    end

    it "rejects when 'keys' is missing" do
      expect(described_class.validate({})).to include("missing 'keys' array")
    end

    it "rejects when 'keys' is not an array" do
      expect(described_class.validate({ "keys" => "oops" })).to include("missing 'keys' array")
    end

    it "rejects non-hash entries inside 'keys'" do
      issues = described_class.validate({ keys: [ "not-a-hash" ] })
      expect(issues).to include(a_string_matching(/keys\[0\] is not an object/))
    end
  end
end
