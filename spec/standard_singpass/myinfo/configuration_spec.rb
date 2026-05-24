require "rails_helper"

# Exercises the global configure / public_jwks paths and the private-JWKS
# parser. The full_flow_spec sidesteps these by passing keys directly into
# Client.new(config); these specs cover the production path where the host
# wires env vars into Myinfo.configure { |c| c.private_jwks_json = ... }.
RSpec.describe StandardSingpass::Myinfo::Configuration do
  let(:signing_key)    { OpenSSL::PKey::EC.generate("prime256v1") }
  let(:encryption_key) { OpenSSL::PKey::EC.generate("prime256v1") }

  let(:private_jwks) do
    sig_jwk = JWT::JWK.new(signing_key, kid: "sig-1").export(include_private: true)
    enc_jwk = JWT::JWK.new(encryption_key, kid: "enc-1").export(include_private: true)
    sig_jwk[:use] = "sig"; sig_jwk[:alg] = "ES256"
    enc_jwk[:use] = "enc"; enc_jwk[:alg] = "ECDH-ES+A256KW"
    { keys: [sig_jwk, enc_jwk] }.to_json
  end

  after { StandardSingpass::Myinfo.reset_configuration! }

  describe "endpoint selection" do
    it "uses staging endpoints by default" do
      c = described_class.new
      expect(c.environment).to eq(:staging)
      expect(c.issuer).to include("stg-id.singpass.gov.sg")
    end

    it "switches to production endpoints when environment is set to :production" do
      c = described_class.new
      c.environment = :production
      expect(c.issuer).to eq("https://id.singpass.gov.sg/fapi")
      expect(c.par_url).to eq("https://id.singpass.gov.sg/fapi/par")
    end

    it "falls back to staging for unknown environments" do
      c = described_class.new
      c.environment = :preview
      expect(c.issuer).to include("stg-id.singpass.gov.sg")
    end
  end

  describe "#private_jwks_json=" do
    it "populates signing_key, signing_kid, and encryption_keys from a valid JWKS" do
      c = described_class.new
      c.private_jwks_json = private_jwks

      expect(c.signing_kid).to eq("sig-1")
      expect(c.signing_key).to include("BEGIN")
      expect(c.encryption_keys).to contain_exactly(hash_including(kid: "enc-1"))
    end

    it "no-ops on blank input in test env" do
      c = described_class.new
      c.private_jwks_json = nil
      expect(c.signing_key).to be_nil
      expect(c.encryption_keys).to eq([])
    end

    it "reports malformed JSON via Rails.error.report and keeps encryption_keys empty" do
      allow(Rails.error).to receive(:report)
      allow(Rails.logger).to receive(:error)

      c = described_class.new
      c.mock_mode = true   # silence the operator-facing warning
      c.private_jwks_json = "not-json"

      expect(c.encryption_keys).to eq([])
      expect(Rails.error).to have_received(:report).with(
        instance_of(JSON::ParserError), hash_including(handled: true)
      )
    end

    it "rejects a public-only signing key (missing `d`) and logs the kid" do
      jwks = JSON.parse(private_jwks)
      jwks["keys"].find { |k| k["use"] == "sig" }.delete("d")
      allow(Rails.logger).to receive(:error)

      c = described_class.new
      c.private_jwks_json = jwks.to_json

      expect(c.signing_key).to be_nil
      expect(c.signing_kid).to be_nil
      expect(Rails.logger).to have_received(:error).with(/public-only/)
    end
  end

  describe "StandardSingpass::Myinfo.public_jwks" do
    it "derives the public JWKS from the configured private keys" do
      StandardSingpass::Myinfo.configure { |c| c.private_jwks_json = private_jwks }

      result = StandardSingpass::Myinfo.public_jwks
      kids = result[:keys].map { |k| k[:kid] }
      uses = result[:keys].map { |k| k[:use] }

      expect(kids).to contain_exactly("sig-1", "enc-1")
      expect(uses).to contain_exactly("sig", "enc")
      # `d` must not leak into the public document.
      expect(result[:keys].none? { |k| k.key?(:d) }).to be true
    end

    it "returns only the configured keys (no signing key → only encryption)" do
      StandardSingpass::Myinfo.configure do |c|
        jwks = JSON.parse(private_jwks)
        jwks["keys"].find { |k| k["use"] == "sig" }.delete("d")  # drop sig
        c.private_jwks_json = jwks.to_json
      end

      result = StandardSingpass::Myinfo.public_jwks
      expect(result[:keys].map { |k| k[:use] }).to eq(["enc"])
    end
  end
end
