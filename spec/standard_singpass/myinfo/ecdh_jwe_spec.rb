require "rails_helper"

RSpec.describe StandardSingpass::Myinfo::EcdhJwe do
  let(:ec_key) { OpenSSL::PKey::EC.generate("prime256v1") }
  let(:payload) { "Hello, ECDH-ES+A256KW!" }

  describe ".encrypt and .decrypt round-trip" do
    it "round-trips with ECDH-ES+A256KW / A256CBC-HS512" do
      jwe = described_class.encrypt(
        payload,
        public_key: ec_key,
        alg: "ECDH-ES+A256KW",
        enc: "A256CBC-HS512",
        kid: "key-1"
      )

      result = described_class.decrypt(jwe, private_key: ec_key)
      expect(result).to eq(payload)
    end

    it "round-trips with ECDH-ES+A256KW / A256GCM" do
      jwe = described_class.encrypt(
        payload,
        public_key: ec_key,
        alg: "ECDH-ES+A256KW",
        enc: "A256GCM",
        kid: "key-1"
      )

      result = described_class.decrypt(jwe, private_key: ec_key)
      expect(result).to eq(payload)
    end

    it "round-trips with ECDH-ES+A256KW / A128CBC-HS256" do
      jwe = described_class.encrypt(
        payload,
        public_key: ec_key,
        alg: "ECDH-ES+A256KW",
        enc: "A128CBC-HS256",
        kid: "key-1"
      )

      result = described_class.decrypt(jwe, private_key: ec_key)
      expect(result).to eq(payload)
    end

    it "round-trips with ECDH-ES+A256KW / A128GCM" do
      jwe = described_class.encrypt(
        payload,
        public_key: ec_key,
        alg: "ECDH-ES+A256KW",
        enc: "A128GCM",
        kid: "key-1"
      )

      result = described_class.decrypt(jwe, private_key: ec_key)
      expect(result).to eq(payload)
    end

    it "round-trips with ECDH-ES+A128KW / A256GCM" do
      jwe = described_class.encrypt(
        payload,
        public_key: ec_key,
        alg: "ECDH-ES+A128KW",
        enc: "A256GCM",
        kid: "key-1"
      )

      result = described_class.decrypt(jwe, private_key: ec_key)
      expect(result).to eq(payload)
    end

    it "round-trips with apu and apv" do
      apu = "sender-id"
      apv = "recipient-id"

      jwe = described_class.encrypt(
        payload,
        public_key: ec_key,
        alg: "ECDH-ES+A256KW",
        enc: "A256GCM",
        apu:,
        apv:
      )

      header = JSON.parse(Base64.urlsafe_decode64(jwe.split(".").first))
      expect(header["apu"]).to eq(Base64.urlsafe_encode64(apu, padding: false))
      expect(header["apv"]).to eq(Base64.urlsafe_encode64(apv, padding: false))

      result = described_class.decrypt(jwe, private_key: ec_key)
      expect(result).to eq(payload)
    end

    it "includes kid in the JWE header when provided" do
      jwe = described_class.encrypt(
        payload,
        public_key: ec_key,
        alg: "ECDH-ES+A256KW",
        enc: "A256GCM",
        kid: "my-key-id"
      )

      header = JSON.parse(Base64.urlsafe_decode64(jwe.split(".").first))
      expect(header["kid"]).to eq("my-key-id")
    end

    it "includes epk in the JWE header" do
      jwe = described_class.encrypt(
        payload,
        public_key: ec_key,
        alg: "ECDH-ES+A256KW",
        enc: "A256GCM"
      )

      header = JSON.parse(Base64.urlsafe_decode64(jwe.split(".").first))
      expect(header["epk"]).to include("kty" => "EC", "crv" => "P-256")
      expect(header["epk"]).to have_key("x")
      expect(header["epk"]).to have_key("y")
    end

    it "produces 5-segment compact serialization" do
      jwe = described_class.encrypt(
        payload,
        public_key: ec_key,
        alg: "ECDH-ES+A256KW",
        enc: "A256GCM"
      )

      expect(jwe.split(".").length).to eq(5)
    end
  end

  describe ".decrypt" do
    it "raises DecryptionFailed for invalid JWE format" do
      expect {
        described_class.decrypt("not.enough.segments", private_key: ec_key)
      }.to raise_error(described_class::DecryptionFailed, /Invalid JWE format/)
    end

    it "raises DecryptionFailed when decrypting with wrong key" do
      other_key = OpenSSL::PKey::EC.generate("prime256v1")
      jwe = described_class.encrypt(
        payload,
        public_key: ec_key,
        alg: "ECDH-ES+A256KW",
        enc: "A256CBC-HS512",
        kid: "key-1"
      )

      expect {
        described_class.decrypt(jwe, private_key: other_key)
      }.to raise_error(described_class::DecryptionFailed)
    end

    it "raises InvalidAlgorithm for unsupported algorithm" do
      header = Base64.urlsafe_encode64({ "alg" => "RSA-OAEP", "enc" => "A256GCM" }.to_json, padding: false)
      jwe = "#{header}.fake.fake.fake.fake"

      expect {
        described_class.decrypt(jwe, private_key: ec_key)
      }.to raise_error(described_class::InvalidAlgorithm, /Unsupported alg/)
    end

    it "raises DecryptionFailed when authentication tag is tampered (CBC)" do
      jwe = described_class.encrypt(
        payload,
        public_key: ec_key,
        alg: "ECDH-ES+A256KW",
        enc: "A256CBC-HS512",
        kid: "key-1"
      )

      parts = jwe.split(".")
      # Tamper with the auth tag
      parts[4] = Base64.urlsafe_encode64(SecureRandom.random_bytes(32), padding: false)
      tampered_jwe = parts.join(".")

      expect {
        described_class.decrypt(tampered_jwe, private_key: ec_key)
      }.to raise_error(described_class::DecryptionFailed)
    end

    it "raises DecryptionFailed when ciphertext is tampered (GCM)" do
      jwe = described_class.encrypt(
        payload,
        public_key: ec_key,
        alg: "ECDH-ES+A256KW",
        enc: "A256GCM",
        kid: "key-1"
      )

      parts = jwe.split(".")
      # Tamper with the ciphertext
      parts[3] = Base64.urlsafe_encode64("tampered_ciphertext", padding: false)
      tampered_jwe = parts.join(".")

      expect {
        described_class.decrypt(tampered_jwe, private_key: ec_key)
      }.to raise_error(described_class::DecryptionFailed)
    end
  end

  describe ".encrypt" do
    it "raises InvalidAlgorithm for unsupported alg" do
      expect {
        described_class.encrypt(payload, public_key: ec_key, alg: "RSA-OAEP", enc: "A256GCM")
      }.to raise_error(described_class::InvalidAlgorithm, /Unsupported alg/)
    end

    it "raises InvalidAlgorithm for unsupported enc" do
      expect {
        described_class.encrypt(payload, public_key: ec_key, alg: "ECDH-ES+A256KW", enc: "A192GCM")
      }.to raise_error(described_class::InvalidAlgorithm, /Unsupported enc/)
    end
  end
end
