# typed: false

require "rails_helper"

RSpec.describe "StandardSingpass error hierarchy" do
  it "roots every MyInfo error at StandardSingpass::Error" do
    expect(StandardSingpass::Myinfo::Error.ancestors).to include(StandardSingpass::Error)
    %w[AuthenticationError PARError DecryptionError SignatureError RateLimitError ConfigurationError ApiError].each do |name|
      expect(StandardSingpass::Myinfo.const_get(name).ancestors).to include(StandardSingpass::Error)
    end
  end

  describe "deprecated Security error constants" do
    # Silence Ruby's constant-deprecation warning for these lookups.
    around do |example|
      original = Warning[:deprecated]
      Warning[:deprecated] = false
      example.run
    ensure
      Warning[:deprecated] = original
    end

    it "aliases Security::DecryptionError to the public DecryptionError" do
      expect(StandardSingpass::Myinfo::Security::DecryptionError).to be(StandardSingpass::Myinfo::DecryptionError)
    end

    it "aliases Security::ValidationError to the public SignatureError" do
      expect(StandardSingpass::Myinfo::Security::ValidationError).to be(StandardSingpass::Myinfo::SignatureError)
    end

    it "keeps an old `rescue Security::ValidationError` catching what Security raises" do
      expect {
        begin
          raise StandardSingpass::Myinfo::SignatureError, "bad sig"
        rescue StandardSingpass::Myinfo::Security::ValidationError => e
          raise "caught: #{e.message}"
        end
      }.to raise_error(RuntimeError, "caught: bad sig")
    end
  end
end
