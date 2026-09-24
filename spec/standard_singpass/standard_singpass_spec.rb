# typed: false

require "rails_helper"

RSpec.describe StandardSingpass do
  after { StandardSingpass::Myinfo.reset_configuration! }

  describe ".config" do
    it "returns the MyInfo configuration object" do
      expect(described_class.config).to be(StandardSingpass::Myinfo.configuration)
    end

    it "is also available as Myinfo.config" do
      expect(StandardSingpass::Myinfo.config).to be(StandardSingpass::Myinfo.configuration)
    end
  end

  describe ".configure" do
    it "yields the MyInfo configuration and returns it" do
      result = described_class.configure { |c| c.client_id = "top-level-client" }

      expect(StandardSingpass::Myinfo.configuration.client_id).to eq("top-level-client")
      expect(result).to be(StandardSingpass::Myinfo.configuration)
    end

    it "resets the cached public JWKS like Myinfo.configure does" do
      StandardSingpass::Myinfo.instance_variable_set(:@public_jwks, { keys: [:stale] })
      described_class.configure { |c| c.client_id = "x" }
      expect(StandardSingpass::Myinfo.instance_variable_get(:@public_jwks)).to be_nil
    end
  end
end
