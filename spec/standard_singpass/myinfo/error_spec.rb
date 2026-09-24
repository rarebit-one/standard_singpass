# typed: false

require "rails_helper"

RSpec.describe "StandardSingpass error hierarchy" do
  it "roots every MyInfo error at StandardSingpass::Error" do
    expect(StandardSingpass::Myinfo::Error.ancestors).to include(StandardSingpass::Error)
    %w[AuthenticationError PARError DecryptionError SignatureError RateLimitError ConfigurationError ApiError].each do |name|
      expect(StandardSingpass::Myinfo.const_get(name).ancestors).to include(StandardSingpass::Error)
    end
  end

  it "no longer defines the Security::DecryptionError / Security::ValidationError aliases (removed in 0.5)" do
    expect(StandardSingpass::Myinfo::Security.const_defined?(:DecryptionError, false)).to be(false)
    expect(StandardSingpass::Myinfo::Security.const_defined?(:ValidationError, false)).to be(false)
  end
end
