# typed: false

require "rails_helper"

RSpec.describe StandardSingpass::Myinfo::TestPersonas do
  it "bundles the personas hosts drive mock callbacks against" do
    expect(described_class.keys).to include(
      "default", "self_employed", "tamil_name", "permanent_resident",
      "sparse_data", "fin_holder", "work_permit_holder", "error_paths",
      "duplicate_check"
    )
  end

  it "parses every bundled persona without raising" do
    described_class.keys.each do |key|
      parsed = StandardSingpass::Myinfo::PersonDataParser.call(described_class.fetch(key))
      expect(parsed).to be_a(Hash), "persona #{key.inspect} did not parse"
    end
  end

  it "models a Work Permit holder (FIN, RPass)" do
    persona = described_class.fetch("work_permit_holder")
    expect(persona.dig("uinfin", "value")).to start_with("G")
    expect(persona.dig("passtype", "code")).to eq("RPass")
  end

  it "falls back to the default persona for a blank key" do
    expect(described_class.fetch(nil)).to eq(described_class.fetch("default"))
  end

  it "raises UnknownPersona for an unknown key" do
    expect { described_class.fetch("nope") }.to raise_error(described_class::UnknownPersona)
  end

  it "no longer defines reload! (removed in 0.5)" do
    expect(described_class).not_to respond_to(:reload!)
  end
end
