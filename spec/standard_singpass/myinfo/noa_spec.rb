# typed: false

require "rails_helper"

RSpec.describe StandardSingpass::Myinfo::Noa do
  let(:noa_2025) do
    { year_of_assessment: "2025", amount: "75000.00", employment: "75000.00" }
  end
  let(:noa_2024) do
    { year_of_assessment: "2024", amount: "70000.00", employment: "70000.00" }
  end

  describe ".history" do
    it "returns the 2-year history when the noahistory scope was granted" do
      parsed = { noa_history: [noa_2025, noa_2024] }

      expect(described_class.history(parsed)).to eq([noa_2025, noa_2024])
    end

    it "wraps the single-year record when only the noa scope was granted" do
      expect(described_class.history({ noa: noa_2025 })).to eq([noa_2025])
    end

    it "prefers the 2-year history when both scopes yielded data" do
      parsed = { noa_history: [noa_2025, noa_2024], noa: noa_2025 }

      expect(described_class.history(parsed)).to eq([noa_2025, noa_2024])
    end

    it "reads string keys, so a hash round-tripped through JSON or a DB column works" do
      parsed = JSON.parse({ noa: noa_2025 }.to_json)

      expect(described_class.history(parsed)).to eq([{ "year_of_assessment" => "2025",
                                                       "amount" => "75000.00",
                                                       "employment" => "75000.00" }])
    end

    it "prefers the history over the single record with string keys too" do
      parsed = JSON.parse({ noa_history: [noa_2025], noa: noa_2024 }.to_json)

      expect(described_class.history(parsed).first["year_of_assessment"]).to eq("2025")
    end

    it "returns nil when neither NOA scope yielded data" do
      expect(described_class.history({})).to be_nil
      expect(described_class.history({ noa_history: [] })).to be_nil
      expect(described_class.history({ noa: {} })).to be_nil
      expect(described_class.history({ noa_history: nil, noa: nil })).to be_nil
    end

    it "returns nil for a non-hash input" do
      expect(described_class.history(nil)).to be_nil
      expect(described_class.history("noa")).to be_nil
    end

    it "ignores the basic-scope keys" do
      expect(described_class.history({ noa_basic: noa_2025 })).to be_nil
    end
  end

  describe ".basic_history" do
    let(:basic_2025) { { year_of_assessment: "2025", amount: "75000.00" } }

    it "returns the basic history when the noahistory-basic scope was granted" do
      expect(described_class.basic_history({ noa_history_basic: [basic_2025] }))
        .to eq([basic_2025])
    end

    it "wraps the single basic record when only noa-basic was granted" do
      expect(described_class.basic_history({ noa_basic: basic_2025 })).to eq([basic_2025])
    end

    it "returns nil when neither basic scope yielded data" do
      expect(described_class.basic_history({ noa: basic_2025 })).to be_nil
    end
  end

  describe "against real parser output" do
    # The point of the module is that it consumes PersonDataParser's own
    # emission, so drive it from the parser rather than a hand-built hash.
    def parse(payload)
      StandardSingpass::Myinfo::PersonDataParser.call(payload)
    end

    def noa_block(year, amount)
      {
        "yearofassessment" => { "value" => year },
        "amount" => { "value" => amount },
        "employment" => { "value" => amount }
      }
    end

    it "normalises a noahistory-scoped payload" do
      parsed = parse("noahistory" => { "noas" => [noa_block("2025", "75000.00"),
                                                  noa_block("2024", "70000.00")] })

      history = described_class.history(parsed)

      expect(history.length).to eq(2)
      expect(history.map { |r| r[:year_of_assessment] }).to eq(%w[2025 2024])
    end

    it "normalises a noa-scoped payload into the same list shape" do
      parsed = parse("noa" => noa_block("2025", "75000.00"))

      history = described_class.history(parsed)

      expect(history.length).to eq(1)
      expect(history.first[:year_of_assessment]).to eq("2025")
      expect(history.first[:amount]).to eq("75000.00")
    end

    it "returns nil for a payload with no NOA scope at all" do
      expect(described_class.history(parse("uinfin" => { "value" => "S1234567A" }))).to be_nil
    end
  end
end
