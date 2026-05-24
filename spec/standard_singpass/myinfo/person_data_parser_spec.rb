require "rails_helper"

RSpec.describe StandardSingpass::Myinfo::PersonDataParser do
  let(:full_person_data) do
    {
      "uinfin" => { "value" => "S1234567A" },
      "name" => { "value" => "John Doe" },
      "sex" => { "code" => "M" },
      "race" => { "code" => "CN" },
      "nationality" => { "code" => "SG" },
      "dob" => { "value" => "1990-01-15" },
      "email" => { "value" => "john@example.com" },
      "mobileno" => {
        "prefix" => { "value" => "+" },
        "areacode" => { "value" => "65" },
        "nbr" => { "value" => "91234567" }
      },
      "regadd" => {
        "block" => { "value" => "123" },
        "building" => { "value" => "Tower A" },
        "floor" => { "value" => "10" },
        "unit" => { "value" => "05" },
        "street" => { "value" => "Orchard Road" },
        "postal" => { "value" => "238888" },
        "country" => { "code" => "SG" }
      },
      "residentialstatus" => { "code" => "C" },
      "marital" => { "code" => "1" }
    }
  end

  describe ".call" do
    it "extracts all fields from complete person data" do
      result = described_class.call(full_person_data)

      expect(result[:nric]).to eq("S1234567A")
      expect(result[:name]).to eq("John Doe")
      expect(result[:sex]).to eq("M")
      expect(result[:race]).to eq("CN")
      expect(result[:nationality]).to eq("SG")
      expect(result[:date_of_birth]).to eq("1990-01-15")
      expect(result[:email]).to eq("john@example.com")
      expect(result[:mobile_number]).to eq("+6591234567")
      expect(result[:residential_status]).to eq("C")
      expect(result[:marital_status]).to eq("1")
    end

    it "does not extract education_level (academic qualifications excluded from the default scope)" do
      person_data = full_person_data.merge("edulevel" => { "code" => "7" })
      result = described_class.call(person_data)
      expect(result).not_to have_key(:education_level)
    end

    it "extracts registered address fields" do
      result = described_class.call(full_person_data)
      addr = result[:registered_address]

      expect(addr[:block]).to eq("123")
      expect(addr[:building]).to eq("Tower A")
      expect(addr[:floor]).to eq("10")
      expect(addr[:unit]).to eq("05")
      expect(addr[:street]).to eq("Orchard Road")
      expect(addr[:postal]).to eq("238888")
      expect(addr[:country]).to eq("SG")
    end

    it "handles nil person data" do
      result = described_class.call(nil)
      expect(result).to eq({})
    end

    it "handles empty person data" do
      result = described_class.call({})
      expect(result).to eq({})
    end

    it "omits nil fields" do
      partial_data = { "uinfin" => { "value" => "S1234567A" } }
      result = described_class.call(partial_data)

      expect(result).to eq({ nric: "S1234567A" })
      expect(result).not_to have_key(:email)
      expect(result).not_to have_key(:mobile_number)
    end

    it "extracts mobile number from the Singpass FAPI 2.0 shape (prefix/areacode/nbr each wrapped in value)" do
      data = {
        "mobileno" => {
          "prefix" => { "value" => "+" },
          "areacode" => { "value" => "65" },
          "nbr" => { "value" => "97399245" }
        }
      }
      result = described_class.call(data)

      expect(result[:mobile_number]).to eq("+6597399245")
    end

    it "returns nil when mobileno has no nbr" do
      data = {
        "mobileno" => {
          "prefix" => { "value" => "+" },
          "areacode" => { "value" => "65" }
        }
      }
      result = described_class.call(data)

      expect(result).not_to have_key(:mobile_number)
    end

    it "returns nil when the prefix is missing (avoids producing a number without +)" do
      data = {
        "mobileno" => {
          "areacode" => { "value" => "65" },
          "nbr" => { "value" => "97399245" }
        }
      }
      result = described_class.call(data)

      expect(result).not_to have_key(:mobile_number)
    end

    # Per Singpass's v5 migration guide, the userinfo response wraps the
    # attribute set in a `person_info` field. The parser unwraps once on
    # the way in so all extractors can read attributes at the top level.
    context "with the FAPI 2.0 person_info wrapper" do
      let(:wrapped_person_data) do
        {
          "sub" => "1c0cee38-3a8f-4f8a-83bc-7a0e4c59d6a9",
          "person_info" => full_person_data
        }
      end

      it "extracts attributes from inside the wrapper" do
        result = described_class.call(wrapped_person_data)

        expect(result[:nric]).to eq("S1234567A")
        expect(result[:name]).to eq("John Doe")
        expect(result[:sex]).to eq("M")
        expect(result[:mobile_number]).to eq("+6591234567")
      end

      it "handles a nil person_info entry" do
        data = { "sub" => "1c0cee38-3a8f-4f8a-83bc-7a0e4c59d6a9", "person_info" => nil }
        result = described_class.call(data)
        expect(result).to eq({})
      end
    end

    # Expanded MyInfo data catalog: alternative names, FIN-only pass info,
    # address-derived housing type, employment, CPF, NOA, HDB ownership, and
    # vehicle ownership. All flow into the host's parsed-fields projection so
    # downstream consumers (underwriters, admin views) can read the full set
    # without re-implementing extraction.
    describe "expanded data catalog" do
      describe "alternative names" do
        it "extracts alias, hanyu pinyin, hanyu pinyin alias, and married names" do
          data = {
            "aliasname" => { "value" => "JOHN" },
            "hanyupinyinname" => { "value" => "WANG XIAO MING" },
            "hanyupinyinaliasname" => { "value" => "JOHN WANG" },
            "marriedname" => { "value" => "DOE-SMITH" }
          }
          result = described_class.call(data)

          expect(result[:alias_name]).to eq("JOHN")
          expect(result[:hanyu_pinyin_name]).to eq("WANG XIAO MING")
          expect(result[:hanyu_pinyin_alias_name]).to eq("JOHN WANG")
          expect(result[:married_name]).to eq("DOE-SMITH")
        end
      end

      describe "FIN-only pass info" do
        it "prefers the human-readable desc over the raw enum code" do
          data = {
            "passtype" => { "code" => "EP", "desc" => "EMPLOYMENT PASS" },
            "passstatus" => { "code" => "LIVE", "desc" => "LIVE" },
            "passexpirydate" => { "value" => "2027-12-31" },
            "employmentsector" => { "code" => "FINSVCS", "desc" => "FINANCIAL SERVICES" }
          }
          result = described_class.call(data)

          expect(result[:pass_type]).to eq("EMPLOYMENT PASS")
          expect(result[:pass_status]).to eq("LIVE")
          expect(result[:pass_expiry_date]).to eq("2027-12-31")
          expect(result[:employment_sector]).to eq("FINANCIAL SERVICES")
        end

        it "falls back to the code when desc is missing" do
          data = {
            "passtype" => { "code" => "EP" },
            "passstatus" => { "code" => "LIVE" }
          }
          result = described_class.call(data)

          expect(result[:pass_type]).to eq("EP")
          expect(result[:pass_status]).to eq("LIVE")
        end

        it "omits pass info entirely for SC/PR borrowers (no field present)" do
          result = described_class.call(full_person_data)
          expect(result).not_to have_key(:pass_type)
          expect(result).not_to have_key(:pass_status)
        end
      end

      describe "housing type" do
        it "prefers desc over the raw enum code so borrowers see '4-ROOM FLAT' not '112'" do
          data = {
            "hdbtype" => { "code" => "112", "desc" => "4-ROOM FLAT" },
            "housingtype" => { "code" => "HDB", "desc" => "HDB" }
          }
          result = described_class.call(data)

          expect(result[:hdb_type]).to eq("4-ROOM FLAT")
          expect(result[:housing_type]).to eq("HDB")
        end

        it "falls back to the code when desc is missing" do
          data = { "hdbtype" => { "code" => "112" } }
          result = described_class.call(data)
          expect(result[:hdb_type]).to eq("112")
        end
      end

      describe "employment" do
        # Stored as `:employment` (not `:employer_name`) because the upstream
        # `employment` field returns a company name for FIN holders but a
        # status label ("EMPLOYED" / "SELF-EMPLOYED") for SC/PR. The consumer
        # decides how to render based on residential status.
        it "extracts the employment field for FIN holders (company name)" do
          data = {
            "employment" => { "value" => "ACME PTE LTD" },
            "occupation" => { "code" => "5223", "desc" => "SALES SUPERVISOR" }
          }
          result = described_class.call(data)

          expect(result[:employment]).to eq("ACME PTE LTD")
          # SSOC code is opaque to borrowers; the desc is the only useful
          # form for the review screen + Singpass officer audit.
          expect(result[:occupation]).to eq("SALES SUPERVISOR")
        end

        it "extracts the employment field for SC/PR (status label)" do
          data = { "employment" => { "value" => "SELF-EMPLOYED" } }
          result = described_class.call(data)

          expect(result[:employment]).to eq("SELF-EMPLOYED")
        end

        it "does not surface employer_name (renamed to :employment to avoid mislabeling SC/PR)" do
          data = { "employment" => { "value" => "EMPLOYED" } }
          result = described_class.call(data)

          expect(result).not_to have_key(:employer_name)
        end

        it "extracts cpf employer history" do
          data = {
            "cpfemployers" => {
              "history" => [
                { "employer" => { "value" => "ACME" }, "month" => { "value" => "2026-04" } },
                { "employer" => { "value" => "BETA" }, "month" => { "value" => "2026-03" } }
              ]
            }
          }
          result = described_class.call(data)

          expect(result[:cpf_employers]).to eq([
            { name: "ACME", month: "2026-04" },
            { name: "BETA", month: "2026-03" }
          ])
        end

        it "tolerates the direct-array shape some Singpass attributes use" do
          data = {
            "cpfemployers" => [
              { "employer" => { "value" => "ACME" }, "month" => { "value" => "2026-04" } }
            ]
          }
          result = described_class.call(data)

          expect(result[:cpf_employers]).to eq([{ name: "ACME", month: "2026-04" }])
        end
      end

      describe "income" do
        it "extracts noa-basic and noa-history-basic" do
          data = {
            "noa-basic" => {
              "yearofassessment" => { "value" => "2025" },
              "amount" => { "value" => "75000.00" }
            },
            "noahistory-basic" => {
              "noas" => [
                { "yearofassessment" => { "value" => "2024" }, "amount" => { "value" => "70000.00" } },
                { "yearofassessment" => { "value" => "2023" }, "amount" => { "value" => "65000.00" } }
              ]
            }
          }
          result = described_class.call(data)

          expect(result[:noa_basic]).to eq(year_of_assessment: "2025", amount: "75000.00")
          expect(result[:noa_history_basic]).to eq([
            { year_of_assessment: "2024", amount: "70000.00" },
            { year_of_assessment: "2023", amount: "65000.00" }
          ])
        end

        it "extracts detailed noa with income breakdown" do
          data = {
            "noa" => {
              "yearofassessment" => { "value" => "2025" },
              "amount" => { "value" => "75000.00" },
              "employment" => { "value" => "60000.00" },
              "trade" => { "value" => "5000.00" },
              "rent" => { "value" => "10000.00" },
              "interest" => { "value" => "0.00" },
              "taxclearance" => { "value" => "C" }
            }
          }
          result = described_class.call(data)

          expect(result[:noa]).to eq(
            year_of_assessment: "2025",
            amount: "75000.00",
            employment: "60000.00",
            trade: "5000.00",
            rent: "10000.00",
            interest: "0.00",
            tax_category: "C"
          )
        end

        it "extracts cpf contribution history" do
          data = {
            "cpfcontributions" => {
              "history" => [
                {
                  "employer" => { "value" => "ACME" },
                  "month" => { "value" => "2026-04" },
                  "amount" => { "value" => "1850.00" },
                  "date" => { "value" => "2026-04-15" }
                }
              ]
            }
          }
          result = described_class.call(data)

          expect(result[:cpf_contributions]).to eq([
            { employer: "ACME", month: "2026-04", amount: "1850.00", date: "2026-04-15" }
          ])
        end

        it "extracts detailed noa history (year-by-year income breakdown)" do
          data = {
            "noahistory" => {
              "noas" => [
                {
                  "yearofassessment" => { "value" => "2024" },
                  "amount" => { "value" => "70000.00" },
                  "employment" => { "value" => "55000.00" },
                  "trade" => { "value" => "5000.00" },
                  "rent" => { "value" => "10000.00" },
                  "interest" => { "value" => "0.00" },
                  "taxclearance" => { "value" => "C" }
                },
                {
                  "yearofassessment" => { "value" => "2023" },
                  "amount" => { "value" => "65000.00" },
                  "employment" => { "value" => "65000.00" }
                }
              ]
            }
          }
          result = described_class.call(data)

          expect(result[:noa_history]).to eq([
            {
              year_of_assessment: "2024",
              amount: "70000.00",
              employment: "55000.00",
              trade: "5000.00",
              rent: "10000.00",
              interest: "0.00",
              tax_category: "C"
            },
            {
              year_of_assessment: "2023",
              amount: "65000.00",
              employment: "65000.00"
            }
          ])
        end
      end

      describe "assets and liabilities" do
        it "extracts cpf ordinary account balance only (MA/SA/RA ring-fenced)" do
          data = {
            "cpfbalances" => {
              "oa" => { "value" => "12345.67" },
              "ma" => { "value" => "55000.00" },
              "sa" => { "value" => "40000.00" }
            }
          }
          result = described_class.call(data)

          expect(result[:cpf_balances]).to eq(ordinary_account: "12345.67")
        end

        it "extracts cpf housing withdrawal totals" do
          data = {
            "cpfhousingwithdrawal" => {
              "totalprincipalamount" => { "value" => "200000.00" },
              "totalmonthlyinstalmentamount" => { "value" => "1500.00" },
              "totalaccruedinterestamount" => { "value" => "50000.00" }
            }
          }
          result = described_class.call(data)

          expect(result[:cpf_housing_withdrawal]).to eq(
            principal: "200000.00",
            monthly_instalment: "1500.00",
            accrued_interest: "50000.00"
          )
        end

        it "extracts ownerprivate flag as 'Y' string" do
          data = { "ownerprivate" => { "value" => "Y" } }
          result = described_class.call(data)

          expect(result[:owner_private]).to eq("Y")
        end

        # Real FAPI 2.0 staging traffic has been observed returning
        # `ownerprivate` as a JSON boolean rather than the documented "Y"/"N"
        # string. extract_value normalises booleans so downstream consumers
        # see one shape; without this the Sorbet sig
        # (`returns(T.nilable(String))`) raises TypeError on the affected
        # persona data.
        it "normalises a boolean `true` ownerprivate to 'Y'" do
          data = { "ownerprivate" => { "value" => true } }
          result = described_class.call(data)

          expect(result[:owner_private]).to eq("Y")
        end

        it "normalises a boolean `false` ownerprivate to 'N'" do
          data = { "ownerprivate" => { "value" => false } }
          result = described_class.call(data)

          expect(result[:owner_private]).to eq("N")
        end

        it "extracts hdb ownership records (one entry per flat owned)" do
          data = {
            "hdbownership" => [
              {
                "noofowners" => { "value" => "2" },
                "address" => {
                  "block" => { "value" => "456" },
                  "street" => { "value" => "TAMPINES ST 21" },
                  "postal" => { "value" => "520456" },
                  "country" => { "code" => "SG" }
                },
                "hdbtype" => { "code" => "112", "desc" => "4-ROOM FLAT" },
                "loangranted" => { "value" => "300000" },
                "balanceloanrepayment" => { "value" => "15" },
                "outstandingloanbalance" => { "value" => "240000" },
                "monthlyloaninstalment" => { "value" => "1800" },
                "outstandinginstalment" => { "value" => "1800" }
              }
            ]
          }
          result = described_class.call(data)

          expect(result[:hdb_ownership]).to eq([
            {
              no_of_owners: "2",
              address: { block: "456", street: "TAMPINES ST 21", postal: "520456", country: "SG" },
              hdb_type: "4-ROOM FLAT",
              loan_granted: "300000",
              balance_loan_repayment: "15",
              outstanding_loan_balance: "240000",
              monthly_loan_instalment: "1800",
              outstanding_instalment: "1800"
            }
          ])
        end

        it "supports multiple HDB flats in a single response" do
          data = {
            "hdbownership" => [
              { "noofowners" => { "value" => "1" }, "monthlyloaninstalment" => { "value" => "1500" } },
              { "noofowners" => { "value" => "2" }, "monthlyloaninstalment" => { "value" => "2200" } }
            ]
          }
          result = described_class.call(data)

          expect(result[:hdb_ownership].size).to eq(2)
          expect(result[:hdb_ownership].sum { |r| r[:monthly_loan_instalment].to_i }).to eq(3700)
        end

        it "extracts vehicle effective ownership dates" do
          data = {
            "vehicles" => [
              { "effectiveownership" => { "value" => "2024-06-15T00:00:00" } },
              { "effectiveownership" => { "value" => "2020-01-10T00:00:00" } }
            ]
          }
          result = described_class.call(data)

          expect(result[:vehicles]).to eq([
            { effective_ownership_date: "2024-06-15T00:00:00" },
            { effective_ownership_date: "2020-01-10T00:00:00" }
          ])
        end
      end

      describe "edge cases" do
        it "omits CPF / NOA / HDB / vehicle keys entirely when not present (FIN borrower)" do
          # FIN-only borrowers have no CPF, no NOA history, no HDB ownership.
          data = {
            "uinfin" => { "value" => "G1234567X" },
            "passtype" => { "code" => "EP" },
            "passstatus" => { "code" => "LIVE" }
          }
          result = described_class.call(data)

          expect(result).not_to have_key(:cpf_balances)
          expect(result).not_to have_key(:cpf_contributions)
          expect(result).not_to have_key(:cpf_employers)
          expect(result).not_to have_key(:noa_basic)
          expect(result).not_to have_key(:noa_history_basic)
          expect(result).not_to have_key(:hdb_ownership)
          expect(result).not_to have_key(:vehicles)
        end

        it "omits empty arrays — does not return empty hdb_ownership: []" do
          data = { "hdbownership" => [] }
          result = described_class.call(data)
          expect(result).not_to have_key(:hdb_ownership)
        end

        it "skips array entries that have no useful data" do
          data = {
            "hdbownership" => [
              { "noofowners" => { "value" => "1" }, "monthlyloaninstalment" => { "value" => "1500" } },
              {}  # empty entry — should not produce a {} record
            ]
          }
          result = described_class.call(data)
          expect(result[:hdb_ownership].size).to eq(1)
        end
      end
    end
  end
end
