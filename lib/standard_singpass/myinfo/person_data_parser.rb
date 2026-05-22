# typed: strict

module StandardSingpass
  module Myinfo
    class PersonDataParser
      extend T::Sig

      # Extracts structured fields from the raw MyInfo person data response.
      # Returns a hash suitable for storing in the host application's MyInfo
      # record (typically encrypted at rest).
      sig { params(person_data: T.nilable(T::Hash[String, T.untyped])).returns(T::Hash[Symbol, T.untyped]) }
      def self.call(person_data)
        new(person_data).parse
      end

      # Singpass FAPI 2.0 / v5 userinfo responses wrap the attribute set in
      # `person_info`:
      #   { "sub" => "<uuid>", "person_info" => { "uinfin" => { "value" => "..." }, ... } }
      # Per the official migration guide:
      #   https://docs.developer.singpass.gov.sg/docs/technical-specifications/migration-guides/login-myinfo-v5-apps
      # We unwrap once here so every consumer can read attributes at the top
      # level. Tests and mock-mode pass flat data — that also works because we
      # only unwrap when the wrapper key is present.
      sig { params(person_data: T.nilable(T::Hash[String, T.untyped])).void }
      def initialize(person_data)
        data = person_data || {}
        @data = T.let(data.key?("person_info") ? (data["person_info"] || {}) : data, T::Hash[String, T.untyped])
      end

      sig { returns(T::Hash[Symbol, T.untyped]) }
      def parse
        {
          # Identity
          nric: extract_value("uinfin"),
          name: extract_value("name"),
          alias_name: extract_value("aliasname"),
          hanyu_pinyin_name: extract_value("hanyupinyinname"),
          hanyu_pinyin_alias_name: extract_value("hanyupinyinaliasname"),
          married_name: extract_value("marriedname"),
          sex: extract_code("sex"),
          race: extract_code("race"),
          nationality: extract_code("nationality"),
          date_of_birth: extract_value("dob"),
          residential_status: extract_code("residentialstatus"),
          marital_status: extract_code("marital"),

          # Contact
          email: extract_value("email"),
          mobile_number:,

          # Address
          registered_address:,
          hdb_type: extract_label("hdbtype"),
          housing_type: extract_label("housingtype"),

          # Pass info — FIN-only; absent for SC/PR.
          pass_type: extract_label("passtype"),
          pass_status: extract_label("passstatus"),
          pass_expiry_date: extract_value("passexpirydate"),
          employment_sector: extract_label("employmentsector"),

          # Employment. Singpass `employment` returns the employer's company
          # name for FIN holders, but a status label ("EMPLOYED" / "SELF-
          # EMPLOYED") for SC/PR. Stored as `:employment` rather than
          # `:employer_name` so consumers don't render "Employer: EMPLOYED"
          # for citizen borrowers.
          employment: extract_value("employment"),
          # SSOC 4-digit code → desc (e.g. "5223" → "SALES SUPERVISOR"). Codes
          # alone are meaningless to humans reviewing what's been shared.
          occupation: extract_label("occupation"),
          cpf_employers:,

          # Income — MAS TDSR inputs
          noa_basic:,
          noa_history_basic:,
          noa: noa_detailed,
          noa_history: noa_history_detailed,
          cpf_contributions:,

          # Assets / liabilities
          cpf_balances:,
          cpf_housing_withdrawal:,
          owner_private: extract_value("ownerprivate"),
          hdb_ownership:,
          vehicles:
        }.compact
      end

      private

      sig { params(field: String).returns(T.nilable(String)) }
      def extract_value(field)
        target = @data[field]
        return nil unless target.is_a?(Hash)
        val = target["value"]
        return nil if val.nil?
        return nil if val.is_a?(String) && val.empty?
        # Singpass returns some Y/N attributes (observed on `ownerprivate`
        # in FAPI 2.0 v5) as JSON booleans rather than "Y"/"N" strings.
        # Normalise here so downstream consumers see one shape regardless
        # of upstream type. Boolean false → "N", true → "Y".
        return val ? "Y" : "N" if val == true || val == false
        return val if val.is_a?(String)
        # Numeric or other unexpected types — stringify rather than crash.
        val.to_s
      end

      sig { params(field: String).returns(T.nilable(String)) }
      def extract_code(field)
        target = @data[field]
        return nil unless target.is_a?(Hash)
        target["code"].presence
      end

      # Singpass MyInfo v5 returns enum fields as `{ code: "112", desc: "4-ROOM FLAT", ... }`.
      # `extract_code` keeps the raw enum for business logic (e.g. residential
      # status eligibility check). For display-only enums (HDB type, housing
      # type, occupation, pass info, employment sector) the desc is what the
      # human reviewing what's been shared needs to see — falling back to code
      # when desc is absent rather than render an empty cell.
      sig { params(field: String).returns(T.nilable(String)) }
      def extract_label(field)
        label_from(@data[field])
      end

      # Hash-direct variant of `extract_label` for nested code/desc blocks
      # (e.g. `hdbownership[].hdbtype`) where the parent already navigated
      # to the leaf hash.
      sig { params(hash: T.untyped).returns(T.nilable(String)) }
      def label_from(hash)
        return nil unless hash.is_a?(Hash)
        hash["desc"].presence || hash["code"].presence
      end

      # Singpass MyInfo (FAPI 2.0) returns `mobileno` as three nested objects —
      # `prefix` ("+"), `areacode` ("65"), `nbr` ("91234567") — each wrapped in
      # `{ "value" => ... }`.
      sig { returns(T.nilable(String)) }
      def mobile_number
        mobileno = @data["mobileno"]
        return nil unless mobileno.is_a?(Hash)

        prefix = mobileno.dig("prefix", "value")
        areacode = mobileno.dig("areacode", "value")
        number = mobileno.dig("nbr", "value")
        return nil if number.blank? || prefix.blank?

        "#{prefix}#{areacode}#{number}"
      end

      sig { returns(T.nilable(T::Hash[Symbol, String])) }
      def registered_address
        addr = @data["regadd"]
        return nil unless addr

        {
          block: addr.dig("block", "value"),
          building: addr.dig("building", "value"),
          floor: addr.dig("floor", "value"),
          unit: addr.dig("unit", "value"),
          street: addr.dig("street", "value"),
          postal: addr.dig("postal", "value"),
          country: addr.dig("country", "code")
        }.compact
      end

      # CPF Ordinary Account balance only. FAPI 2.0 sub-attribute scope
      # assumption: the `cpfbalances.oa` scope returns the response in the
      # nested form `{ "cpfbalances": { "oa": { "value": "..." } } }` rather
      # than a flattened key. Same assumption for `hdbownership.*` and
      # `vehicles.effectiveownership` below.
      sig { returns(T.nilable(T::Hash[Symbol, String])) }
      def cpf_balances
        oa = @data.dig("cpfbalances", "oa", "value")
        return nil if oa.blank?
        { ordinary_account: oa }
      end

      sig { returns(T.nilable(T::Array[T::Hash[Symbol, String]])) }
      def cpf_contributions
        list = array_at("cpfcontributions", "history")
        return nil unless list

        list.filter_map do |entry|
          next unless entry.is_a?(Hash)
          record = {
            employer: entry.dig("employer", "value"),
            month: entry.dig("month", "value"),
            amount: entry.dig("amount", "value"),
            date: entry.dig("date", "value")
          }.compact
          record.presence
        end.presence
      end

      sig { returns(T.nilable(T::Array[T::Hash[Symbol, String]])) }
      def cpf_employers
        list = array_at("cpfemployers", "history")
        return nil unless list

        list.filter_map do |entry|
          next unless entry.is_a?(Hash)
          record = {
            name: entry.dig("employer", "value"),
            month: entry.dig("month", "value")
          }.compact
          record.presence
        end.presence
      end

      sig { returns(T.nilable(T::Hash[Symbol, String])) }
      def cpf_housing_withdrawal
        block = @data["cpfhousingwithdrawal"]
        return nil unless block.is_a?(Hash)

        record = {
          principal: block.dig("totalprincipalamount", "value"),
          monthly_instalment: block.dig("totalmonthlyinstalmentamount", "value"),
          accrued_interest: block.dig("totalaccruedinterestamount", "value")
        }.compact
        record.presence
      end

      sig { returns(T.nilable(T::Hash[Symbol, String])) }
      def noa_basic
        noa_record(@data["noa-basic"])
      end

      sig { returns(T.nilable(T::Array[T::Hash[Symbol, String]])) }
      def noa_history_basic
        list = array_at("noahistory-basic", "noas")
        return nil unless list

        list.filter_map { |entry| noa_record(entry) }.presence
      end

      sig { returns(T.nilable(T::Hash[Symbol, String])) }
      def noa_detailed
        block = @data["noa"]
        return nil unless block.is_a?(Hash)

        record = {
          year_of_assessment: block.dig("yearofassessment", "value"),
          amount: block.dig("amount", "value"),
          employment: block.dig("employment", "value"),
          trade: block.dig("trade", "value"),
          rent: block.dig("rent", "value"),
          interest: block.dig("interest", "value"),
          tax_category: block.dig("taxclearance", "value")
        }.compact
        record.presence
      end

      sig { returns(T.nilable(T::Array[T::Hash[Symbol, String]])) }
      def noa_history_detailed
        list = array_at("noahistory", "noas")
        return nil unless list

        list.filter_map do |entry|
          next unless entry.is_a?(Hash)
          record = {
            year_of_assessment: entry.dig("yearofassessment", "value"),
            amount: entry.dig("amount", "value"),
            employment: entry.dig("employment", "value"),
            trade: entry.dig("trade", "value"),
            rent: entry.dig("rent", "value"),
            interest: entry.dig("interest", "value"),
            tax_category: entry.dig("taxclearance", "value")
          }.compact
          record.presence
        end.presence
      end

      # HDB ownership records — one entry per flat owned. The 8 sub-fields
      # drive TDSR housing-loan calculations: monthly instalment is the most
      # important (direct repayment-capacity reduction); outstanding balance
      # gives leverage ratio context.
      sig { returns(T.nilable(T::Array[T::Hash[Symbol, T.untyped]])) }
      def hdb_ownership
        list = array_at("hdbownership")
        return nil unless list

        list.filter_map do |entry|
          next unless entry.is_a?(Hash)
          record = {
            no_of_owners: entry.dig("noofowners", "value"),
            address: hdb_address(entry["address"]),
            hdb_type: label_from(entry["hdbtype"]),
            loan_granted: entry.dig("loangranted", "value"),
            balance_loan_repayment: entry.dig("balanceloanrepayment", "value"),
            outstanding_loan_balance: entry.dig("outstandingloanbalance", "value"),
            monthly_loan_instalment: entry.dig("monthlyloaninstalment", "value"),
            outstanding_instalment: entry.dig("outstandinginstalment", "value")
          }.compact
          record.presence
        end.presence
      end

      sig { params(addr: T.untyped).returns(T.nilable(T::Hash[Symbol, String])) }
      def hdb_address(addr)
        return nil unless addr.is_a?(Hash)

        record = {
          block: addr.dig("block", "value"),
          building: addr.dig("building", "value"),
          floor: addr.dig("floor", "value"),
          unit: addr.dig("unit", "value"),
          street: addr.dig("street", "value"),
          postal: addr.dig("postal", "value"),
          country: addr.dig("country", "code")
        }.compact
        record.presence
      end

      sig { returns(T.nilable(T::Array[T::Hash[Symbol, String]])) }
      def vehicles
        list = array_at("vehicles")
        return nil unless list

        list.filter_map do |entry|
          next unless entry.is_a?(Hash)
          date = entry.dig("effectiveownership", "value")
          next if date.blank?
          { effective_ownership_date: date }
        end.presence
      end

      sig { params(entry: T.untyped).returns(T.nilable(T::Hash[Symbol, String])) }
      def noa_record(entry)
        return nil unless entry.is_a?(Hash)
        record = {
          year_of_assessment: entry.dig("yearofassessment", "value"),
          amount: entry.dig("amount", "value")
        }.compact
        record.presence
      end

      # Singpass returns array-shaped attributes either as a direct array
      # (e.g. `vehicles: [...]`) or wrapped in a sub-key like
      # `cpfcontributions: { history: [...] }` / `noahistory: { noas: [...] }`.
      sig { params(field: String, sub: T.nilable(String)).returns(T.nilable(T::Array[T.untyped])) }
      def array_at(field, sub = nil)
        block = @data[field]

        direct =
          case block
          when Array then block
          when Hash then sub ? block[sub] : nil
          end

        return direct if direct.is_a?(Array)
        nil
      end
    end
  end
end
