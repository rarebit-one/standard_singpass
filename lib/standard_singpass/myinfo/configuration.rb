# MyInfo (Singpass) configuration.
#
# The host application is responsible for reading environment variables and
# passing them in via `StandardSingpass::Myinfo.configure`. The gem itself
# does not consult ENV — keeping env wiring at the host boundary makes the
# gem portable and trivially testable.
#
# Required attributes:
#   c.environment        - :production | :staging (drives endpoint URLs)
#   c.client_id          - App ID from Singpass Developer Portal
#   c.redirect_url       - OAuth callback URL (e.g. https://example.com/singpass/callback)
#   c.private_jwks_json  - Full JWKS JSON string with private signing + encryption keys
#                          (keys are identified by "use": "sig" and "use": "enc")
#
# Optional attributes:
#   c.scope                  - Space-separated scopes (defaults to DEFAULT_SCOPE)
#   c.minimum_acr            - Required Authentication Context Class Reference URN
#   c.network_wrapper        - Lambda wrapping outbound Faraday calls (e.g. circuit breaker)
#   c.mock_mode              - When true, suppresses missing-key warnings
#   c.personas_path          - Pathname to JSON file of test personas
#   c.authorize_url, c.par_url, c.token_url, c.userinfo_url,
#   c.jwks_url, c.userinfo_jwks_url, c.issuer
#                            - Override individual endpoints (rarely needed)

module StandardSingpass
  module Myinfo
    class Configuration
      # Default MyInfo scope — keep aligned with the Singpass developer-portal
      # approval list. Entries on separate lines so diffs against the portal's
      # ordered dump are reviewable line-by-line. Joined into a single
      # space-delimited string before sending to PAR.
      DEFAULT_SCOPE = %w[
        openid
        aliasname
        cpfbalances.oa
        cpfcontributions
        cpfemployers
        cpfhousingwithdrawal
        dob
        email
        employment
        employmentsector
        hanyupinyinaliasname
        hanyupinyinname
        hdbownership.address
        hdbownership.balanceloanrepayment
        hdbownership.hdbtype
        hdbownership.loangranted
        hdbownership.monthlyloaninstalment
        hdbownership.noofowners
        hdbownership.outstandinginstalment
        hdbownership.outstandingloanbalance
        hdbtype
        housingtype
        marital
        marriedname
        mobileno
        name
        nationality
        noa
        noa-basic
        noahistory
        noahistory-basic
        occupation
        ownerprivate
        passexpirydate
        passstatus
        passtype
        race
        regadd
        residentialstatus
        sex
        uinfin
        vehicles.effectiveownership
      ].join(" ").freeze

      # The categories and their lender-underwriting purpose (PDPA §18,
      # Purpose Limitation):
      #
      #   Identity        — uinfin, name, alias names, dob, sex, race,
      #                     nationality, residentialstatus → KYC, contracts
      #   Pass (FIN-only) — passtype, passstatus, passexpirydate,
      #                     employmentsector → tenure-vs-pass-expiry, eligibility
      #   Address         — regadd, hdbtype, housingtype → KYC + income proxy
      #   Contact         — mobileno, email → OTP, mailers
      #   Family          — marital → soft underwriting signal
      #   Income          — noa, noa-basic, noahistory, noahistory-basic,
      #                     cpfcontributions → MAS TDSR input
      #   Employment      — employment, occupation, cpfemployers
      #                     → continuity + employer stability
      #   Assets          — cpfbalances.oa (only OA — MA/SA/RA are ring-fenced
      #                     and not lender-relevant), ownerprivate
      #   Liabilities     — cpfhousingwithdrawal, hdbownership.* (8 sub-fields)
      #                     → TDSR housing component
      #   Vehicle         — vehicles.effectiveownership (asset/liability hint;
      #                     full vehicle details deliberately not requested)
      #
      # `cpfbalances.oa`, `hdbownership.*`, and `vehicles.effectiveownership`
      # use FAPI 2.0 sub-attribute scope notation — sharper data minimisation
      # than parent-keyword grants.

      PRODUCTION_ENDPOINTS = {
        authorize_url:     "https://id.singpass.gov.sg/fapi/auth",
        par_url:           "https://id.singpass.gov.sg/fapi/par",
        token_url:         "https://id.singpass.gov.sg/fapi/token",
        jwks_url:          "https://id.singpass.gov.sg/.well-known/keys",
        issuer:            "https://id.singpass.gov.sg/fapi",
        userinfo_url:      "https://id.singpass.gov.sg/fapi/userinfo",
        userinfo_jwks_url: "https://id.singpass.gov.sg/.well-known/keys"
      }.freeze

      STAGING_ENDPOINTS = {
        authorize_url:     "https://stg-id.singpass.gov.sg/fapi/auth",
        par_url:           "https://stg-id.singpass.gov.sg/fapi/par",
        token_url:         "https://stg-id.singpass.gov.sg/fapi/token",
        jwks_url:          "https://stg-id.singpass.gov.sg/.well-known/keys",
        issuer:            "https://stg-id.singpass.gov.sg/fapi",
        userinfo_url:      "https://stg-id.singpass.gov.sg/fapi/userinfo",
        userinfo_jwks_url: "https://stg-id.singpass.gov.sg/.well-known/keys"
      }.freeze

      attr_accessor :authorize_url, :par_url, :token_url, :userinfo_url,
                    :jwks_url, :userinfo_jwks_url, :issuer,
                    :client_id, :redirect_url, :scope,
                    :signing_key, :signing_kid, :encryption_keys,
                    :minimum_acr, :network_wrapper, :mock_mode, :personas_path

      def initialize
        self.environment = :staging
        @scope = DEFAULT_SCOPE
        @encryption_keys = []
        @network_wrapper = ->(&block) { block.call }
        @mock_mode = false
      end

      def environment=(env)
        @environment = env
        endpoints = env == :production ? PRODUCTION_ENDPOINTS : STAGING_ENDPOINTS
        @authorize_url     = endpoints[:authorize_url]
        @par_url           = endpoints[:par_url]
        @token_url         = endpoints[:token_url]
        @jwks_url          = endpoints[:jwks_url]
        @issuer            = endpoints[:issuer]
        @userinfo_url      = endpoints[:userinfo_url]
        @userinfo_jwks_url = endpoints[:userinfo_jwks_url]
      end

      attr_reader :environment

      # Accepts the raw JWKS JSON string and populates signing_key, signing_kid,
      # and encryption_keys. Logs and reports issues via Rails.logger / Rails.error
      # rather than raising — a malformed JWKS silently degrades the Singpass
      # widget at runtime, but the host should boot regardless.
      def private_jwks_json=(jwks_json)
        @encryption_keys = []
        @signing_key = nil
        @signing_kid = nil

        if jwks_json.nil? || jwks_json.to_s.strip.empty?
          return if mock_mode || (defined?(Rails) && Rails.env.test?)
          Rails.logger.warn("StandardSingpass::Myinfo: private_jwks_json is not set — Singpass flow will fail at first request")
          return
        end

        jwks = JSON.parse(jwks_json)
        raise TypeError, "private_jwks_json must be a JSON object with a \"keys\" array, got #{jwks.class}" unless jwks.is_a?(Hash)
        keys = jwks["keys"] || []

        sig_jwks = keys.select { |k| k.is_a?(Hash) && k["use"] == "sig" }
        Rails.logger.warn("StandardSingpass::Myinfo: multiple sig keys in private_jwks_json — using first") if sig_jwks.size > 1
        sig_jwk = sig_jwks.first
        if sig_jwk
          @signing_kid = sig_jwk["kid"]
          @signing_key = jwk_to_private_pem(sig_jwk, role: "signing")
          # Keep paired: a nil signing_key with a populated signing_kid is
          # confusing in console triage (which is the scenario this method is
          # trying to help with).
          @signing_kid = nil unless @signing_key
        elsif !mock_mode && !(defined?(Rails) && Rails.env.test?)
          Rails.logger.error("StandardSingpass::Myinfo: private_jwks_json contains no key with \"use\":\"sig\"")
        end

        enc_jwks = keys.select { |k| k.is_a?(Hash) && k["use"] == "enc" }
        @encryption_keys = enc_jwks.filter_map do |enc_jwk|
          pem = jwk_to_private_pem(enc_jwk, role: "encryption")
          next unless pem
          { kid: enc_jwk["kid"], key: pem }
        end
        # Distinguish the two empty-state cases: missing entirely (operator
        # forgot to include enc keys) vs all-rejected (every enc key was
        # public-only or otherwise unloadable). The latter is the trap the
        # rest of this method is built to catch.
        if @encryption_keys.empty? && !mock_mode && !(defined?(Rails) && Rails.env.test?)
          if enc_jwks.empty?
            Rails.logger.error("StandardSingpass::Myinfo: private_jwks_json contains no key with \"use\":\"enc\"")
          else
            Rails.logger.error("StandardSingpass::Myinfo: private_jwks_json has \"use\":\"enc\" keys but none are usable (all public-only or invalid)")
          end
        end
      rescue JSON::ParserError, TypeError => e
        # JSON::ParserError: not valid JSON. TypeError: valid JSON but wrong
        # shape (e.g. an array, a string) — caught explicitly so an operator
        # who pastes the wrong file doesn't see a bare TypeError escape.
        # Reported because a malformed private JWKS silently degrades the
        # Singpass widget — the request that finally fails will report, but by
        # then customers have hit the broken page.
        Rails.logger.error("StandardSingpass::Myinfo: failed to parse private_jwks_json: #{e.class}: #{e.message}")
        Rails.error.report(e, handled: true, context: { component: "StandardSingpass::Myinfo::Configuration", reason: "parse_private_jwks" }) if defined?(Rails.error)
        @encryption_keys = []
      end

      private

      # Converts a JWK to a *private* PEM. Refuses public-only JWKs — the
      # private scalar (`d` for EC) must be present, otherwise signing /
      # decryption will fail at runtime deep inside a request flow with an
      # opaque OpenSSL::PKey::PKeyError. Logs the kid so operators can
      # correlate against the JWKS they pasted into the env var.
      def jwk_to_private_pem(jwk_hash, role:)
        kid = jwk_hash["kid"]
        if jwk_hash["d"].blank?
          Rails.logger.error("StandardSingpass::Myinfo: #{role} JWK #{kid.inspect} is public-only (missing \"d\") — re-export with include_private: true")
          return nil
        end
        JWT::JWK.new(jwk_hash).keypair.to_pem
      rescue => e
        Rails.logger.error("StandardSingpass::Myinfo: failed to convert #{role} JWK #{kid.inspect}: #{e.class} — #{e.message}")
        Rails.error.report(e, handled: true, context: { component: "StandardSingpass::Myinfo::Configuration", reason: "jwk_to_private_pem", role:, kid: }) if defined?(Rails.error)
        nil
      end
    end
  end
end
