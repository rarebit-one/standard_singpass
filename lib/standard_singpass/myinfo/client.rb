# typed: strict

module StandardSingpass
  module Myinfo
    class Client
      extend T::Sig

      CLIENT_ASSERTION_TYPE = T.let("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", String)

      REQUIRED_CONFIG = T.let(%i[client_id redirect_url scope token_url authorize_url
                           par_url signing_key signing_kid jwks_url issuer
                           userinfo_url userinfo_jwks_url].freeze, T::Array[Symbol])

      # Allow up to 30 seconds of clock skew for token expiry checks (RFC 7519 §4.1.4)
      CLOCK_SKEW_LEEWAY = T.let(30, Integer)

      # Maximum age for iat (issued-at) claim: reject tokens issued more than 5 minutes ago
      IAT_MAX_AGE = T.let(300, Integer)

      sig { params(config: T::Hash[Symbol, T.untyped]).void }
      def initialize(config = {})
        c = StandardSingpass::Myinfo.configuration
        @client_id = T.let(config[:client_id] || c.client_id, T.nilable(String))
        @redirect_url = T.let(config[:redirect_url] || c.redirect_url, T.nilable(String))
        @scope = T.let(config[:scope] || c.scope, T.nilable(String))
        @token_url = T.let(config[:token_url] || c.token_url, T.nilable(String))
        @userinfo_url = T.let(config[:userinfo_url] || c.userinfo_url, T.nilable(String))
        @authorize_url = T.let(config[:authorize_url] || c.authorize_url, T.nilable(String))
        @par_url = T.let(config[:par_url] || c.par_url, T.nilable(String))
        @signing_key = T.let(config[:signing_key] || c.signing_key, T.nilable(String))
        @signing_kid = T.let(config[:signing_kid] || c.signing_kid, T.nilable(String))
        @encryption_keys = T.let(config[:encryption_keys] || c.encryption_keys || [], T::Array[T::Hash[Symbol, T.untyped]])
        @jwks_url = T.let(config[:jwks_url] || c.jwks_url, T.nilable(String))
        @issuer = T.let(config[:issuer] || c.issuer, T.nilable(String))
        @userinfo_jwks_url = T.let(config[:userinfo_jwks_url] || c.userinfo_jwks_url, T.nilable(String))
        @minimum_acr = T.let(config[:minimum_acr] || c.minimum_acr, T.nilable(String))
        @network_wrapper = T.let(config[:network_wrapper] || c.network_wrapper, T.untyped)
        @http_connection = T.let(nil, T.nilable(Faraday::Connection))

        validate_config!
      end

      sig { params(code_challenge: String, state: String, nonce: String, dpop_key_pair: OpenSSL::PKey::EC).returns(T::Hash[Symbol, T.untyped]) }
      def push_authorization_request(code_challenge:, state:, nonce:, dpop_key_pair:)
        body = {
          response_type: "code",
          client_id: @client_id,
          redirect_uri: @redirect_url,
          scope: @scope,
          code_challenge:,
          code_challenge_method: "S256",
          state:,
          nonce:,
          client_assertion_type: CLIENT_ASSERTION_TYPE,
          client_assertion: Security.build_client_assertion(
            client_id: T.must(@client_id),
            audience: T.must(@issuer),
            signing_key: T.must(@signing_key),
            signing_kid: T.must(@signing_kid)
          )
        }

        # Ask Singpass to enforce a minimum assurance level upstream. The same
        # config attribute also drives downstream validation of the returned
        # id_token (validate_id_token_acr) — defense in depth. When unset, we
        # skip both the request parameter and the validator entirely; useful
        # for sandbox personas that may return non-conformant acr values.
        # Concrete URN per Singpass: `urn:singpass:authentication:loa:N` (N
        # is 2 or 3; Singpass never issues below LOA 2). `.to_s.strip` mirrors
        # the validator so whitespace-only values are treated as unset and any
        # value sent over the wire is trimmed.
        min_acr = @minimum_acr.to_s.strip
        body[:acr_values] = min_acr unless min_acr.empty?

        with_network_wrapper do
          response = http_connection.post(@par_url) do |req|
            req.headers["DPoP"] = Security.build_dpop_proof(
              http_method: "POST",
              url: T.must(@par_url),
              key_pair: dpop_key_pair
            )
            req.headers["Content-Type"] = "application/x-www-form-urlencoded"
            req.body = URI.encode_www_form(body)
          end
          handle_par_response(response)
        end
      rescue Faraday::Error => e
        raise PARError, "PAR endpoint unreachable: #{e.class}"
      end

      sig { params(request_uri: String).returns(String) }
      def build_authorize_redirect(request_uri:)
        params = {
          client_id: @client_id,
          request_uri:
        }

        "#{@authorize_url}?#{URI.encode_www_form(params)}"
      end

      sig { params(auth_code: String, code_verifier: String, dpop_key_pair: OpenSSL::PKey::EC, nonce: T.nilable(String)).returns(T::Hash[Symbol, T.untyped]) }
      def get_person_data(auth_code:, code_verifier:, dpop_key_pair:, nonce: nil)
        token_data = exchange_token(auth_code:, code_verifier:, dpop_key_pair:)
        id_token_payload = validate_id_token(token_data[:id_token], nonce:)

        person_data = fetch_userinfo(access_token: token_data[:access_token], dpop_key_pair:)

        # `acr` is the Authentication Context Class Reference — Singpass FAPI 2.0
        # uses it to communicate which assurance level the user authenticated at
        # (e.g. password+OTP vs. biometrics). Surface it so the callback can
        # persist it for audit. Optional per OIDC core; nil when not present.
        { person_data:, id_token_acr: id_token_payload["acr"] }
      end

      private

      sig { params(response: Faraday::Response).returns(T::Hash[Symbol, T.untyped]) }
      def handle_par_response(response)
        case response.status
        when 200, 201
          data = JSON.parse(response.body)
          { request_uri: data.fetch("request_uri"), expires_in: data.fetch("expires_in") }
        when 401, 403
          raise PARError, "PAR rejected (HTTP #{response.status}): #{body_excerpt(response)}"
        when 429
          raise RateLimitError, "PAR endpoint rate limit exceeded"
        else
          raise PARError, "PAR failed (HTTP #{response.status}): #{body_excerpt(response)}"
        end
      rescue KeyError
        raise PARError, "PAR response missing required fields"
      rescue JSON::ParserError
        raise PARError, "Invalid PAR response format"
      end

      sig { params(auth_code: String, code_verifier: String, dpop_key_pair: OpenSSL::PKey::EC).returns(T::Hash[Symbol, T.untyped]) }
      def exchange_token(auth_code:, code_verifier:, dpop_key_pair:)
        body = {
          grant_type: "authorization_code",
          code: auth_code,
          redirect_uri: @redirect_url,
          code_verifier:,
          client_id: @client_id,
          client_assertion_type: CLIENT_ASSERTION_TYPE,
          client_assertion: Security.build_client_assertion(
            client_id: T.must(@client_id),
            audience: T.must(@issuer),
            signing_key: T.must(@signing_key),
            signing_kid: T.must(@signing_kid),
            code: auth_code
          )
        }

        with_network_wrapper do
          response = http_connection.post(@token_url) do |req|
            req.headers["DPoP"] = Security.build_dpop_proof(
              http_method: "POST",
              url: T.must(@token_url),
              key_pair: dpop_key_pair
            )
            req.headers["Content-Type"] = "application/x-www-form-urlencoded"
            req.body = URI.encode_www_form(body)
          end
          handle_token_response(response)
        end
      rescue Faraday::Error => e
        raise ApiError, "MyInfo token endpoint unreachable: #{e.class}"
      end

      sig { params(access_token: String, dpop_key_pair: OpenSSL::PKey::EC).returns(T::Hash[String, T.untyped]) }
      def fetch_userinfo(access_token:, dpop_key_pair:)
        with_network_wrapper do
          response = http_connection.get(@userinfo_url) do |req|
            req.headers["Authorization"] = "DPoP #{access_token}"
            req.headers["DPoP"] = Security.build_dpop_proof(
              http_method: "GET",
              url: T.must(@userinfo_url),
              key_pair: dpop_key_pair,
              access_token:
            )
          end
          handle_person_response(response, jwks_url: @userinfo_jwks_url)
        end
      rescue Faraday::Error => e
        raise ApiError, "MyInfo userinfo endpoint unreachable: #{e.class}"
      end

      sig { params(id_token: T.nilable(String), nonce: T.nilable(String)).returns(T::Hash[String, T.untyped]) }
      def validate_id_token(id_token, nonce: nil)
        raise AuthenticationError, "ID token missing from token response" unless id_token

        payload = decrypt_and_decode_id_token(id_token)

        validate_id_token_issuer(payload)
        validate_id_token_audience(payload)
        validate_id_token_expiry(payload)
        validate_id_token_iat(payload)
        validate_id_token_sub(payload)
        validate_id_token_acr(payload)
        validate_id_token_nonce(payload, nonce) if nonce.present?

        payload
      end

      # FAPI 2.0 always returns id_tokens as 5-segment JWE (encrypted to our enc
      # key, signed by Singpass). The previous 3-segment fallback was a v3/v4
      # sandbox compatibility path; FAPI 2.0 has no sandbox/production
      # distinction here.
      sig { params(id_token: String).returns(T::Hash[String, T.untyped]) }
      def decrypt_and_decode_id_token(id_token)
        raise AuthenticationError, "ID token must be a 5-segment JWE" unless id_token.split(".", -1).length == 5

        decrypted = Security.decrypt_jwe(id_token, private_keys: @encryption_keys)
        Security.validate_jws(decrypted, jwks_url: T.must(@jwks_url))
      rescue Security::DecryptionError
        raise AuthenticationError, "ID token decryption failed"
      rescue Security::ValidationError
        raise AuthenticationError, "ID token signature verification failed"
      rescue JWT::DecodeError
        raise AuthenticationError, "Failed to decode ID token"
      end

      sig { params(payload: T::Hash[String, T.untyped]).void }
      def validate_id_token_issuer(payload)
        token_iss = payload["iss"]
        raise AuthenticationError, "ID token iss claim is missing" unless token_iss.present?

        unless ActiveSupport::SecurityUtils.secure_compare(token_iss.to_s, @issuer.to_s)
          raise AuthenticationError, "ID token issuer does not match expected issuer"
        end
      end

      sig { params(payload: T::Hash[String, T.untyped]).void }
      def validate_id_token_audience(payload)
        token_aud = payload["aud"]
        raise AuthenticationError, "ID token aud claim is missing" unless token_aud.present?

        aud_values = Array(token_aud)
        unless aud_values.any? { |a| ActiveSupport::SecurityUtils.secure_compare(a.to_s, @client_id.to_s) }
          raise AuthenticationError, "ID token audience does not match client_id"
        end
      end

      sig { params(payload: T::Hash[String, T.untyped]).void }
      def validate_id_token_expiry(payload)
        token_exp = payload["exp"]
        raise AuthenticationError, "ID token exp claim is missing" unless token_exp.present?

        if token_exp.to_i + CLOCK_SKEW_LEEWAY < Time.now.to_i
          raise AuthenticationError, "ID token has expired"
        end
      end

      sig { params(payload: T::Hash[String, T.untyped]).void }
      def validate_id_token_iat(payload)
        token_iat = payload["iat"]
        raise AuthenticationError, "ID token iat claim is missing" unless token_iat.present?

        if token_iat.to_i > Time.now.to_i + CLOCK_SKEW_LEEWAY
          raise AuthenticationError, "ID token iat is in the future"
        end

        if token_iat.to_i + IAT_MAX_AGE < Time.now.to_i
          raise AuthenticationError, "ID token iat is too old"
        end
      end

      sig { params(payload: T::Hash[String, T.untyped], nonce: String).void }
      def validate_id_token_nonce(payload, nonce)
        token_nonce = payload["nonce"]
        raise AuthenticationError, "ID token nonce claim is missing" unless token_nonce.present?

        unless ActiveSupport::SecurityUtils.secure_compare(token_nonce.to_s, nonce.to_s)
          raise AuthenticationError, "ID token nonce does not match session nonce"
        end
      end

      sig { params(payload: T::Hash[String, T.untyped]).void }
      def validate_id_token_sub(payload)
        token_sub = payload["sub"]
        raise AuthenticationError, "ID token sub claim is missing" unless token_sub.present?
      end

      # Enforce a minimum Authentication Context Class Reference (`acr`) on the
      # id_token. The floor is configured via `minimum_acr` so staging and
      # production can diverge — staging may tolerate looser values returned by
      # MyInfo sandbox personas. When the attr is unset or blank, both this
      # validator and the upstream PAR `acr_values` parameter are skipped.
      #
      # Singpass's `acr` URN format is `urn:singpass:authentication:loa:N`
      # where N is 2 or 3 (no LOA 1 path — Singpass's IdP is 2FA by design).
      sig { params(payload: T::Hash[String, T.untyped]).void }
      def validate_id_token_acr(payload)
        required_acr = @minimum_acr.to_s.strip
        return if required_acr.empty?

        required_level = parse_acr_level(required_acr)
        if required_level.nil?
          raise ConfigurationError,
            "minimum_acr=#{required_acr.inspect} is not a recognised Singpass LOA URN (expected: urn:singpass:authentication:loa:N)"
        end

        actual_acr   = payload["acr"]
        actual_level = parse_acr_level(T.cast(actual_acr, T.nilable(String)))

        if actual_level.nil? || actual_level < required_level
          raise AuthenticationError, "id_token acr=#{actual_acr.inspect} is below required minimum (#{required_acr})"
        end
      end

      # Parses the trailing integer N out of `urn:singpass:authentication:loa:N`.
      # Returns nil for blank input or anything that doesn't match — for actual
      # id_token acr claims, callers treat nil as "below the floor" so
      # unparseable values fail closed. For the configured floor, callers
      # distinguish nil as a misconfiguration (ConfigurationError) rather than
      # an assurance-level failure.
      sig { params(acr_string: T.nilable(String)).returns(T.nilable(Integer)) }
      def parse_acr_level(acr_string)
        return nil if acr_string.to_s.empty?
        match = acr_string.to_s.match(/loa:(\d+)\z/)
        match && match[1].to_i
      end

      sig { params(response: Faraday::Response).returns(T::Hash[Symbol, T.untyped]) }
      def handle_token_response(response)
        case response.status
        when 200
          data = JSON.parse(response.body)
          { access_token: data.fetch("access_token"), id_token: data["id_token"] }
        when 401, 403
          raise AuthenticationError, "Token exchange rejected (HTTP #{response.status}): #{body_excerpt(response)}"
        when 429
          raise RateLimitError, "Token endpoint rate limit exceeded"
        else
          raise ApiError, "Token exchange failed (HTTP #{response.status}): #{body_excerpt(response)}"
        end
      rescue KeyError
        raise AuthenticationError, "Token response missing access_token"
      rescue JSON::ParserError
        raise AuthenticationError, "Invalid token response format"
      end

      sig { params(response: Faraday::Response, jwks_url: T.nilable(String)).returns(T::Hash[String, T.untyped]) }
      def handle_person_response(response, jwks_url:)
        case response.status
        when 200
          decrypt_and_validate_person(response.body, jwks_url:)
        when 401, 403
          raise AuthenticationError, "Person data request forbidden (HTTP #{response.status}): #{body_excerpt(response)}"
        when 429
          raise RateLimitError, "Person endpoint rate limit exceeded"
        else
          raise ApiError, "Person data fetch failed (HTTP #{response.status}): #{body_excerpt(response)}"
        end
      end

      # Standardized FAPI/OAuth error fields that are safe to surface in error
      # messages — non-PII, useful for debugging, and explicitly named by the
      # OAuth 2.0 / FAPI 2.0 / Singpass specs. Any other field in the response
      # body is dropped: Singpass error payloads can carry NRIC / email / other
      # PII alongside the OAuth fields, and we'd rather lose diagnostic detail
      # than leak PII into log streams.
      SAFE_ERROR_FIELDS = T.let(%w[error error_description trace_id id state].freeze, T::Array[String])

      # Single-line excerpt of a Faraday response body for inclusion in error
      # messages. Parses JSON when possible and emits only the SAFE_ERROR_FIELDS
      # values; falls back to a fixed-marker for non-JSON or unrecognised shape.
      # Never returns arbitrary body content — that would risk leaking PII.
      sig { params(response: Faraday::Response).returns(String) }
      def body_excerpt(response)
        body = response.body.to_s
        return "(empty body)" if body.empty?

        parsed = begin
          JSON.parse(body)
        rescue JSON::ParserError
          nil
        end

        if parsed.is_a?(Hash)
          parts = SAFE_ERROR_FIELDS.filter_map do |field|
            value = parsed[field]
            next if value.nil? || value.to_s.empty?
            "#{field}=#{value.inspect}"
          end
          return parts.empty? ? "(non-standard error body — no error/error_description fields)" : parts.join(" ")
        end

        "(non-JSON body, #{body.bytesize} bytes)"
      end

      sig { params(jwe_body: String, jwks_url: T.nilable(String)).returns(T::Hash[String, T.untyped]) }
      def decrypt_and_validate_person(jwe_body, jwks_url:)
        decrypted = Security.decrypt_jwe(jwe_body, private_keys: @encryption_keys)
        Security.validate_jws(decrypted, jwks_url: T.must(jwks_url))
      rescue Security::DecryptionError => e
        raise DecryptionError, e.message
      rescue Security::ValidationError => e
        raise SignatureError, e.message
      end

      sig { void }
      def validate_config!
        missing = REQUIRED_CONFIG.select { |key| instance_variable_get(:"@#{key}").blank? }
        raise ArgumentError, "Missing MyInfo config: #{missing.join(', ')}" if missing.any?
      end

      sig { returns(Faraday::Connection) }
      def http_connection
        @http_connection ||= Faraday.new do |f|
          f.options.open_timeout = 10
          f.options.timeout = 15
        end
      end

      # Wraps the given block in the configured network_wrapper. Default is
      # the identity wrapper (no resilience). Hosts typically set this to a
      # circuit-breaker lambda. Scoped narrowly to the Faraday network call
      # so that downstream JWE/JWS processing errors (DecryptionError,
      # SignatureError) propagate untouched — they indicate key/cert
      # misconfiguration, not an upstream outage, and should not trip a
      # circuit breaker.
      sig { params(block: T.proc.returns(T.untyped)).returns(T.untyped) }
      def with_network_wrapper(&block)
        @network_wrapper.call(&block)
      end
    end
  end
end
