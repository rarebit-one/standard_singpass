# typed: strict

module StandardSingpass
  module Myinfo
    class Security
      extend T::Sig

      class DecryptionError < StandardError; end
      class ValidationError < StandardError; end

      JWKS_CACHE_TTL = T.let(1.hour, ActiveSupport::Duration)

      # Generates a PKCE code verifier and code challenge pair (S256).
      sig { returns({ code_verifier: String, code_challenge: String }) }
      def self.generate_pkce_pair
        code_verifier = SecureRandom.urlsafe_base64(48)
        code_challenge = Base64.urlsafe_encode64(
          Digest::SHA256.digest(code_verifier), padding: false
        )
        { code_verifier:, code_challenge: }
      end

      # Generates an ephemeral EC key pair (ES256 / prime256v1) for DPoP.
      sig { returns(OpenSSL::PKey::EC) }
      def self.generate_ephemeral_key_pair
        OpenSSL::PKey::EC.generate("prime256v1")
      end

      # Builds a DPoP proof JWT per RFC 9449.
      sig { params(http_method: String, url: String, key_pair: OpenSSL::PKey::EC, access_token: T.nilable(String)).returns(String) }
      def self.build_dpop_proof(http_method:, url:, key_pair:, access_token: nil)
        jwk = JWT::JWK.new(key_pair)

        header = {
          typ: "dpop+jwt",
          alg: "ES256",
          jwk: jwk.export(include_private: false)
        }

        htu = URI(url).tap { |u| u.query = nil; u.fragment = nil }.to_s

        claims = {
          htm: http_method.upcase,
          htu:,
          iat: Time.current.to_i,
          exp: (Time.current + 2.minutes).to_i,
          jti: SecureRandom.uuid
        }

        if access_token
          ath = Base64.urlsafe_encode64(
            Digest::SHA256.digest(access_token), padding: false
          )
          claims[:ath] = ath
        end

        JWT.encode(claims, key_pair, "ES256", header)
      end

      # Builds a private_key_jwt client assertion for the token endpoint.
      sig { params(client_id: String, audience: String, signing_key: T.any(String, OpenSSL::PKey::PKey), signing_kid: String, code: T.nilable(String)).returns(String) }
      def self.build_client_assertion(client_id:, audience:, signing_key:, signing_kid:, code: nil)
        key = signing_key.is_a?(OpenSSL::PKey::PKey) ? signing_key : OpenSSL::PKey.read(signing_key)

        header = {
          alg: "ES256",
          kid: signing_kid,
          typ: "JWT"
        }

        claims = {
          iss: client_id,
          sub: client_id,
          aud: audience,
          iat: Time.current.to_i,
          exp: (Time.current + 2.minutes).to_i,
          jti: SecureRandom.uuid
        }
        claims[:code] = code if code.present?

        JWT.encode(claims, key, "ES256", header)
      end

      # Decrypts a JWE string using the matching private key (by kid). FAPI 2.0
      # mandates EC P-256 with ECDH-ES+A256KW; RSA-OAEP (the v4 path) is no
      # longer supported by Singpass and we no longer accept it on our side.
      sig { params(jwe_string: String, private_keys: T::Array[T::Hash[Symbol, T.untyped]]).returns(String) }
      def self.decrypt_jwe(jwe_string, private_keys:)
        header_kid = extract_jwe_kid(jwe_string)
        raise DecryptionError, "JWE header missing kid field" unless header_kid

        matching_key = private_keys.find { |k| k[:kid] == header_kid }
        raise DecryptionError, "No matching decryption key found" unless matching_key

        alg = extract_jwe_alg(jwe_string)
        unless EcdhJwe::SUPPORTED_ALGS.include?(alg)
          raise DecryptionError, "Unsupported JWE alg #{alg.inspect}; FAPI 2.0 requires #{EcdhJwe::SUPPORTED_ALGS.join('/')}"
        end

        EcdhJwe.decrypt(jwe_string, private_key: resolve_key(matching_key[:key]))
      rescue EcdhJwe::DecryptionFailed => e
        raise DecryptionError, "JWE decryption failed: #{e.message}"
      rescue ArgumentError => e
        raise DecryptionError, "Malformed JWE: #{e.message}"
      end

      # Validates a JWS string against keys from a JWKS endpoint.
      # Performs signature verification only — callers must validate claims (aud, iss, nbf, etc.).
      sig { params(jws_string: String, jwks_url: String).returns(T::Hash[String, T.untyped]) }
      def self.validate_jws(jws_string, jwks_url:)
        jwks_data = fetch_jwks(jwks_url)
        begin
          decode_with_jwks(jws_string, jwks_data)
        rescue JWT::VerificationError
          # Retry once with a fresh JWKS fetch in case of key rotation
          jwks_data = fetch_jwks(jwks_url, force_refresh: true)
          begin
            decode_with_jwks(jws_string, jwks_data)
          rescue JWT::DecodeError => e
            raise ValidationError, "JWS validation failed: #{e.message}"
          end
        rescue JWT::DecodeError => e
          raise ValidationError, "JWS validation failed: #{e.message}"
        end
      end

      sig { params(jws_string: String, jwks_data: T::Hash[String, T.untyped]).returns(T::Hash[String, T.untyped]) }
      private_class_method def self.decode_with_jwks(jws_string, jwks_data)
        jwks = JWT::JWK::Set.new(jwks_data)
        decoded = JWT.decode(jws_string, nil, true, algorithms: ALLOWED_ALGORITHMS, jwks:)
        decoded.first
      end

      sig { params(jwe_string: String).returns(T::Hash[String, T.untyped]) }
      def self.extract_jwe_header(jwe_string)
        header_segment = jwe_string.split(".").first
        return {} unless header_segment.present?
        padded = header_segment + "=" * ((4 - header_segment.length % 4) % 4)
        JSON.parse(Base64.urlsafe_decode64(padded))
      end
      private_class_method :extract_jwe_header

      sig { params(jwe_string: String).returns(T.nilable(String)) }
      def self.extract_jwe_kid(jwe_string)
        extract_jwe_header(jwe_string)["kid"]
      end
      private_class_method :extract_jwe_kid

      sig { params(jwe_string: String).returns(T.nilable(String)) }
      def self.extract_jwe_alg(jwe_string)
        extract_jwe_header(jwe_string)["alg"]
      end
      private_class_method :extract_jwe_alg

      sig { params(key: T.untyped).returns(T.untyped) }
      def self.resolve_key(key)
        case key
        when OpenSSL::PKey::PKey then key
        when String then OpenSSL::PKey.read(key)
        else raise DecryptionError, "Unsupported key type: #{key.class}"
        end
      end
      private_class_method :resolve_key

      sig { params(url: String, force_refresh: T::Boolean).returns(T::Hash[String, T.untyped]) }
      def self.fetch_jwks(url, force_refresh: false)
        cache_key = "standard_singpass:myinfo:jwks:#{Digest::SHA256.hexdigest(url)}"

        Rails.cache.delete(cache_key) if force_refresh

        Rails.cache.fetch(cache_key, expires_in: JWKS_CACHE_TTL) do
          response = Faraday.get(url) { |req| req.options.timeout = 5; req.options.open_timeout = 3 }
          raise ValidationError, "Failed to fetch JWKS: HTTP #{response.status}" unless response.success?

          JSON.parse(response.body)
        end
      rescue Faraday::Error, JSON::ParserError => e
        raise ValidationError, "Failed to fetch JWKS: #{e.message}"
      end
      private_class_method :fetch_jwks

      # FAPI 2.0 mandates ES256 for all JWS signatures.
      ALLOWED_ALGORITHMS = T.let(%w[ES256].freeze, T::Array[String])
    end
  end
end
