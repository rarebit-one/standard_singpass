# typed: strict

module StandardSingpass
  module Myinfo
    # Generates and validates the private JWKS document that gets pasted into
    # the host application's `MYINFO_PRIVATE_JWKS` env var (or equivalent).
    # Public-facing entrypoint is the `standard_singpass:myinfo:generate_jwks`
    # rake task; this module holds the logic so it's testable without going
    # through Rake.
    #
    # The validator mirrors what `Configuration#private_jwks_json=` requires —
    # particularly the "must have private scalar `d`" check that traps the
    # public/private key mix-up.
    module JwksGenerator
      extend T::Sig

      SIG_ALG = T.let("ES256", String)
      ENC_ALG = T.let("ECDH-ES+A256KW", String)
      EC_CURVE = T.let("P-256", String)
      EC_OPENSSL_NAME = T.let("prime256v1", String)

      sig { params(sig_kid: String, enc_kid: String).returns(T::Hash[Symbol, T.untyped]) }
      def self.generate(sig_kid:, enc_kid:)
        sig_jwk = build_jwk(OpenSSL::PKey::EC.generate(EC_OPENSSL_NAME), kid: sig_kid, use: "sig", alg: SIG_ALG)
        enc_jwk = build_jwk(OpenSSL::PKey::EC.generate(EC_OPENSSL_NAME), kid: enc_kid, use: "enc", alg: ENC_ALG)

        jwks = { keys: [ sig_jwk, enc_jwk ] }

        # Defensive — the trap this module is built to prevent. If we ever
        # emit a public-only JWK from a generation path, refuse early.
        issues = validate(jwks)
        raise "Internal: generated JWKS failed self-validation:\n#{issues.join("\n")}" if issues.any?

        jwks
      end

      # Returns an array of issue strings; empty array means valid.
      # Accepts either symbol- or string-keyed hashes (JSON.parse output is
      # string-keyed; in-memory values from .generate are symbol-keyed).
      sig { params(jwks: T.untyped).returns(T::Array[String]) }
      def self.validate(jwks)
        return [ "root is not a JSON object (got #{jwks.class})" ] unless jwks.is_a?(Hash)

        keys = jwks["keys"] || jwks[:keys]
        return [ "missing 'keys' array" ] unless keys.is_a?(Array)

        issues = []

        sig_keys = keys.select { |k| k.is_a?(Hash) && key_field(k, :use) == "sig" }
        enc_keys = keys.select { |k| k.is_a?(Hash) && key_field(k, :use) == "enc" }

        issues << "expected exactly one sig key (use=\"sig\"), got #{sig_keys.size}" unless sig_keys.size == 1
        issues << "expected at least one enc key (use=\"enc\"), got 0" if enc_keys.empty?

        # RFC 7517 §4.5: kid values within a JWKS should be distinct so a
        # consumer can pick keys unambiguously. The runtime config loader
        # selects by `use`, so a duplicate kid wouldn't blow up at boot —
        # but Singpass may behave differently, and a duplicate is almost
        # always an operator copy/paste mistake.
        hashlike_keys = keys.grep(Hash)
        kid_counts = hashlike_keys.group_by { |k| key_field(k, :kid) }.transform_values(&:size)
        kid_counts.each do |kid, count|
          next if count <= 1
          issues << "duplicate kid #{kid.inspect} appears #{count} times — kids must be unique within a JWKS (RFC 7517 §4.5)"
        end

        keys.each_with_index do |k, i|
          unless k.is_a?(Hash)
            issues << "keys[#{i}] is not an object (got #{k.class})"
            next
          end
          kid = key_field(k, :kid)
          use = key_field(k, :use)
          label = "keys[#{i}] kid=#{kid.inspect} use=#{use.inspect}"

          d = key_field(k, :d)
          kty = key_field(k, :kty)
          crv = key_field(k, :crv)
          alg = key_field(k, :alg)

          # Public-only-key trap. Without `d` the JWK is public-only and
          # cannot sign or decrypt — every Singpass call fails at runtime.
          # `.blank?` matches the runtime config loader's check so the
          # validator and the loader accept the same set of inputs.
          issues << "#{label}: missing 'd' (public-only — re-export with include_private: true)" if d.blank?
          issues << "#{label}: kty=#{kty.inspect} expected \"EC\"" unless kty == "EC"
          issues << "#{label}: crv=#{crv.inspect} expected \"P-256\" (FAPI 2.0 requires EC P-256)" unless crv == EC_CURVE

          case use
          when "sig"
            issues << "#{label}: alg=#{alg.inspect} expected \"#{SIG_ALG}\"" unless alg == SIG_ALG
          when "enc"
            issues << "#{label}: alg=#{alg.inspect} expected \"#{ENC_ALG}\"" unless alg == ENC_ALG
          else
            issues << "#{label}: use=#{use.inspect} expected \"sig\" or \"enc\""
          end
        end

        issues
      end

      sig { params(key: OpenSSL::PKey::EC, kid: String, use: String, alg: String).returns(T::Hash[Symbol, T.untyped]) }
      private_class_method def self.build_jwk(key, kid:, use:, alg:)
        jwk = JWT::JWK.new(key, kid:).export(include_private: true)
        jwk[:use] = use
        jwk[:alg] = alg
        jwk
      end

      sig { params(hash: T::Hash[T.untyped, T.untyped], field: Symbol).returns(T.untyped) }
      private_class_method def self.key_field(hash, field)
        hash[field] || hash[field.to_s]
      end
    end
  end
end
