require "sorbet-runtime"
require "active_support/all"
require "faraday"
require "jwt"
require "openssl"
require "json"
require "base64"
require "digest"
require "securerandom"
require "aes_key_wrap"

require "standard_singpass/myinfo/error"
require "standard_singpass/myinfo/configuration"
require "standard_singpass/myinfo/ecdh_jwe"
require "standard_singpass/myinfo/security"
require "standard_singpass/myinfo/client"
require "standard_singpass/myinfo/person_data_parser"
require "standard_singpass/myinfo/jwks_generator"
require "standard_singpass/myinfo/test_personas"

module StandardSingpass
  module Myinfo
    class << self
      def configure
        yield(configuration) if block_given?
        @public_jwks = nil
      end

      def configuration
        @configuration ||= Configuration.new
      end

      def reset_configuration!
        @configuration = Configuration.new
        @public_jwks = nil
      end

      def public_jwks
        @public_jwks ||= build_public_jwks
      end

      private

      def build_public_jwks
        keys = []
        c = configuration

        if c.signing_key.present? && c.signing_kid.present?
          begin
            key = OpenSSL::PKey.read(c.signing_key)
            jwk = JWT::JWK.new(key, kid: c.signing_kid)
            exported = jwk.export(include_private: false)
            exported[:use] = "sig"
            exported[:alg] = "ES256"
            keys << exported
          rescue OpenSSL::PKey::PKeyError => e
            Rails.logger.error("StandardSingpass::Myinfo: failed to load signing key: #{e.message}")
            Rails.error.report(e, handled: true, context: { component: "StandardSingpass::Myinfo", reason: "build_public_jwks_signing", kid: c.signing_kid })
          end
        end

        Array(c.encryption_keys).each do |enc_key_config|
          key = OpenSSL::PKey.read(enc_key_config[:key])
          jwk = JWT::JWK.new(key, kid: enc_key_config[:kid])
          exported = jwk.export(include_private: false)
          exported[:use] = "enc"
          exported[:alg] = "ECDH-ES+A256KW"
          keys << exported
        rescue OpenSSL::PKey::PKeyError => e
          Rails.logger.error("StandardSingpass::Myinfo: failed to load encryption key #{enc_key_config[:kid]}: #{e.message}")
          Rails.error.report(e, handled: true, context: { component: "StandardSingpass::Myinfo", reason: "build_public_jwks_encryption", kid: enc_key_config[:kid] })
        end

        { keys: }
      end
    end
  end
end
