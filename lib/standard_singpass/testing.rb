# typed: strict

require "standard_singpass"

module StandardSingpass
  # Test-only helpers. Not loaded by `require "standard_singpass"`; require
  # this file from a spec helper:
  #
  #   require "standard_singpass/testing"
  #
  # Nothing here is needed at runtime — Singpass encrypts, the gem decrypts.
  module Testing
    # ECDH-ES JWE *encryption*, the mirror of
    # `StandardSingpass::Myinfo::EcdhJwe.decrypt`. Use it to build the
    # encrypted id_token / userinfo payloads Singpass would return, so specs
    # can exercise the real decrypt + verify path end to end.
    #
    # Accepts exactly the algorithms the decryptor does
    # (`Myinfo::EcdhJwe::SUPPORTED_ALGS` / `SUPPORTED_ENCS`), and shares its
    # key-agreement and KDF code, so a fixture that encrypts here decrypts
    # there by construction.
    class EcdhJwe
      extend T::Sig

      Impl = StandardSingpass::Myinfo::EcdhJwe
      InvalidAlgorithm = StandardSingpass::Myinfo::EcdhJwe::InvalidAlgorithm

      # Encrypts a payload and returns a compact-serialized JWE string.
      sig do
        params(
          payload: String,
          public_key: OpenSSL::PKey::EC,
          alg: String,
          enc: String,
          kid: T.nilable(String),
          apu: T.nilable(String),
          apv: T.nilable(String)
        ).returns(String)
      end
      def self.encrypt(payload, public_key:, alg:, enc:, kid: nil, apu: nil, apv: nil)
        shared(:validate_algorithms!, alg, enc)

        # Generate ephemeral key pair on same curve
        group = public_key.group
        ephemeral_key = OpenSSL::PKey::EC.generate(group.curve_name)

        # ECDH key agreement
        shared_secret = shared(:derive_shared_secret, ephemeral_key, public_key)

        # Derive KEK via Concat KDF
        kek_size = Impl::KEK_SIZES.fetch(alg)
        kek = shared(:concat_kdf, shared_secret, alg, kek_size, apu:, apv:)

        # Generate random CEK
        cek_size = Impl::CEK_SIZES.fetch(enc)
        cek = SecureRandom.random_bytes(cek_size)

        # Wrap CEK with KEK
        encrypted_key = AESKeyWrap.wrap(cek, kek)

        # Build header
        epk_jwk = ec_public_key_to_jwk(ephemeral_key)
        header = { "alg" => alg, "enc" => enc, "epk" => epk_jwk }
        header["kid"] = kid if kid
        header["apu"] = Base64.urlsafe_encode64(apu, padding: false) if apu
        header["apv"] = Base64.urlsafe_encode64(apv, padding: false) if apv

        # Encrypt content
        header_b64 = Base64.urlsafe_encode64(header.to_json, padding: false)
        iv, ciphertext, auth_tag = encrypt_content(cek, enc, payload, header_b64)

        # Assemble compact serialization
        [
          header_b64,
          Base64.urlsafe_encode64(encrypted_key, padding: false),
          Base64.urlsafe_encode64(T.must(iv), padding: false),
          Base64.urlsafe_encode64(T.must(ciphertext), padding: false),
          Base64.urlsafe_encode64(T.must(auth_tag), padding: false)
        ].join(".")
      end

      class << self
        extend T::Sig

        private

        # The decryptor's key-agreement / KDF / validation helpers are private
        # class methods; reuse them rather than keeping a second copy.
        sig { params(name: Symbol, args: T.untyped, kwargs: T.untyped).returns(T.untyped) }
        def shared(name, *args, **kwargs)
          T.unsafe(Impl).send(name, *args, **kwargs)
        end

        # Converts an OpenSSL EC key to a JWK hash (public components only).
        sig { params(ec_key: OpenSSL::PKey::EC).returns(T::Hash[String, String]) }
        def ec_public_key_to_jwk(ec_key)
          # Get the public key point
          point = ec_key.public_key
          group = ec_key.group

          # Determine curve name for JWK
          crv = case group.curve_name
          when "prime256v1" then "P-256"
          when "secp384r1" then "P-384"
          when "secp521r1" then "P-521"
          else raise InvalidAlgorithm, "Unsupported curve: #{group.curve_name}"
          end

          # Get uncompressed point bytes (0x04 || x || y)
          bn = point.to_bn(:uncompressed)
          uncompressed = bn.to_s(2)

          # Skip the 0x04 prefix byte
          coord_length = (uncompressed.bytesize - 1) / 2
          x = uncompressed[1, coord_length]
          y = uncompressed[1 + coord_length, coord_length]

          {
            "kty" => "EC",
            "crv" => crv,
            "x" => Base64.urlsafe_encode64(x, padding: false),
            "y" => Base64.urlsafe_encode64(y, padding: false)
          }
        end

        sig { params(cek: String, enc: String, plaintext: String, aad: String).returns(T::Array[String]) }
        def encrypt_content(cek, enc, plaintext, aad)
          case enc
          when "A128GCM", "A256GCM"
            encrypt_gcm(cek, plaintext, aad, enc)
          when "A128CBC-HS256", "A256CBC-HS512"
            encrypt_cbc(cek, plaintext, aad, enc)
          else
            raise InvalidAlgorithm, "Unsupported enc: #{enc}"
          end
        end

        sig { params(cek: String, plaintext: String, aad: String, enc: String).returns(T::Array[String]) }
        def encrypt_gcm(cek, plaintext, aad, enc)
          cipher = OpenSSL::Cipher.new(shared(:gcm_cipher_name, enc))
          cipher.encrypt
          cipher.key = cek
          iv = cipher.random_iv
          cipher.auth_data = aad
          ciphertext = cipher.update(plaintext) + cipher.final
          auth_tag = cipher.auth_tag
          [iv, ciphertext, auth_tag]
        end

        sig { params(cek: String, plaintext: String, aad: String, enc: String).returns(T::Array[String]) }
        def encrypt_cbc(cek, plaintext, aad, enc)
          mac_key_len = cek.bytesize / 2
          mac_key = cek[0, mac_key_len]
          enc_key = cek[mac_key_len, mac_key_len]

          cipher = OpenSSL::Cipher.new(shared(:cbc_cipher_name, enc))
          cipher.encrypt
          cipher.key = T.must(enc_key)
          iv = cipher.random_iv
          ciphertext = cipher.update(plaintext) + cipher.final

          # Compute authentication tag (HMAC over AAD || IV || ciphertext || AL)
          al = [aad.bytesize * 8].pack("Q>")
          hmac_input = aad + iv + ciphertext + al
          hmac = OpenSSL::HMAC.digest(shared(:cbc_hmac_digest, enc), T.must(mac_key), hmac_input)
          tag_len = mac_key_len  # half of HMAC output
          auth_tag = hmac[0, tag_len]

          [iv, ciphertext, auth_tag]
        end
      end
    end
  end
end
