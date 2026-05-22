# typed: strict

module StandardSingpass
  module Myinfo
    # Native ECDH-ES+A256KW JWE implementation for decryption.
    #
    # The `jwt` gem does not support ECDH-ES key agreement algorithms; this
    # service implements the subset needed for MyInfo (FAPI 2.0):
    #   alg: ECDH-ES+A256KW
    #   enc: A128CBC-HS256, A256CBC-HS512, A128GCM, A256GCM
    #
    # References:
    #   - RFC 7516 (JWE)
    #   - RFC 7518 Section 4.6 (ECDH-ES key agreement)
    #   - NIST SP 800-56A Concat KDF
    class EcdhJwe
      extend T::Sig

      class DecryptionFailed < StandardError; end
      class InvalidAlgorithm < StandardError; end

      SUPPORTED_ALGS = T.let(%w[ECDH-ES+A128KW ECDH-ES+A256KW].freeze, T::Array[String])
      SUPPORTED_ENCS = T.let(%w[A128CBC-HS256 A256CBC-HS512 A128GCM A256GCM].freeze, T::Array[String])

      # Key wrap key sizes (in bytes) for each alg
      KEK_SIZES = T.let({
        "ECDH-ES+A128KW" => 16,
        "ECDH-ES+A256KW" => 32
      }.freeze, T::Hash[String, Integer])

      # CEK sizes (in bytes) for each enc
      CEK_SIZES = T.let({
        "A128CBC-HS256" => 32,
        "A256CBC-HS512" => 64,
        "A128GCM" => 16,
        "A256GCM" => 32
      }.freeze, T::Hash[String, Integer])

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
        validate_algorithms!(alg, enc)

        # Generate ephemeral key pair on same curve
        group = public_key.group
        ephemeral_key = OpenSSL::PKey::EC.generate(group.curve_name)

        # ECDH key agreement
        shared_secret = derive_shared_secret(ephemeral_key, public_key)

        # Derive KEK via Concat KDF
        kek_size = KEK_SIZES.fetch(alg)
        kek = concat_kdf(shared_secret, alg, kek_size, apu:, apv:)

        # Generate random CEK
        cek_size = CEK_SIZES.fetch(enc)
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

      # Decrypts a compact-serialized JWE string.
      sig { params(jwe_string: String, private_key: OpenSSL::PKey::EC).returns(String) }
      def self.decrypt(jwe_string, private_key:)
        parts = jwe_string.split(".")
        raise DecryptionFailed, "Invalid JWE format" unless parts.length == 5

        header_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64 = parts

        header = JSON.parse(Base64.urlsafe_decode64(T.must(header_b64)))
        alg = header["alg"]
        enc = header["enc"]

        validate_algorithms!(alg, enc)

        epk = header["epk"]
        raise DecryptionFailed, "Missing ephemeral public key (epk)" unless epk

        # Decode apu/apv from header if present
        apu = header["apu"] ? Base64.urlsafe_decode64(header["apu"]) : nil
        apv = header["apv"] ? Base64.urlsafe_decode64(header["apv"]) : nil

        # Reconstruct ephemeral public key
        ephemeral_public_key = jwk_to_ec_public_key(epk)

        # ECDH key agreement
        shared_secret = derive_shared_secret(private_key, ephemeral_public_key)

        # Derive KEK via Concat KDF
        kek_size = KEK_SIZES.fetch(alg)
        kek = concat_kdf(shared_secret, alg, kek_size, apu:, apv:)

        # Unwrap CEK
        encrypted_key = Base64.urlsafe_decode64(T.must(encrypted_key_b64))
        cek = AESKeyWrap.unwrap(encrypted_key, kek)
        raise DecryptionFailed, "Key unwrap failed" unless cek

        # Decrypt content
        iv = Base64.urlsafe_decode64(T.must(iv_b64))
        ciphertext = Base64.urlsafe_decode64(T.must(ciphertext_b64))
        auth_tag = Base64.urlsafe_decode64(T.must(tag_b64))

        decrypt_content(cek, enc, ciphertext, iv, auth_tag, T.must(header_b64))
      rescue JSON::ParserError, ArgumentError => e
        raise DecryptionFailed, "Malformed JWE: #{e.message}"
      rescue OpenSSL::OpenSSLError => e
        raise DecryptionFailed, "Decryption failed: #{e.message}"
      end

      class << self
        extend T::Sig

        private

        sig { params(alg: T.untyped, enc: T.untyped).void }
        def validate_algorithms!(alg, enc)
          raise InvalidAlgorithm, "Unsupported alg: #{alg}" unless SUPPORTED_ALGS.include?(alg)
          raise InvalidAlgorithm, "Unsupported enc: #{enc}" unless SUPPORTED_ENCS.include?(enc)
        end

        # Performs ECDH key agreement and returns the raw shared secret.
        sig { params(local_key: OpenSSL::PKey::EC, remote_public_key: OpenSSL::PKey::EC).returns(String) }
        def derive_shared_secret(local_key, remote_public_key)
          local_key.dh_compute_key(remote_public_key.public_key)
        end

        # NIST Concat KDF (single-pass, SHA-256) per RFC 7518 Section 4.6.2
        sig { params(shared_secret: String, algorithm: String, key_length: Integer, apu: T.nilable(String), apv: T.nilable(String)).returns(String) }
        def concat_kdf(shared_secret, algorithm, key_length, apu: nil, apv: nil)
          algorithm_id = [ algorithm.bytesize ].pack("N") + algorithm
          party_u_info = apu ? [ apu.bytesize ].pack("N") + apu : [ 0 ].pack("N")
          party_v_info = apv ? [ apv.bytesize ].pack("N") + apv : [ 0 ].pack("N")
          supp_pub_info = [ key_length * 8 ].pack("N")

          other_info = algorithm_id + party_u_info + party_v_info + supp_pub_info

          # Single round (SHA-256 output is 32 bytes, enough for up to 256-bit keys)
          round_input = [ 1 ].pack("N") + shared_secret + other_info
          digest = OpenSSL::Digest::SHA256.digest(round_input)
          digest[0, key_length]
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

        # Reconstructs an EC public key from a JWK hash.
        sig { params(jwk: T::Hash[String, T.untyped]).returns(OpenSSL::PKey::EC) }
        def jwk_to_ec_public_key(jwk)
          crv = jwk["crv"]
          curve_name = case crv
          when "P-256" then "prime256v1"
          when "P-384" then "secp384r1"
          when "P-521" then "secp521r1"
          else raise InvalidAlgorithm, "Unsupported curve: #{crv}"
          end

          x = Base64.urlsafe_decode64(jwk["x"])
          y = Base64.urlsafe_decode64(jwk["y"])

          group = OpenSSL::PKey::EC::Group.new(curve_name)
          # Build uncompressed point: 0x04 || x || y
          point_hex = "04" + x.unpack1("H*") + y.unpack1("H*")
          point = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(point_hex, 16))

          # Build a public-only EC key
          inner = [ OpenSSL::ASN1::ObjectId.new("id-ecPublicKey"),
                    OpenSSL::ASN1::ObjectId.new(curve_name) ]
          outer = [ OpenSSL::ASN1::Sequence.new(inner),
                    OpenSSL::ASN1::BitString.new(point.to_octet_string(:uncompressed)) ]
          asn1 = OpenSSL::ASN1::Sequence.new(outer)
          OpenSSL::PKey::EC.new(asn1.to_der)
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

        sig { params(cek: String, enc: String, ciphertext: String, iv: String, auth_tag: String, aad: String).returns(String) }
        def decrypt_content(cek, enc, ciphertext, iv, auth_tag, aad)
          case enc
          when "A128GCM", "A256GCM"
            decrypt_gcm(cek, ciphertext, iv, auth_tag, aad, enc)
          when "A128CBC-HS256", "A256CBC-HS512"
            decrypt_cbc(cek, ciphertext, iv, auth_tag, aad, enc)
          else
            raise InvalidAlgorithm, "Unsupported enc: #{enc}"
          end
        end

        sig { params(enc: String).returns(String) }
        def gcm_cipher_name(enc)
          enc == "A128GCM" ? "aes-128-gcm" : "aes-256-gcm"
        end

        sig { params(enc: String).returns(String) }
        def cbc_cipher_name(enc)
          enc == "A128CBC-HS256" ? "aes-128-cbc" : "aes-256-cbc"
        end

        sig { params(enc: String).returns(String) }
        def cbc_hmac_digest(enc)
          enc == "A128CBC-HS256" ? "SHA256" : "SHA512"
        end

        sig { params(cek: String, plaintext: String, aad: String, enc: String).returns(T::Array[String]) }
        def encrypt_gcm(cek, plaintext, aad, enc)
          cipher = OpenSSL::Cipher.new(gcm_cipher_name(enc))
          cipher.encrypt
          cipher.key = cek
          iv = cipher.random_iv
          cipher.auth_data = aad
          ciphertext = cipher.update(plaintext) + cipher.final
          auth_tag = cipher.auth_tag
          [ iv, ciphertext, auth_tag ]
        end

        sig { params(cek: String, ciphertext: String, iv: String, auth_tag: String, aad: String, enc: String).returns(String) }
        def decrypt_gcm(cek, ciphertext, iv, auth_tag, aad, enc)
          raise DecryptionFailed, "Invalid authentication tag" if auth_tag.bytesize < 16

          cipher = OpenSSL::Cipher.new(gcm_cipher_name(enc))
          cipher.decrypt
          cipher.key = cek
          cipher.iv = iv
          cipher.auth_tag = auth_tag
          cipher.auth_data = aad
          cipher.update(ciphertext) + cipher.final
        rescue OpenSSL::Cipher::CipherError
          raise DecryptionFailed, "Content decryption failed"
        end

        sig { params(cek: String, plaintext: String, aad: String, enc: String).returns(T::Array[String]) }
        def encrypt_cbc(cek, plaintext, aad, enc)
          mac_key_len = cek.bytesize / 2
          mac_key = cek[0, mac_key_len]
          enc_key = cek[mac_key_len, mac_key_len]

          cipher = OpenSSL::Cipher.new(cbc_cipher_name(enc))
          cipher.encrypt
          cipher.key = T.must(enc_key)
          iv = cipher.random_iv
          ciphertext = cipher.update(plaintext) + cipher.final

          # Compute authentication tag (HMAC over AAD || IV || ciphertext || AL)
          al = [ aad.bytesize * 8 ].pack("Q>")
          hmac_input = aad + iv + ciphertext + al
          hmac = OpenSSL::HMAC.digest(cbc_hmac_digest(enc), T.must(mac_key), hmac_input)
          tag_len = mac_key_len  # half of HMAC output
          auth_tag = hmac[0, tag_len]

          [ iv, ciphertext, auth_tag ]
        end

        sig { params(cek: String, ciphertext: String, iv: String, auth_tag: String, aad: String, enc: String).returns(String) }
        def decrypt_cbc(cek, ciphertext, iv, auth_tag, aad, enc)
          mac_key_len = cek.bytesize / 2
          mac_key = cek[0, mac_key_len]
          enc_key = cek[mac_key_len, mac_key_len]

          # Verify authentication tag
          al = [ aad.bytesize * 8 ].pack("Q>")
          hmac_input = aad + iv + ciphertext + al
          hmac = OpenSSL::HMAC.digest(cbc_hmac_digest(enc), T.must(mac_key), hmac_input)
          tag_len = mac_key_len
          expected_tag = hmac[0, tag_len]

          unless OpenSSL.fixed_length_secure_compare(auth_tag, expected_tag)
            raise DecryptionFailed, "Authentication tag verification failed"
          end

          cipher = OpenSSL::Cipher.new(cbc_cipher_name(enc))
          cipher.decrypt
          cipher.key = T.must(enc_key)
          cipher.iv = iv
          cipher.update(ciphertext) + cipher.final
        rescue OpenSSL::Cipher::CipherError
          raise DecryptionFailed, "Content decryption failed"
        end
      end
    end
  end
end
