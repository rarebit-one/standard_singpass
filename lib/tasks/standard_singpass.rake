# typed: false

# Singpass MyInfo operational tasks.
#
# These run on a trusted local machine — never CI, never a shared shell.
# The output of `generate_jwks` contains private key material.
#
#   bin/rails standard_singpass:myinfo:generate_jwks
#   bin/rails 'standard_singpass:myinfo:generate_jwks[my-sig-2,my-enc-2]'
#   bin/rails 'standard_singpass:myinfo:validate_jwks[path/to/private-jwks.json]'
#   cat private-jwks.json | bin/rails standard_singpass:myinfo:validate_jwks

namespace :standard_singpass do
  namespace :myinfo do
    desc "Generate a fresh MyInfo private JWKS (sig + enc, EC P-256). JSON to stdout, narrative to stderr."
    task :generate_jwks, [ :sig_kid, :enc_kid ] => :environment do |_, args|
      sig_kid = args[:sig_kid].presence || "singpass-sig-#{Date.current.strftime('%Y%m%d')}"
      enc_kid = args[:enc_kid].presence || "singpass-enc-#{Date.current.strftime('%Y%m%d')}"

      jwks = StandardSingpass::Myinfo::JwksGenerator.generate(sig_kid:, enc_kid:)

      # Narrative on stderr so `> private-jwks.json` captures clean JSON.
      warn ""
      warn "Generated MYINFO private JWKS:"
      jwks[:keys].each do |k|
        warn "  kid=#{k[:kid]}  use=#{k[:use]}  alg=#{k[:alg]}  crv=#{k[:crv]}  has_d=true"
      end
      warn ""
      warn "Next steps:"
      warn "  1. Store the JSON below in your secret manager (e.g. 1Password)."
      warn "  2. Paste into the env var your host uses to populate"
      warn "     StandardSingpass::Myinfo.configure { |c| c.private_jwks_json = ... }"
      warn "     (mark as Secret/Encrypted; do not shell-escape, paste raw)."
      warn "  3. After redeploy, confirm your public JWKS endpoint shows the same"
      warn "     kids with NO 'd' field."
      warn ""

      puts JSON.generate(jwks)
    end

    desc "Validate a MyInfo private JWKS payload. Catches the public-only-key trap before paste."
    task :validate_jwks, [ :path ] => :environment do |_, args|
      raw = if args[:path].present?
        File.read(args[:path])
      elsif !$stdin.tty?
        $stdin.read
      else
        abort "Provide a path or pipe JSON:\n" \
              "  bin/rails 'standard_singpass:myinfo:validate_jwks[path/to/jwks.json]'\n" \
              "  cat private-jwks.json | bin/rails standard_singpass:myinfo:validate_jwks"
      end

      begin
        jwks = JSON.parse(raw)
      rescue JSON::ParserError => e
        abort "Not valid JSON: #{e.message}"
      end

      issues = StandardSingpass::Myinfo::JwksGenerator.validate(jwks)

      if issues.empty?
        key_count = (jwks["keys"] || []).size
        warn "OK — JWKS validates: #{key_count} keys, all private (have 'd'), all EC P-256, alg matches use."
      else
        warn "JWKS validation FAILED — #{issues.size} issue(s):"
        issues.each { |i| warn "  - #{i}" }
        exit 1
      end
    end
  end
end
