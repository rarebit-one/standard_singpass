# typed: true

# Hand-edited shims for OpenSSL constants Sorbet's stdlib RBI doesn't model.
# Regenerate via `bundle exec tapioca gems` should NOT touch this file.

class OpenSSL::PKey::EC::Point
  # Accepts :uncompressed, :compressed, or :hybrid. Argument name matches
  # OpenSSL's upstream docs so future readers can cross-reference.
  sig { params(conversion_form: Symbol).returns(String) }
  def to_octet_string(conversion_form); end
end
