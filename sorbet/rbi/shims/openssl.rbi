# typed: true

# Hand-edited shims for OpenSSL constants Sorbet's stdlib RBI doesn't model.
# Regenerate via `bundle exec tapioca gems` should NOT touch this file.

class OpenSSL::PKey::EC::Point
  sig { params(conversion: Symbol).returns(String) }
  def to_octet_string(conversion); end
end
