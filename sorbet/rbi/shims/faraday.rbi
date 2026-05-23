# typed: true

# Module-level helpers on Faraday that tapioca's generated RBI does not
# cover. We only use Faraday.get for one-shot JWKS fetches in
# Security.fetch_jwks; the rest of the gem uses Faraday::Connection
# instances.

module Faraday
  class << self
    sig do
      params(
        url: String,
        block: T.nilable(T.proc.params(req: Faraday::Request).void)
      ).returns(Faraday::Response)
    end
    def get(url, &block); end
  end
end
