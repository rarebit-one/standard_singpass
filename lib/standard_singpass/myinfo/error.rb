# typed: strict

module StandardSingpass
  module Myinfo
    class Error < StandardError; end
    class AuthenticationError < Error; end
    class ApiError < Error; end
    class PARError < Error; end
    class DecryptionError < Error; end
    class SignatureError < Error; end
    class RateLimitError < Error; end
    class ConfigurationError < Error; end
  end
end
