# typed: strict

module StandardSingpass
  module Myinfo
    class Error < StandardError; end
    class AuthenticationError < Error; end
    class PARError < Error; end
    class DecryptionError < Error; end
    class SignatureError < Error; end
    class RateLimitError < Error; end
    class ConfigurationError < Error; end

    # Raised for a Myinfo response we can't use, and for transport failures
    # reaching Myinfo at all.
    #
    # `status` carries the HTTP status when the error came from an actual
    # response (nil for transport failures, and for errors a host application
    # raises itself). Hosts need it to tell "Myinfo or one of its upstream
    # agencies is unavailable" — 502/503/504, retry in a few minutes — apart
    # from "we sent something wrong", which is a bug and warrants support
    # contact. Parsing the status back out of `message` is the alternative, and
    # it is a trap: the message is not a stable interface.
    #
    # 502 specifically is Singpass's documented signal that a Myinfo upstream
    # (CPF Board, IRAS, MOM, …) is down, including during their published
    # maintenance windows:
    # https://docs.developer.singpass.gov.sg/docs/products/singpass-myinfo/scheduled-downtimes
    class ApiError < Error
      extend T::Sig

      sig { returns(T.nilable(Integer)) }
      attr_reader :status

      # `status:` is keyword-only and optional so the bare `raise ApiError,
      # "msg"` form used across the client (and by hosts) keeps working.
      sig { params(message: T.nilable(String), status: T.nilable(Integer)).void }
      def initialize(message = nil, status: nil)
        super(message)
        @status = status
      end
    end
  end
end
