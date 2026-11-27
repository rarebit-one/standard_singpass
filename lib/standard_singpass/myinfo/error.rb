# typed: strict

require "standard_singpass/error"

module StandardSingpass
  module Myinfo
    # Base class for every MyInfo error the gem raises. Descends from the
    # gem-wide `StandardSingpass::Error`.
    #
    # Every error carries the two facts a host needs to decide what to tell
    # the user, so neither has to be recovered by reading the message:
    #
    # `status` — the HTTP status of the Singpass response that produced the
    # error. Nil when there was no response (a transport failure) and for
    # errors a host raises itself.
    #
    # `transport?` — true when we never got an answer from Singpass at all
    # (DNS, connection refused, TLS, read timeout — a `Faraday::Error` under
    # the hood), as opposed to Singpass answering with something we can't
    # use. Only the former is unambiguously *their* side being unreachable.
    #
    # Both live on the base class rather than on `ApiError` alone because
    # every leg of the flow raises its own class — `PARError` for PAR,
    # `ApiError` for token and userinfo — and a host asking "is Singpass
    # available?" needs the same answer from all of them. Scoping `status` to
    # `ApiError` would silently misclassify a 502 from the PAR endpoint as
    # "our request was wrong".
    #
    # The alternative — matching "unreachable" or an HTTP code in `message` —
    # is a trap: the message is not a stable interface. `FailureClassifier`
    # consumes these so hosts never have to.
    class Error < StandardSingpass::Error
      extend T::Sig

      sig { returns(T.nilable(Integer)) }
      attr_reader :status

      # The OAuth `error` code from the Singpass response body
      # (`invalid_request`, `upstream_dependency_error`, …). Nil when the
      # response carried none, for transport failures, and for errors raised
      # before any response exists. Lets a host branch on the code without
      # parsing `message`: for example, a 502 `upstream_dependency_error` on
      # the PAR or token leg can mean Singpass could not fetch *our* JWKS,
      # and a userinfo `invalid_request` is what a Singpass Foreign Account
      # (which has no Myinfo data) produces.
      sig { returns(T.nilable(String)) }
      attr_reader :error_code

      # Both keywords are optional so the bare `raise SomeError, "msg"` form
      # used across the client (and by hosts) keeps working unchanged.
      sig do
        params(
          message: T.nilable(String),
          status: T.nilable(Integer),
          transport: T::Boolean,
          error_code: T.nilable(String)
        ).void
      end
      def initialize(message = nil, status: nil, transport: false, error_code: nil)
        super(message)
        @status = status
        @transport = transport
        @error_code = error_code
      end

      sig { returns(T::Boolean) }
      def transport?
        @transport
      end
    end

    class AuthenticationError < Error; end
    class PARError < Error; end
    class DecryptionError < Error; end
    class SignatureError < Error; end
    class RateLimitError < Error; end
    class ConfigurationError < Error; end

    # Raised for a Myinfo token- or userinfo-endpoint response we can't use,
    # and for transport failures reaching those endpoints at all. `status` and
    # `transport?` come from Error.
    #
    # 502 specifically is Singpass's documented signal that a Myinfo upstream
    # (CPF Board, IRAS, MOM, …) is down, including during their published
    # maintenance windows:
    # https://docs.developer.singpass.gov.sg/docs/products/singpass-myinfo/scheduled-downtimes
    class ApiError < Error; end
  end
end
