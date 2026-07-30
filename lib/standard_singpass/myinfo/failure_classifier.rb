# typed: strict

module StandardSingpass
  module Myinfo
    # Decides whether a Myinfo failure is *Singpass's* side being unavailable
    # or *our* request being wrong.
    #
    # The distinction exists because it changes what the host tells the user.
    # An unavailable upstream clears itself within minutes, so the honest
    # instruction is "try again shortly"; telling someone "something on our
    # side stopped the verification — contact support and quote this
    # reference" is both wrong and a dead end. Conversely, presenting a
    # genuine integration bug as a transient blip sends the user round a loop
    # that will never succeed.
    #
    # This lives in the gem rather than in each host because the rule is
    # entirely Myinfo protocol knowledge: which statuses Singpass uses for
    # upstream-agency outages, and which of the gem's own exception classes
    # represent an unreachable endpoint. Hosts typically need the same answer
    # at more than one call site (a callback's result branch and a
    # controller's rescue), so it is a module function rather than a private
    # method on either.
    module FailureClassifier
      extend T::Sig

      # 502 is Singpass's documented signal that a Myinfo upstream agency
      # (CPF Board, IRAS, MOM, …) is unavailable — returned both for genuine
      # blips and throughout their published maintenance windows. 503/504 are
      # the generic unavailable/gateway-timeout equivalents.
      # https://docs.developer.singpass.gov.sg/docs/products/singpass-myinfo/scheduled-downtimes
      #
      # `Client::RETRYABLE_USERINFO_STATUSES` is an alias of this list: the
      # statuses worth one more automatic attempt are exactly the statuses
      # that mean "their side, transient".
      UPSTREAM_UNAVAILABLE_STATUSES = T.let([502, 503, 504].freeze, T::Array[Integer])

      # True when the failure is Singpass (or one of its upstream agencies)
      # being unavailable, i.e. the user should be told to retry shortly.
      # False for anything that looks like our own request being wrong —
      # authentication, decryption, signature, and configuration failures, and
      # any non-Myinfo exception.
      #
      # Deliberately keyed on the base `Error` rather than `ApiError`: every
      # leg of the flow raises its own class (`PARError` for PAR, `ApiError`
      # for token and userinfo), and a 502 is a 502 whichever leg returned it.
      # Narrowing to `ApiError` would report a PAR-leg outage as our own bug.
      sig { params(error: ::StandardError).returns(T::Boolean) }
      def self.upstream_unavailable?(error)
        # Rate limiting counts: temporary, clears on its own, and the advice
        # the host gives the user is identical.
        return true if error.is_a?(RateLimitError)
        return false unless error.is_a?(Error)

        # A transport failure never reached Singpass at all, which is still
        # their endpoint being unreachable from here.
        return true if error.transport?

        # `status` is nil for an error a host raised itself; that falls
        # through to false rather than being guessed at.
        UPSTREAM_UNAVAILABLE_STATUSES.include?(error.status)
      end
    end
  end
end
