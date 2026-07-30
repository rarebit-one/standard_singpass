# typed: strict

module StandardSingpass
  module Myinfo
    # Normalises Notice-of-Assessment data from `PersonDataParser` into a
    # single list, regardless of which NOA scope the Singpass app was approved
    # for.
    #
    # Singpass approves NOA access at one of two widths, and the width is a
    # property of the *app registration*, not of the request:
    #
    #   noa            → Notice of Assessment, latest year only
    #   noahistory     → Notice of Assessment, last 2 years
    #
    # `PersonDataParser` mirrors that faithfully, emitting `:noa` (one record)
    # or `:noa_history` (an array, one entry per assessment year). The two
    # records have an identical shape — `year_of_assessment`, `amount`,
    # `employment`, `trade`, `rent`, `interest`, `tax_category` — so every
    # consumer that renders NOA data ends up writing the same "array or wrap
    # the single record" branch. That branch is scope-grant knowledge, not
    # host policy, so it belongs here.
    #
    # The `-basic` scopes (`noa-basic` / `noahistory-basic`) are the same
    # split at a narrower field set (`year_of_assessment` and `amount` only),
    # handled by `.basic_history`.
    #
    # The wider grant is preferred when both keys are present: a 2-year
    # history is a superset of the latest year, so returning it loses nothing.
    #
    # Keys are looked up as both Symbol and String because parser output is
    # symbol-keyed when fresh but string-keyed once it has round-tripped
    # through JSON or a database column — which is where most hosts read it
    # back from.
    module Noa
      extend T::Sig

      # Detailed NOA records, newest first as Singpass returns them. Returns
      # nil when neither detailed scope yielded data (e.g. a self-reported
      # application with no Myinfo record at all).
      sig { params(parsed: T.untyped).returns(T.nilable(T::Array[T.untyped])) }
      def self.history(parsed)
        normalize(parsed, history_key: :noa_history, single_key: :noa)
      end

      # Same, for the `-basic` scope pair.
      sig { params(parsed: T.untyped).returns(T.nilable(T::Array[T.untyped])) }
      def self.basic_history(parsed)
        normalize(parsed, history_key: :noa_history_basic, single_key: :noa_basic)
      end

      sig do
        params(
          parsed: T.untyped,
          history_key: Symbol,
          single_key: Symbol
        ).returns(T.nilable(T::Array[T.untyped]))
      end
      def self.normalize(parsed, history_key:, single_key:)
        history = fetch(parsed, history_key)
        return history if history.is_a?(Array) && !history.empty?

        single = fetch(parsed, single_key)
        single.is_a?(Hash) && !single.empty? ? [single] : nil
      end
      private_class_method :normalize

      sig { params(parsed: T.untyped, key: Symbol).returns(T.untyped) }
      def self.fetch(parsed, key)
        return nil unless parsed.is_a?(Hash)

        parsed[key].nil? ? parsed[key.to_s] : parsed[key]
      end
      private_class_method :fetch
    end
  end
end
