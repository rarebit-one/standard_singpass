# typed: strict

module StandardSingpass
  module Myinfo
    # Boot-time guard against running with `config.mock_mode` enabled where it
    # must never be.
    #
    # Mock mode short-circuits the FAPI 2.0 dance and serves data from static
    # fixture personas (`TestPersonas`). That is exactly right for
    # development, CI, and staging rehearsals, and catastrophic in production:
    # real users would submit fabricated identity and income data, and it
    # would be indistinguishable downstream from verified Myinfo data. A
    # mis-set environment variable on one deploy is all it takes, and nothing
    # about the running app looks wrong afterwards — which is why this is a
    # boot-time check rather than a runtime warning.
    #
    # Three outcomes, deliberately:
    #
    #   production deploy       → raise. The app refuses to boot.
    #   production-*like* deploy → log + report, boot anyway.
    #   anything else           → silent.
    #
    # The middle tier exists because staging and preview deploys routinely run
    # `RAILS_ENV=production` while being entirely legitimate places to enable
    # mock mode. Failing those closed would make the guard unusable, and
    # staying silent would hide a genuinely mis-set variable, so they get a
    # loud-but-non-fatal signal instead.
    #
    # "Production deploy" is decided by `config.production_env_detector` when
    # set, else by the estate's APP_ENVIRONMENT convention (shared with
    # standard_id, standard_audit and standard_health): APP_ENVIRONMENT when it
    # is set, where only staging, preview, development and test are
    # non-production and any other value (a typo included) is production, so a
    # mis-set variable fails closed; else `Rails.env.production?`. A staging box
    # with RAILS_ENV=production and APP_ENVIRONMENT=staging is therefore
    # production-*like*, not production, with no detector wiring.
    #
    # Wired automatically from the engine's `after_initialize`, so a host gets
    # the guard by configuring `mock_mode` at all. There is no opt-out: a
    # guard you can forget to invoke is a guard that isn't there.
    module MockModeGuard
      extend T::Sig

      sig { void }
      def self.check!
        return unless StandardSingpass::Myinfo.configuration.mock_mode

        if production_deploy?
          raise ConfigurationError, production_message
        elsif rails_production?
          report_production_like
        end
      end

      # APP_ENVIRONMENT values that are not production; anything else is.
      NON_PRODUCTION_APP_ENVIRONMENTS = T.let(%w[staging preview development test].freeze, T::Array[String])

      # Whether this deploy is real production for the purpose of the guard.
      # Defers to config.production_env_detector when set, else to
      # APP_ENVIRONMENT (failing closed), else Rails.env.production?.
      sig { returns(T::Boolean) }
      def self.production_deploy?
        detector = StandardSingpass::Myinfo.configuration.production_env_detector
        return !!detector.call if detector

        app_env = ENV["APP_ENVIRONMENT"].to_s.strip
        return !NON_PRODUCTION_APP_ENVIRONMENTS.include?(app_env) unless app_env.empty?

        rails_production?
      end

      sig { returns(T::Boolean) }
      def self.rails_production?
        defined?(::Rails) && ::Rails.env.production?
      end
      private_class_method :rails_production?

      sig { returns(String) }
      def self.production_message
        "StandardSingpass::Myinfo mock_mode is enabled on a production " \
          "deploy. Mock mode bypasses the real Singpass flow and serves " \
          "fixture persona data, so real users would submit fabricated " \
          "identity data that is indistinguishable from verified Myinfo " \
          "data downstream. The application refuses to boot. Unset the " \
          "mock-mode environment variable on this deploy and redeploy. If " \
          "this deploy is not actually production, set APP_ENVIRONMENT " \
          "(staging, preview, development or test) or " \
          "config.production_env_detector so the gem can tell."
      end
      private_class_method :production_message

      # A production-*like* deploy (RAILS_ENV=production but not production
      # per the detector) — staging, preview, a review app. Mock mode can be
      # intentional here, so this boots; it is reported rather than raised.
      #
      # Reported through `Rails.error` rather than a specific error tracker so
      # whatever the host has subscribed (Sentry included) picks it up.
      sig { void }
      def self.report_production_like
        message = "StandardSingpass::Myinfo mock_mode is enabled on a " \
          "deploy running RAILS_ENV=production. Users will go through the " \
          "mock Singpass flow and submit fixture data. Unset the mock-mode " \
          "environment variable unless this is intentional."

        ::Rails.logger&.error("StandardSingpass::Myinfo: #{message}")

        return unless defined?(::Rails.error)

        ::Rails.error.report(
          ConfigurationError.new(message),
          handled: true,
          context: {
            component: "StandardSingpass::Myinfo::MockModeGuard",
            reason: "mock_mode_on_production_like_deploy"
          }
        )
      end
      private_class_method :report_production_like
    end
  end
end
