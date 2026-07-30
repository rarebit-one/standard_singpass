# typed: false

require "rails_helper"

RSpec.describe StandardSingpass::Myinfo::MockModeGuard do
  after { StandardSingpass::Myinfo.reset_configuration! }

  def configure(mock_mode:, detector: nil)
    StandardSingpass::Myinfo.configure do |c|
      c.mock_mode = mock_mode
      c.production_env_detector = detector
    end
  end

  def as_rails_env(name)
    allow(Rails).to receive(:env).and_return(ActiveSupport::StringInquirer.new(name))
  end

  describe ".check!" do
    context "when mock mode is off" do
      it "does nothing, even on production" do
        configure(mock_mode: false, detector: -> { true })

        expect { described_class.check! }.not_to raise_error
      end
    end

    context "when mock mode is on" do
      it "refuses to boot on a production deploy" do
        configure(mock_mode: true, detector: -> { true })

        expect { described_class.check! }.to raise_error(
          StandardSingpass::Myinfo::ConfigurationError,
          /refuses to boot/
        )
      end

      it "refuses to boot on Rails.env.production? with no detector configured" do
        configure(mock_mode: true)
        as_rails_env("production")

        expect { described_class.check! }
          .to raise_error(StandardSingpass::Myinfo::ConfigurationError)
      end

      it "boots but reports on a production-like deploy (staging on RAILS_ENV=production)" do
        configure(mock_mode: true, detector: -> { false })
        as_rails_env("production")
        allow(Rails.logger).to receive(:error)
        allow(Rails.error).to receive(:report)

        expect { described_class.check! }.not_to raise_error

        expect(Rails.logger).to have_received(:error).with(/mock_mode is enabled/)
        expect(Rails.error).to have_received(:report) do |error, **options|
          expect(error).to be_a(StandardSingpass::Myinfo::ConfigurationError)
          expect(options[:handled]).to be(true)
          expect(options[:context]).to include(component: "StandardSingpass::Myinfo::MockModeGuard")
        end
      end

      it "stays silent in development and test" do
        configure(mock_mode: true)
        allow(Rails.logger).to receive(:error)
        allow(Rails.error).to receive(:report)

        expect { described_class.check! }.not_to raise_error

        expect(Rails.logger).not_to have_received(:error)
        expect(Rails.error).not_to have_received(:report)
      end

      it "stays silent when the detector says non-production and RAILS_ENV is not production" do
        configure(mock_mode: true, detector: -> { false })
        as_rails_env("staging")
        allow(Rails.logger).to receive(:error)

        expect { described_class.check! }.not_to raise_error
        expect(Rails.logger).not_to have_received(:error)
      end

      it "lets the detector veto Rails.env — a preview box on RAILS_ENV=production still boots" do
        configure(mock_mode: true, detector: -> { false })
        as_rails_env("production")
        allow(Rails.error).to receive(:report)

        expect { described_class.check! }.not_to raise_error
      end

      it "lets the detector override a non-production RAILS_ENV" do
        configure(mock_mode: true, detector: -> { true })
        as_rails_env("staging")

        expect { described_class.check! }
          .to raise_error(StandardSingpass::Myinfo::ConfigurationError)
      end
    end
  end

  describe ".production_deploy?" do
    it "uses the detector's return value when one is configured" do
      configure(mock_mode: false, detector: -> { true })
      as_rails_env("test")

      expect(described_class.production_deploy?).to be(true)
    end

    it "coerces a truthy non-boolean detector result" do
      configure(mock_mode: false, detector: -> { "yes" })

      expect(described_class.production_deploy?).to be(true)
    end

    it "falls back to Rails.env.production? without a detector" do
      configure(mock_mode: false)

      expect(described_class.production_deploy?).to be(false)

      as_rails_env("production")
      expect(described_class.production_deploy?).to be(true)
    end
  end

  describe "engine wiring" do
    it "runs the guard from after_initialize, so hosts cannot forget to wire it" do
      allow(described_class).to receive(:check!)

      ActiveSupport.run_load_hooks(:after_initialize, Rails.application)

      expect(described_class).to have_received(:check!).at_least(:once)
    end
  end
end
