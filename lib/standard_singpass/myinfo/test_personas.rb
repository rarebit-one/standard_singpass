# typed: false

module StandardSingpass
  module Myinfo
    # Loads the test-persona fixture set used by Singpass mock-callback flows
    # (E2E only) and RSpec helpers. The fixture file is the single source of
    # truth so Ruby and Playwright sides can't drift.
    #
    # The host application can override the fixture path via
    # `StandardSingpass::Myinfo.configuration.personas_path = Pathname.new(...)`.
    # Without an override, the gem's bundled `fixtures/myinfo-personas.json`
    # is used.
    module TestPersonas
      DEFAULT_KEY = "default"
      GEM_FIXTURE_PATH = Pathname.new(File.expand_path("../../../fixtures/myinfo-personas.json", __dir__)).freeze

      class UnknownPersona < KeyError; end

      def self.fetch(key)
        key = key.to_s.presence || DEFAULT_KEY
        data.fetch(key) do
          raise UnknownPersona, "Unknown MyInfo test persona: #{key.inspect}. Known: #{data.keys.inspect}"
        end
      end

      def self.keys
        data.keys
      end

      def self.data
        @data ||= JSON.parse(fixture_path.read).freeze
      end

      # Test-only — call from a spec `before(:suite)` if you want to pick up
      # mid-run edits to the fixture file.
      def self.reload!
        @data = nil
        data
      end

      def self.fixture_path
        configured = StandardSingpass::Myinfo.configuration.personas_path
        configured ? Pathname.new(configured) : GEM_FIXTURE_PATH
      end
    end
  end
end
