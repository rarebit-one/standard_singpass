require "simplecov"
SimpleCov.start do
  enable_coverage :branch
  add_filter "/spec/"
  # Initial extraction baseline; tighten as we add gem-side tests for the
  # paths the host previously covered indirectly (e.g. Configuration parse
  # failure branches, public_jwks key-load errors).
  minimum_coverage line: 85, branch: 75
end

ENV["RAILS_ENV"] ||= "test"

require File.expand_path("dummy/config/environment.rb", __dir__)
require "rspec/rails"

RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  config.shared_context_metadata_behavior = :apply_to_host_groups
end
