# typed: true
# frozen_string_literal: true

# Loaded before Bundler.require during `tapioca gems`. Our engine.rb
# references ::Rails::Engine at module-body load time, so railties must be
# loaded before our gem is required. `require "rails"` pulls in
# active_support, active_record, active_job, action_controller, action_view,
# and railties (which defines Rails::Engine).
require "rails"
