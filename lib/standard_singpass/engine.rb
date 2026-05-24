# Defines the Rails engine when Rails is loaded. In tooling contexts that
# load the gem without Rails (e.g. `tapioca gems`, which calls
# `Bundler.require` before any explicit `require "rails"`), this file is
# still required by `lib/standard_singpass.rb` but the engine class is
# simply not defined — which is fine, because rake-task autoloading is
# only meaningful inside a Rails host anyway.
if defined?(::Rails::Engine)
  module StandardSingpass
    class Engine < ::Rails::Engine
      isolate_namespace StandardSingpass

      rake_tasks do
        load File.expand_path("../tasks/standard_singpass.rake", __dir__)
      end
    end
  end
end
