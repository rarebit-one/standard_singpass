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

      initializer "standard_singpass.deprecator" do |app|
        app.deprecators[:standard_singpass] = StandardSingpass.deprecator if app.respond_to?(:deprecators)
      end

      rake_tasks do
        load File.expand_path("../tasks/standard_singpass.rake", __dir__)
      end

      # Runs after the host's own initializers (and its `to_prepare`
      # blocks), so the whole configure block has run by the time either is
      # read. The guard is inert unless mock mode is on; resolving the
      # private JWKS here surfaces missing/malformed-key warnings at boot
      # rather than on the first Singpass request.
      config.after_initialize do
        StandardSingpass::Myinfo::MockModeGuard.check!
        StandardSingpass::Myinfo.configuration.resolve_private_jwks!
      end
    end
  end
end
