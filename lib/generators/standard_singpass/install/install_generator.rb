# typed: ignore

# Sorbet skips this file — Rails::Generators::Base / Thor's dynamic API is
# not modelled in tapioca's generated RBIs and adding shims for it has
# diminishing returns for a one-class generator.

require "rails/generators"

module StandardSingpass
  module Generators
    # Installs StandardSingpass in a host Rails application.
    #
    # Writes the initializer at `config/initializers/standard_singpass.rb`
    # with the full configuration surface commented out so consumers know
    # what's available without being forced to wire everything up front.
    #
    # Idempotent: re-running the generator skips an existing initializer
    # unless `--force` is passed.
    class InstallGenerator < Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)

      desc <<~DESC
        Installs StandardSingpass. By default this:
          * writes config/initializers/standard_singpass.rb

        The generator is idempotent — an existing initializer is left alone
        unless --force is passed.
      DESC

      class_option :force, type: :boolean, default: false,
        desc: "Overwrite config/initializers/standard_singpass.rb if it already exists"

      def copy_initializer
        initializer_path = "config/initializers/standard_singpass.rb"

        if File.exist?(File.join(destination_root, initializer_path)) && !options[:force]
          say_status("identical", "#{initializer_path} (already exists; pass --force to overwrite)", :blue)
          return
        end

        template "initializer.rb.erb", initializer_path, force: options[:force]
      end
    end
  end
end
