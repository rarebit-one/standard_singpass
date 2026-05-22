module StandardSingpass
  class Engine < ::Rails::Engine
    isolate_namespace StandardSingpass

    rake_tasks do
      load File.expand_path("../tasks/standard_singpass.rake", __dir__)
    end
  end
end
