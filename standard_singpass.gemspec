require_relative "lib/standard_singpass/version"

Gem::Specification.new do |spec|
  spec.name        = "standard_singpass"
  spec.version     = StandardSingpass::VERSION
  spec.authors     = ["Jaryl Sim"]
  spec.email       = ["code@jaryl.dev"]
  spec.homepage    = "https://github.com/rarebit-one/standard_singpass"
  spec.summary     = "Singpass MyInfo (and future Singpass Sign-In) client for Rails apps."
  spec.description = "StandardSingpass packages the FAPI 2.0 OAuth client, DPoP/PKCE primitives, native ECDH-ES JWE decryption, and person-data parser needed to integrate with Singpass MyInfo. Designed as a reusable Rails engine; the host owns persistence, orchestration, and UI."
  spec.license     = "MIT"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/rarebit-one/standard_singpass"
  spec.metadata["changelog_uri"] = "https://github.com/rarebit-one/standard_singpass/blob/main/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "https://github.com/rarebit-one/standard_singpass/issues"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir["{app,config,db,lib,fixtures}/**/*", "MIT-LICENSE", "Rakefile", "README.md", "CHANGELOG.md"]
  end

  spec.required_ruby_version = ">= 4.0"

  spec.add_dependency "rails", ">= 8.0"
  spec.add_dependency "faraday", ">= 2.0"
  spec.add_dependency "jwt", ">= 2.7"
  spec.add_dependency "aes_key_wrap", "~> 1.1"
  # Sorbet sigils in the gem source (T.let, sig {}, T::Sig) require
  # sorbet-runtime at load time. Declared as a runtime dep so consumers
  # don't have to opt into Sorbet themselves.
  spec.add_dependency "sorbet-runtime", "~> 0.5"

  spec.add_development_dependency "simplecov", "~> 0.22"
  spec.add_development_dependency "sorbet", "~> 0.5"
  spec.add_development_dependency "tapioca", "~> 0.16"
end
