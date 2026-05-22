source "https://rubygems.org"

# Specify your gem's dependencies in standard_singpass.gemspec.
# The minimum Ruby version is declared in standard_singpass.gemspec
# (required_ruby_version) so the gem stays installable on any supported
# patch release; CI runs against the full 4.x matrix.
gemspec

gem "sqlite3"

group :development, :test do
  gem "rspec-rails", "~> 8.0"
  gem "webmock", "~> 3.20"
end

# Omakase Ruby styling [https://github.com/rails/rubocop-rails-omakase/]
gem "rubocop-rails-omakase", require: false
gem "brakeman", require: false
gem "bundler-audit", require: false
