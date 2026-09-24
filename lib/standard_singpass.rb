require "standard_singpass/version"
require "standard_singpass/engine"
require "standard_singpass/myinfo"

module StandardSingpass
  class << self
    # Top-level entry points matching the sibling `standard_*` gems'
    # `Gem.configure` / `Gem.config` convention. Singpass MyInfo is the only
    # product the gem integrates today, so both delegate to
    # `StandardSingpass::Myinfo` — `configure` goes through
    # `Myinfo.configure` so the derived public-JWKS cache is still reset.
    #
    #   StandardSingpass.configure { |c| c.client_id = "..." }
    #   StandardSingpass.config.client_id
    def configure(&block)
      Myinfo.configure(&block)
      config
    end

    def config
      Myinfo.configuration
    end
  end
end
