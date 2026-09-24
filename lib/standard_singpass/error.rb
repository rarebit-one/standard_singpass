# typed: strict

module StandardSingpass
  # Root of every error the gem raises, across products. Hosts that want one
  # `rescue` for "anything standard_singpass raised" rescue this;
  # `StandardSingpass::Myinfo::Error` (which carries `status` / `transport?`)
  # descends from it.
  class Error < StandardError; end
end
