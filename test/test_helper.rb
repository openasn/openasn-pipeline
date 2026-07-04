# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../pipeline", __dir__)

require "minitest/autorun"
begin
  require "minitest/reporters"
  Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new
rescue LoadError
  # bare minitest is fine (e.g. running without bundler)
end

require_relative "../pipeline/lib/env"
require_relative "../pipeline/lib/ipmath"
require_relative "../pipeline/lib/binary"
require_relative "../pipeline/lib/asjson"
require_relative "../pipeline/lib/overrides"
require_relative "../pipeline/lib/license_gate"
require_relative "../pipeline/lib/classifier"
