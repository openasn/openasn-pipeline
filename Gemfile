# frozen_string_literal: true

source "https://rubygems.org"

# The pipeline itself is stdlib-only by design (see README) - these are
# developer/CI conveniences, not runtime dependencies of the build.
gem "rake", "~> 13.0"

group :development, :test do
  # csv left Ruby's DEFAULT gems in 3.4 (still ships as a BUNDLED gem):
  # https://www.ruby-lang.org/en/news/2024/12/25/ruby-3-4-0-released/
  # The nightly (`ruby pipeline/run.rb`, no bundler) finds the bundled gem
  # fine, but under `bundle exec rake test` only Gemfile gems are loadable,
  # so publish.rb's `require "csv"` breaks once tests load publish.rb
  # (test/publish_test.rb does). Dev/test group is enough: the nightly
  # workflow invokes the pipeline WITHOUT bundle exec.
  gem "csv"
  gem "minitest", "~> 6.0"
  gem "minitest-reporters", "~> 1.6"
end
