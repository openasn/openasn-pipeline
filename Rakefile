# frozen_string_literal: true

# OpenASN data pipeline tasks. The nightly CI entry point is `rake build`
# (invoked by the DATA repo's nightly-build.yml); everything else is operator tooling.

require "rake/testtask"

desc "Full pipeline: fetch → license gate → normalize → crosscheck → compile → validate → publish (dist only)"
task :build do
  ruby "pipeline/run.rb"
end

desc "Fetch Tier A sources into build/cache/ (conditional GET; keep-last-good)"
task :fetch do
  ruby "pipeline/fetch.rb"
end

desc "Re-pin upstream license SHA-256 hashes (ONLY inside a reviewed PR explaining why)"
task "licenses:pin" do
  require_relative "pipeline/lib/http"
  require_relative "pipeline/lib/license_gate"
  OpenASNPipeline::LicenseGate.pin!
end

desc "Verify upstream licenses against pinned hashes without building"
task "licenses:check" do
  require_relative "pipeline/lib/http"
  require_relative "pipeline/lib/license_gate"
  OpenASNPipeline::LicenseGate.run
end

desc "Generate override candidate lists from cached data (curation aid, writes build/work/candidates/)"
task "overrides:candidates" do
  ruby "pipeline/tools/override_candidates.rb"
end

desc "Classify one IP against the artifacts in build/dist/ (debugging aid): rake 'lookup[8.8.8.8]'"
task :lookup, [:ip] do |_t, args|
  require "ipaddr"
  require_relative "pipeline/lib/binary"
  require_relative "pipeline/lib/classifier"
  ip = IPAddr.new(args[:ip])
  family = ip.ipv4? ? "ipv4" : "ipv6"
  artifact = OpenASNPipeline::Binary::Artifact.new("build/dist/openasn-#{family}.bin")
  puts OpenASNPipeline::Classifier.classify(artifact, ip.to_i).to_h.inspect
end

Rake::TestTask.new(:test) do |t|
  t.libs << "pipeline"
  t.test_files = FileList["test/**/*_test.rb"]
end

desc "Remove build workspace (cache, work, dist)"
task :clean do
  rm_rf "build"
end

task default: :test
