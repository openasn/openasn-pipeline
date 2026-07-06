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

# --- LLM enrichment pilot (operator tooling; never part of `rake build`) ----
# The nightly build must stay LLM-free and deterministic — these tasks spend
# operator money/quota and are always invoked by hand. See pipeline/enrich/.

desc "LLM classification pilot vs our gold set (ARM=both|local|enriched LIMIT=n BATCH=12 FETCH=1)"
task "enrich:pilot" do
  ruby "pipeline/enrich/pilot.rb"
end

desc "Resume a killed pilot from its saved gold+packets: rake 'enrich:resume[pilot-YYYYMMDD-HHMMSS]'"
task "enrich:resume", [:dir] do |_t, args|
  require_relative "pipeline/enrich/pilot"
  OpenASNPipeline::Enrich::Pilot.resume(args.fetch(:dir))
end

# Both debug tasks build packets through Pilot.build_packet — the same code
# path enrich:pilot uses — so debug output can never drift from what the
# pilot actually feeds the model.
desc "Debug: evidence packet for one ASN: rake 'enrich:evidence[3352]' (EXTERNAL=0 for local-only)"
task "enrich:evidence", [:asn] do |_t, args|
  require_relative "pipeline/enrich/pilot"
  packet = OpenASNPipeline::Enrich::Pilot.build_packet(Integer(args[:asn]),
                                                       external: ENV["EXTERNAL"] != "0")
  puts JSON.pretty_generate(packet)
end

desc "Debug: classify one ASN end-to-end through the LLM: rake 'enrich:classify[3352]'"
task "enrich:classify", [:asn] do |_t, args|
  require_relative "pipeline/enrich/pilot"
  packet = OpenASNPipeline::Enrich::Pilot.build_packet(Integer(args[:asn]))
  llm = OpenASNPipeline::Enrich::LlmClient.new
  puts "backend=#{llm.backend} model=#{llm.model}"
  result = llm.classify_batch([packet]).first
  puts JSON.pretty_generate(result.to_h_compact)
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
