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

desc "Layer-A quant importer (no LLM): CAIDA AS Rank + RIR stats -> build/enrich/quant.jsonl. PAGES=n / RIRS=arin,ripencc bound it for a sample run."
task "enrich:quant" do
  require_relative "pipeline/enrich/quant/build"
  pages = ENV["PAGES"] && Integer(ENV["PAGES"])
  rirs  = ENV["RIRS"]&.split(",")
  stats = OpenASNPipeline::Quant::Build.run(caida_pages: pages, rirs: rirs)
  puts "quant: #{stats.inspect}"
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

# The export suite is a subset of `rake test`, not a replacement: it is the
# fast loop while iterating on the projection/profile. Synthetic fixtures
# only - no data repo, no cache, no network.
Rake::TestTask.new("exports:test") do |t|
  t.description = "Export unit tests only (offline, synthetic fixtures)"
  t.libs << "pipeline"
  t.test_files = FileList["test/export_*_test.rb"]
end

# Operator tooling for the portable exports. Neither task uploads anything,
# neither takes a publication flag, and both work from files already on
# disk: `exports:benchmark` reads a finished release directory (build/dist
# or an unpacked snapshot) and writes its outputs somewhere else entirely,
# `exports:validate` re-reads an assembled candidate.
desc "Validate an assembled export candidate directory: rake 'exports:validate[build/work/export/<gen>]'"
task "exports:validate", [:dir] do |_t, args|
  require "json"
  require_relative "pipeline/export/validate"
  dir = args[:dir] or abort("usage: rake 'exports:validate[DIR]' (quote the brackets in zsh)")
  present = ->(name) { File.file?(File.join(dir, name)) ? File.join(dir, name) : nil }

  records  = present.call("records.jsonl") or abort("#{dir}: no records.jsonl to validate against")
  metadata = present.call("metadata.json") or abort("#{dir}: no metadata.json")
  report = OpenASNPipeline::Export::Validate.call(
    records: records, metadata: metadata,
    csv: present.call("openasn.csv"), csv_gz: present.call("openasn.csv.gz"),
    sqlite: present.call("openasn.sqlite"), sqlite_gz: present.call("openasn.sqlite.gz")
  )
  puts JSON.pretty_generate(report)
end

desc "Size/time/memory for a full export: rake 'exports:benchmark[build/dist,build/work/export-bench]'. Never uploads."
task "exports:benchmark", [:input, :output] do |_t, args|
  require "json"
  require_relative "pipeline/export/inputs"
  require_relative "pipeline/export/metadata"
  require_relative "pipeline/export/run"
  require_relative "pipeline/export/sqlite"

  input  = args[:input] or abort("usage: rake 'exports:benchmark[INPUT,OUTPUT]' (quote the brackets in zsh)")
  output = args[:output] or abort("usage: rake 'exports:benchmark[INPUT,OUTPUT]'")
  abort("#{output} already exists; the exporters refuse to overwrite a candidate") if File.exist?(output)

  snapshot = OpenASNPipeline::Export::Inputs.load(
    v4_path: File.join(input, "openasn-ipv4.bin"),
    v6_path: File.join(input, "openasn-ipv6.bin"),
    orgs_path: File.join(input, "openasn-orgs.bin")
  )

  # The source catalogue comes from the manifest that shipped WITH these
  # bytes, not from a fresh construction: a benchmark must describe the
  # snapshot it measured, and a local run has no fetch state to ask.
  manifest_path = File.join(input, "manifest.json")
  unless File.file?(manifest_path)
    abort("#{input}: no manifest.json, so there is no honest source provenance for these inputs")
  end
  manifest = JSON.parse(File.read(manifest_path))
  attribution = File.join(input, "ATTRIBUTION.md")

  python = OpenASNPipeline::Export::Sqlite.interpreter
  context = OpenASNPipeline::Export::Metadata.context(
    snapshot: snapshot,
    sources: manifest.fetch("sources"),
    attribution: File.file?(attribution) ? File.read(attribution) : File.read(OpenASNPipeline::Env.attribution_path),
    producer: OpenASNPipeline::Export::Metadata.producer_versions(python: python)
  )

  # Peak memory is deliberately NOT sampled from inside this process. Ruby's
  # stdlib exposes no getrusage, and a sampling thread that shells out to
  # `ps` fires SIGCHLD into the middle of zlib's GVL-released writes, which
  # surfaced as a spurious Zlib::BufError during a 70MB compress. Measure it
  # from outside instead:
  #   /usr/bin/time -l bundle exec rake 'exports:benchmark[IN,OUT]'  (macOS)
  #   /usr/bin/time -v bundle exec rake 'exports:benchmark[IN,OUT]'  (Linux)
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  result = OpenASNPipeline::Export::Run.call(snapshot: snapshot, context: context, staging: output)
  elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

  puts JSON.pretty_generate(
    "input" => input,
    "output" => output,
    "elapsed_seconds" => elapsed.round(2),
    "producer" => context.producer,
    "records" => result.counts.to_h,
    "outputs" => result.outputs.map(&:to_h)
  )
end

desc "Remove build workspace (cache, work, dist)"
task :clean do
  rm_rf "build"
end

task default: :test

desc "Operator: is the nightly healthy? Ages of `latest` and the weekly pins, live gate thresholds, and whether tonight's drift gate would deadlock. Read-only."
task "gates:status" do
  require_relative "pipeline/tools/gates_status"
  exit(1) unless OpenASNPipeline::GatesStatus.call
end
