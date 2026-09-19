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

desc "Re-pin upstream license SHA-256 hashes (ONLY inside a reviewed PR explaining why). ONLY=id1,id2 pins just those ids and leaves every other pin untouched"
task "licenses:pin" do
  require_relative "pipeline/lib/http"
  require_relative "pipeline/lib/license_gate"
  only = ENV["ONLY"]&.split(",")&.map(&:strip)&.reject(&:empty?)
  OpenASNPipeline::LicenseGate.pin!(only: only)
end

desc "Draft data/overrides/org_names.txt lines from enrichment dossiers: rake 'org_names:draft[a.jsonl b.jsonl]'"
task "org_names:draft", [:paths] do |_t, args|
  ruby "pipeline/tools/org_names_from_dossiers.rb", *args[:paths].to_s.split(/[\s,]+/)
end

desc "Verify upstream licenses against pinned hashes without building. SCOPE=tier_a|curation|all (default all; the nightly checks tier_a only)"
task "licenses:check" do
  require_relative "pipeline/lib/http"
  require_relative "pipeline/lib/license_gate"
  OpenASNPipeline::LicenseGate.run(scope: ENV.fetch("SCOPE", "all").to_sym)
end

desc "Generate override candidate lists from cached data (curation aid, writes build/work/candidates/)"
task "overrides:candidates" do
  ruby "pipeline/tools/override_candidates.rb"
end

desc "RIR delegated-extended stats -> build/work/rir/ (registry + holder clusters; NOT published, D-SRC-1). RIPE only with OPENASN_RIR_INCLUDE_RIPE=1"
task "sources:rir" do
  require_relative "pipeline/lib/http"
  require_relative "pipeline/lib/license_gate"
  require_relative "pipeline/lib/rir_stats"
  offline = ENV["OFFLINE"] == "1"
  OpenASNPipeline::LicenseGate.run(offline: offline, scope: :curation)
  puts JSON.pretty_generate(OpenASNPipeline::RirStats.build(offline: offline)[:stats])
end

desc "PROTOTYPE: Wikidata P3797 (CC0) ASN->item seed + coverage vs RIR holder clusters -> build/work/wikidata/ (not published)"
task "sources:wikidata" do
  require_relative "pipeline/lib/http"
  require_relative "pipeline/lib/license_gate"
  require_relative "pipeline/lib/wikidata_asn"
  offline = ENV["OFFLINE"] == "1"
  OpenASNPipeline::LicenseGate.run(offline: offline, scope: :curation) # the RIR files it joins against
  puts JSON.pretty_generate(OpenASNPipeline::WikidataAsn.build(offline: offline).reject { |k, _| k == "conflict_asns" })
end

desc "Sibling candidates for data/overrides/ from RIR holder clusters (curation aid, writes build/work/candidates/*.rir-siblings.txt)"
task "overrides:rir_siblings" do
  ruby "pipeline/tools/rir_siblings.rb"
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
desc "Reproduce the exports from an unpacked release: rake 'exports:from_release[INPUT,OUTPUT]'. Verifies, never uploads."
task "exports:from_release", [:input, :output] do |_t, args|
  require "json"
  require_relative "pipeline/export/from_release"

  input  = args[:input] or abort("usage: rake 'exports:from_release[INPUT,OUTPUT]' (quote the brackets in zsh)")
  output = args[:output] or abort("usage: rake 'exports:from_release[INPUT,OUTPUT]'")
  abort("#{output} already exists; the exporters refuse to overwrite a candidate") if File.exist?(output)

  # Which formats to reproduce. `portable` stays the default so the task
  # behaves as it always has; CI raises it to `all` because a reproduction
  # that skipped the MMDB writer would leave the one build-only toolchain
  # in the system unexercised. The name is the same OPENASN_EXPORTS the
  # pipeline and the nightly already use, so there is one vocabulary.
  mode = ENV.fetch("OPENASN_EXPORTS", "portable")

  result = OpenASNPipeline::Export::FromRelease.call(input: input, output: output, mode: mode)
  puts JSON.pretty_generate(
    "build_id" => result.build_id,
    "mode" => mode,
    "input" => result.input,
    "output" => result.output,
    "publishable" => false,
    "nonpublishable_reasons" => result.nonpublishable_reasons,
    "marker" => result.marker,
    "records" => result.run.counts.to_h,
    "outputs" => result.run.outputs.map(&:to_h)
  )
end

desc "Validate an assembled export candidate directory: rake 'exports:validate[build/work/export/<gen>]'"
task "exports:validate", [:dir] do |_t, args|
  require "json"
  require_relative "pipeline/export/validate"
  dir = args[:dir] or abort("usage: rake 'exports:validate[DIR]' (quote the brackets in zsh)")
  present = ->(name) { File.file?(File.join(dir, name)) ? File.join(dir, name) : nil }

  records  = present.call("records.jsonl") or abort("#{dir}: no records.jsonl to validate against")
  metadata = present.call("metadata.json") or abort("#{dir}: no metadata.json")
  # openasn.mmdb is passed like every other output rather than being left
  # out: a candidate assembled in mode `all` carries one, and a validator
  # that silently ignored the only file it did not know about would report
  # PASS on a directory it had not fully read.
  report = OpenASNPipeline::Export::Validate.call(
    records: records, metadata: metadata,
    csv: present.call("openasn.csv"), csv_gz: present.call("openasn.csv.gz"),
    sqlite: present.call("openasn.sqlite"), sqlite_gz: present.call("openasn.sqlite.gz"),
    mmdb: present.call("openasn.mmdb")
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

# --- MMDB writer (build-only Go toolchain) ---------------------------------
# Deliberately outside `test` and `exports:test`: those must run anywhere, and
# the Ruby MMDB suite skips loudly when `go` is missing. This task is the one
# place that refuses to skip, so CI proves the writer rather than stepping
# over it. Go is a BUILD dependency; nothing shipped to a consumer needs it.
desc "MMDB writer: build/vet/test the Go tool, then run the Ruby MMDB acceptance suite"
task "exports:mmdb_test" do
  tool = File.expand_path("build/work/export-mmdb-tool/openasn-mmdb", __dir__)
  mkdir_p File.dirname(tool)
  sh "go -C tools/mmdbwriter build -o #{tool} ."
  sh "go -C tools/mmdbwriter vet ./..."
  sh "go -C tools/mmdbwriter test ./..."
  ruby "-Ipipeline test/export_mmdb_test.rb"
end

# --- SQLite writer (build-only Python toolchain) ---------------------------
# The mirror image of exports:mmdb_test, and it refuses to skip for the same
# reason. The Ruby suite never runs sqlite.py's own unit tests, so the whole
# Python path - interpreter resolution, spool binding, schema application,
# the lookup query plan - could break while `rake test` stayed green.
#
# WHICH interpreter runs it is the point, not a detail. On the development
# machine a bare `python3` is a Python 3.4 that is killed on startup (exit
# 137), and among healthy interpreters /usr/bin/python3 and
# /opt/homebrew/bin/python3 carry different SQLite libraries that write
# physically different database files. So this resolves the interpreter
# through the same code the release producer uses and PRINTS what it chose:
# a green run that silently used another SQLite engine than the one that
# writes the release proves nothing about the release.
desc "SQLite writer: run sqlite.py's stdlib-only test suite under the resolved build interpreter"
task "exports:python_test" do
  require "json"
  require_relative "pipeline/export/sqlite"

  python = OpenASNPipeline::Export::Sqlite.interpreter
  puts JSON.pretty_generate("resolved_interpreter" => python.to_h,
                            "script" => OpenASNPipeline::Export::Sqlite::SCRIPT)
  # sys.version and sqlite3.sqlite_version straight from the chosen
  # interpreter, in the log, before a single assertion runs.
  # sqlite3.sqlite_version and nothing else from that module: the DB-API
  # `sqlite3.version` attribute was deprecated in Python 3.12 and REMOVED in
  # 3.14, so printing it would turn this log line into an AttributeError on
  # exactly the newer interpreters an operator is most likely to have.
  sh python.command, "-c", <<~PY
    import sqlite3, sys
    print("python  ", sys.version.replace("\\n", " "))
    print("argv[0] ", sys.executable)
    print("sqlite3 ", sqlite3.sqlite_version)
  PY
  sh python.command, "-m", "unittest", "discover", "-s", "test/python", "-t", "test/python", "-v"
end

# --- the offline end-to-end (PRD §17.1) ------------------------------------
# Three tasks rather than one, because the middle of the chain is the two
# tasks that already exist: `exports:synthetic` lays down native bytes,
# `exports:from_release` + `exports:validate` do the real work unchanged,
# and `exports:candidate` assembles and checks what a release would be.
# Splitting it that way means CI exercises the operator tooling that ships,
# not a parallel code path written for CI.
desc "Write a synthetic OASN/OORG release (offline fixture): rake 'exports:synthetic[build/work/ci-e2e]'"
task "exports:synthetic", [:dir] do |_t, args|
  require_relative "pipeline/tools/export_ci"
  dir = args[:dir] or abort("usage: rake 'exports:synthetic[DIR]' (quote the brackets in zsh)")
  release = File.join(dir, OpenASNPipeline::Tools::ExportCI::RELEASE_DIR)
  abort("#{release} already exists; the harness writes a fresh fixture") if File.exist?(release)
  OpenASNPipeline::Tools::ExportCI.write_release(release)
end

desc "Assemble + check a release candidate from a synthetic generation: rake 'exports:candidate[build/work/ci-e2e]'"
task "exports:candidate", [:dir] do |_t, args|
  require "json"
  require_relative "pipeline/tools/export_ci"
  ci = OpenASNPipeline::Tools::ExportCI
  dir = args[:dir] or abort("usage: rake 'exports:candidate[DIR]' (quote the brackets in zsh)")

  report = ci.assemble(release: File.join(dir, ci::RELEASE_DIR),
                       export: File.join(dir, ci::EXPORT_DIR),
                       candidate: File.join(dir, ci::CANDIDATE_DIR))
  puts JSON.pretty_generate(report)
end

desc "Build the synthetic generation twice at a fixed timestamp and compare payload hashes: rake 'exports:reproducibility[build/work/ci-repro]'"
task "exports:reproducibility", [:dir] do |_t, args|
  require "json"
  require_relative "pipeline/tools/export_ci"
  dir = args[:dir] or abort("usage: rake 'exports:reproducibility[DIR]' (quote the brackets in zsh)")
  abort("#{dir} already exists; each comparison starts from an empty directory") if File.exist?(dir)

  puts JSON.pretty_generate(OpenASNPipeline::Tools::ExportCI.reproduce(root: dir))
end
