# frozen_string_literal: true

# MMDB v1 acceptance (PRD ids M01-M07).
#
# Every expectation here is hand-authored against the contract, and every
# lookup goes through MiniMMDB at the bottom of this file - a small MaxMind DB
# reader written from the format spec, sharing no code with either Go library.
# That is the point: the writer (maxmind/mmdbwriter) proving its own output
# with its own reader (oschwald/maxminddb-golang) is one codebase agreeing
# with itself, and the whole reason MMDB is worth shipping is that a stranger's
# reader can open it.
#
# The spools are built through Export::Spool.line_for, so the bytes the Go
# tool parses here are the bytes production writes - a test that hand-rolled
# its own JSONL could pass while the real spool drifted.
#
# The Go toolchain is a BUILD dependency, not a runtime one, so these tests
# skip loudly when `go` is absent rather than failing a contributor's suite.
# `rake exports:mmdb_test` builds the tool first, so CI has no such excuse.

require_relative "test_helper"
require "English"
require "json"
require "open3"
require_relative "../pipeline/export/contract"
require_relative "../pipeline/export/project"
require_relative "../pipeline/export/spool"

module OpenASNPipeline
  class ExportMmdbTest < Minitest::Test
    TOOL_DIR = File.expand_path("../tools/mmdbwriter", __dir__)
    BUILD_ID = "2026-09-18T18:43:40Z"
    BUILD_TS = 1_789_757_020
    ATTRIBUTION = "Data: OpenASN contributors. Synthetic fixture attribution.\n"

    class << self
      # Compiled once per process into the disposable build workspace, never
      # into the source tree.
      def tool
        return @tool if defined?(@tool)

        @tool = begin
          if ENV["OPENASN_MMDB_TOOL"]
            ENV["OPENASN_MMDB_TOOL"]
          elsif system("command -v go > /dev/null 2>&1")
            path = File.join(WORK_DIR, "export-mmdb-tool", "openasn-mmdb")
            FileUtils.mkdir_p(File.dirname(path))
            out, status = Open3.capture2e("go", "build", "-o", path, ".", chdir: TOOL_DIR)
            raise "go build failed:\n#{out}" unless status.success?

            path
          end
        end
      end
    end

    def setup
      tool = self.class.tool
      skip "go is not installed: the MMDB writer was not built or exercised" if tool.nil?

      @tool = tool
      @dir = File.join(WORK_DIR, "test-#{name}")
      FileUtils.mkdir_p(@dir)
    end

    def teardown
      FileUtils.rm_rf(@dir) if @dir
    end

    # --- M01 -----------------------------------------------------------

    def test_a_non_cidr_interval_is_covered_exactly_and_nothing_outside_it_hits
      # 1.0.0.5-1.0.0.10 is six addresses and no CIDR: the writer has to
      # decompose it into /32+/31+/30-shaped pieces that cover it and only it.
      db = build_db([record(:ipv4, v4("1.0.0.5"), v4("1.0.0.10"),
                            asn: 100, as_org: "Access A", category: "isp",
                            network_role: "access_provider",
                            core_verdict: "residential_isp", core_sources: ["asn_category"])])

      (5..10).each do |octet|
        found = db.lookup("1.0.0.#{octet}")
        refute_nil found, "1.0.0.#{octet} is inside the interval"
        assert_equal 100, found["asn"]
        assert_equal "residential_isp", found["core_verdict"]
      end

      assert_nil db.lookup("1.0.0.4"), "the address below the interval must not hit"
      assert_nil db.lookup("1.0.0.11"), "the address above the interval must not hit"
      assert_nil db.lookup("1.0.0.0")
      assert_nil db.lookup("1.0.1.5")
    end

    # --- M02 -----------------------------------------------------------

    def test_adjacent_records_that_share_most_of_their_evidence_stay_distinct
      # Same ASN, same org, same category, same role: everything a careless
      # dedup key might hash. Only the DC overlay differs, and with it the
      # verdict and its explanation.
      shared = { asn: 200, as_org: "Shared Org", category: "isp", network_role: "access_provider" }
      db = build_db([
                      record(:ipv4, v4("1.0.0.0"), v4("1.0.0.7"), **shared,
                             core_verdict: "residential_isp", core_sources: ["asn_category"]),
                      record(:ipv4, v4("1.0.0.8"), v4("1.0.0.15"), **shared, datacenter_range: true,
                             core_verdict: "hosting", core_sources: ["x4b_dc"])
                    ])

      low = db.lookup("1.0.0.7")
      high = db.lookup("1.0.0.8")

      assert_equal "residential_isp", low["core_verdict"]
      assert_equal ["asn_category"], low["core_sources"]
      assert_equal false, low["datacenter_range"]

      assert_equal "hosting", high["core_verdict"]
      assert_equal ["x4b_dc"], high["core_sources"]
      assert_equal true, high["datacenter_range"]

      assert_equal 200, low["asn"]
      assert_equal 200, high["asn"]
      assert_equal "Shared Org", high["as_org"]
    end

    def test_two_records_with_an_identical_payload_share_one_stored_record
      # Deduplication is what keeps the file small, so it has to actually
      # happen - and it must never merge the two intervals into one, which is
      # what the gap probe below proves.
      payload = { asn: 300, as_org: "Same Org", category: "hosting",
                  core_verdict: "hosting", core_sources: ["asn_category"] }
      db = build_db([
                      record(:ipv4, v4("1.0.0.0"), v4("1.0.0.3"), **payload),
                      record(:ipv4, v4("1.0.0.8"), v4("1.0.0.11"), **payload)
                    ])

      first = db.lookup_with_offset("1.0.0.1")
      second = db.lookup_with_offset("1.0.0.9")

      assert_equal first.last, second.last, "an identical payload must be stored once"
      assert_equal "hosting", first.first["core_verdict"]
      assert_nil db.lookup("1.0.0.5"), "the gap between them must stay empty"
    end

    # --- M03 -----------------------------------------------------------

    def test_an_overlay_only_record_omits_its_null_keys_and_keeps_every_false_boolean
      db = build_db([record(:ipv4, v4("1.0.0.0"), v4("1.0.0.3"), vpn_range: true,
                            core_verdict: "vpn", core_sources: ["x4b_vpn"])])
      found = db.lookup("1.0.0.1")

      # MMDB has no null type, so a null field is absent, not empty-stringed.
      %w[asn as_org category network_role].each do |key|
        refute_includes found.keys, key, "#{key} is null here and must be omitted, not stored empty"
      end

      # Every boolean survives, including the false ones - "absent" would
      # otherwise have to mean both false and "this build forgot to write it".
      Export::Contract::SIGNALS.each do |signal|
        assert_includes found.keys, signal.to_s, "#{signal} must be present even when false"
      end
      assert_equal true, found["vpn_range"]
      assert_equal false, found["datacenter_range"]
      assert_equal false, found["bad_asn"]
      assert_equal "vpn", found["core_verdict"]
      assert_equal ["x4b_vpn"], found["core_sources"]

      assert_equal 10, found.keys.length, "an overlay-only record is 8 booleans plus verdict and sources"
    end

    def test_a_routed_record_stores_all_fourteen_payload_fields_and_nothing_else
      db = build_db([record(:ipv4, v4("1.0.0.0"), v4("1.0.0.3"),
                            asn: 15_169, as_org: "Google LLC", category: "hosting",
                            network_role: "midsize_transit", bad_asn: true,
                            core_verdict: "hosting", core_sources: %w[asn_bad_asn asn_category])])
      found = db.lookup("1.0.0.2")

      assert_equal Export::Contract::PAYLOAD_FIELDS.map(&:to_s).sort, found.keys.sort
      # No ip_version, no start/end, no row id, no timestamp: bounds live in
      # the tree and per-row identity would defeat deduplication.
      %w[ip_version start_hex end_hex start end build_id].each do |absent|
        refute_includes found.keys, absent
      end
      assert_equal %w[asn_bad_asn asn_category], found["core_sources"]
    end

    # --- M04 -----------------------------------------------------------

    def test_the_maximum_asn_round_trips_as_an_mmdb_uint32
      db = build_db([
                      record(:ipv4, v4("1.0.0.0"), v4("1.0.0.0"), asn: 0, as_org: "AS Zero",
                             core_verdict: "unknown", core_sources: ["asn_no_category"]),
                      record(:ipv4, v4("1.0.0.1"), v4("1.0.0.1"), asn: 4_294_967_295, as_org: "AS Max",
                             core_verdict: "unknown", core_sources: ["asn_no_category"])
                    ])

      # A real AS0 is a value, not a missing ASN, and must not be normalized
      # away by a truthiness check anywhere in the chain.
      zero = db.lookup("1.0.0.0")
      assert_includes zero.keys, "asn"
      assert_equal 0, zero["asn"]

      max = db.lookup("1.0.0.1")
      assert_equal 4_294_967_295, max["asn"]
      assert_equal :uint32, db.kind_of_field("1.0.0.1", "asn")
    end

    # --- M05 -----------------------------------------------------------

    def test_native_ipv6_in_the_low_prefix_fails_generation_explicitly
      assert_gate_failure(record(:ipv6, 1, 0xff), "::/96")
    end

    def test_native_ipv6_in_the_mapped_prefix_fails_generation_explicitly
      mapped = 0x0000_0000_0000_0000_0000_ffff_0000_0000
      assert_gate_failure(record(:ipv6, mapped, mapped + 0xff), "::ffff:0:0/96")
    end

    def test_the_gate_reports_a_zero_count_on_data_that_does_not_trip_it
      # The tripwire has to be visible when it does NOT fire, or a future
      # violation only shows up as a failed nightly.
      _, stderr = build_db([record(:ipv6, v6("2001:db8::"), v6("2001:db8::ffff"),
                                   core_verdict: "unknown", core_sources: ["unrouted"],
                                   vpn_range: true)], with_stderr: true)

      assert_match(/overlapping ::\/96 = 0/, stderr)
      assert_match(%r{overlapping ::ffff:0:0/96 = 0}, stderr)
    end

    # --- M06 -----------------------------------------------------------

    def test_native_ipv6_in_6to4_and_teredo_space_is_never_aliased_to_ipv4
      db = build_db([
                      record(:ipv4, v4("1.1.1.0"), v4("1.1.1.255"), asn: 13_335, as_org: "Cloudflare",
                             category: "hosting", core_verdict: "hosting", core_sources: ["asn_category"]),
                      record(:ipv4, v4("8.8.8.0"), v4("8.8.8.255"), asn: 15_169, as_org: "Google LLC",
                             category: "hosting", core_verdict: "hosting", core_sources: ["asn_category"]),
                      record(:ipv6, v6("2002:808:808::"), v6("2002:808:808:ffff:ffff:ffff:ffff:ffff"),
                             asn: 64_500, as_org: "Native Six", category: "business",
                             core_verdict: "business", core_sources: ["asn_category"])
                    ])

      # The 6to4 record is IPv6 data and answers as itself.
      native = db.lookup("2002:808:808::1")
      assert_equal 64_500, native["asn"]
      assert_equal "Native Six", native["as_org"]

      # 6to4 space with no native record must stay empty even though the
      # embedded IPv4 address is in the database. An automatic alias would
      # have answered with Cloudflare's record here.
      assert_nil db.lookup("2002:101:101::1"), "2002::/16 must not alias into the IPv4 subtree"
      # Teredo, same rule.
      assert_nil db.lookup("2001:0:101:101::"), "2001::/32 must not alias into the IPv4 subtree"
      assert_nil db.lookup("2001:0:808:808::"), "2001::/32 must not alias into the IPv4 subtree"

      assert_equal 13_335, db.lookup("1.1.1.1")["asn"]
      assert_equal 15_169, db.lookup("8.8.8.8")["asn"]

      # The one representation that a combined MMDB cannot avoid, documented
      # in EXPORT_FORMATS.md §6.4: IPv4 lives in ::/96, so a raw reader
      # resolves ::808:808 to 8.8.8.8's record. A helper applies lookup
      # policy 1 and never searches the IPv4 subtree for a native IPv6 input;
      # this asserts the raw behaviour so a change to it is deliberate.
      assert_equal 15_169, db.lookup("::808:808")["asn"]
    end

    # --- M07 -----------------------------------------------------------

    def test_the_metadata_carries_the_contract_type_epoch_and_deterministic_description
      records = [
        record(:ipv4, v4("1.0.0.0"), v4("1.0.0.255"), asn: 100, as_org: "Access A", category: "isp",
               network_role: "access_provider", core_verdict: "residential_isp",
               core_sources: ["asn_category"]),
        record(:ipv6, v6("2a00:1450::"), v6("2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff"),
               asn: 15_169, as_org: "Google LLC", category: "hosting",
               core_verdict: "hosting", core_sources: ["asn_category"])
      ]
      db, = build_db(records, with_stderr: false, summary: true)

      assert_equal "OpenASN-Core-v1", db.metadata["database_type"]
      assert_equal BUILD_TS, db.metadata["build_epoch"]
      assert_equal 6, db.metadata["ip_version"]
      assert_equal 28, db.metadata["record_size"]
      assert_equal 2, db.metadata["binary_format_major_version"]

      expected = "OpenASN core; schema_version=1; schema_revision=0; " \
                 "classification_profile=core-v1; lookup_policy_version=1; scope=tier_a; " \
                 "build_id=#{BUILD_ID}; records_ipv4=1; records_ipv6=1\n#{ATTRIBUTION}"
      assert_equal expected, db.metadata["description"]["en"]
      assert_equal ["en"], db.metadata["description"].keys
    end

    def test_the_tree_node_count_is_not_the_logical_row_count
      records = (0..3).map do |i|
        record(:ipv4, v4("1.0.#{i}.0"), v4("1.0.#{i}.255"), asn: 100 + i, as_org: "Org #{i}",
               category: "isp", network_role: "access_provider",
               core_verdict: "residential_isp", core_sources: ["asn_category"])
      end
      db, summary = build_db(records, summary: true)

      assert_equal 4, summary.fetch("records_total")
      assert_equal db.metadata["node_count"], summary.fetch("node_count")
      # The search tree needs one node per decision bit, so four /24s are
      # tens of nodes. The manifest, not the tree, states the row count.
      refute_equal summary.fetch("records_total"), summary.fetch("node_count")
      assert_operator summary.fetch("node_count"), :>, summary.fetch("records_total")
    end

    # --- contract and determinism --------------------------------------

    def test_every_core_v1_verdict_and_source_token_is_accepted_and_round_trips
      # The Go writer carries its own copy of the vocabulary because it cannot
      # read Ruby. This is the test that keeps the copy honest: a token added
      # to Contract without being added there fails here.
      verdicts = Export::Contract::VERDICTS
      sources  = Export::Contract::SOURCES
      rows = verdicts.each_with_index.map do |verdict, i|
        record(:ipv4, v4("1.0.0.#{i}"), v4("1.0.0.#{i}"), asn: 1000 + i, as_org: "Org #{i}",
               core_verdict: verdict, core_sources: ["asn_no_category"])
      end
      rows += sources.each_with_index.map do |source, i|
        record(:ipv4, v4("1.0.1.#{i}"), v4("1.0.1.#{i}"), asn: 2000 + i, as_org: "Org #{i}",
               core_verdict: "unknown", core_sources: [source])
      end
      db = build_db(rows)

      verdicts.each_with_index { |verdict, i| assert_equal verdict, db.lookup("1.0.0.#{i}")["core_verdict"] }
      sources.each_with_index { |source, i| assert_equal [source], db.lookup("1.0.1.#{i}")["core_sources"] }
    end

    def test_a_token_outside_the_profile_is_rejected_rather_than_written
      line = Export::Spool.line_for(record(:ipv4, v4("1.0.0.0"), v4("1.0.0.1"),
                                           core_verdict: "unknown", core_sources: ["unrouted"]))
      records_path = File.join(@dir, "records.jsonl")
      File.write(records_path, line.sub('"unrouted"', '"tor_exit"'))

      status, _stdout, stderr = run_tool("build", "--records", records_path,
                                         "--metadata", write_metadata(ipv4: 1, ipv6: 0),
                                         "--output", File.join(@dir, "out.mmdb"))

      refute_equal 0, status, "an unknown source token must fail the build"
      assert_match(/tor_exit/, stderr)
      refute_path_exists File.join(@dir, "out.mmdb")
    end

    def test_the_same_spool_and_metadata_produce_the_same_bytes_twice
      records = [
        record(:ipv4, v4("1.0.0.0"), v4("1.0.0.9"), asn: 100, as_org: "Access A", category: "isp",
               network_role: "access_provider", core_verdict: "residential_isp",
               core_sources: ["asn_category"]),
        record(:ipv6, v6("2a00:1450::"), v6("2a00:1450::ffff"), asn: 15_169, as_org: "Google LLC",
               category: "hosting", core_verdict: "hosting", core_sources: ["asn_category"])
      ]
      records_path = write_spool(records)
      metadata_path = write_metadata(ipv4: 1, ipv6: 1)

      digests = (1..2).map do |i|
        output = File.join(@dir, "out-#{i}.mmdb")
        status, stdout, stderr = run_tool("build", "--records", records_path,
                                          "--metadata", metadata_path, "--output", output)
        assert_equal 0, status, stderr
        Digest::SHA256.file(output).hexdigest.tap do |digest|
          assert_equal digest, JSON.parse(stdout).fetch("sha256"),
                       "the tool must report the digest of the bytes it wrote"
        end
      end

      assert_equal digests.first, digests.last
    end

    def test_verify_mode_accepts_the_database_it_just_built
      records = [
        record(:ipv4, v4("1.0.0.5"), v4("1.0.0.10"), asn: 100, as_org: "Access A", category: "isp",
               network_role: "access_provider", core_verdict: "residential_isp",
               core_sources: ["asn_category"]),
        record(:ipv4, v4("1.0.0.20"), v4("1.0.0.20"), vpn_range: true,
               core_verdict: "vpn", core_sources: ["x4b_vpn"]),
        record(:ipv6, v6("2a00:1450::"), v6("2a00:1450::ffff"), asn: 15_169, as_org: "Google LLC",
               category: "hosting", core_verdict: "hosting", core_sources: ["asn_category"])
      ]
      records_path = write_spool(records)
      metadata_path = write_metadata(ipv4: 2, ipv6: 1)
      output = File.join(@dir, "out.mmdb")

      status, = run_tool("build", "--records", records_path, "--metadata", metadata_path,
                         "--output", output)
      assert_equal 0, status

      status, stdout, stderr = run_tool("verify", "--database", output,
                                        "--records", records_path, "--metadata", metadata_path)
      assert_equal 0, status, stderr
      summary = JSON.parse(stdout)
      assert_equal 0, summary.fetch("mismatches")
      assert_operator summary.fetch("endpoint_comparisons"), :>=, records.length
      assert_operator summary.fetch("gap_probes"), :>, 0
      assert_operator summary.fetch("prefix_comparisons"), :>, 0
    end

    def test_verify_mode_rejects_a_database_that_does_not_match_its_spool
      records = [record(:ipv4, v4("1.0.0.0"), v4("1.0.0.3"), asn: 100, as_org: "Access A",
                        category: "isp", network_role: "access_provider",
                        core_verdict: "residential_isp", core_sources: ["asn_category"])]
      output = File.join(@dir, "out.mmdb")
      status, = run_tool("build", "--records", write_spool(records),
                         "--metadata", write_metadata(ipv4: 1, ipv6: 0), "--output", output)
      assert_equal 0, status

      # A spool claiming one more address than the database covers.
      widened = [record(:ipv4, v4("1.0.0.0"), v4("1.0.0.4"), asn: 100, as_org: "Access A",
                        category: "isp", network_role: "access_provider",
                        core_verdict: "residential_isp", core_sources: ["asn_category"])]
      status, stdout, = run_tool("verify", "--database", output,
                                 "--records", write_spool(widened, name: "widened.jsonl"),
                                 "--metadata", write_metadata(ipv4: 1, ipv6: 0))

      refute_equal 0, status, "verify must not pass a database that disagrees with its spool"
      assert_operator JSON.parse(stdout).fetch("mismatches"), :>, 0
    end

    private

    def v4(text) = IPAddr.new(text).to_i
    def v6(text) = IPAddr.new(text).to_i

    DEFAULTS = { asn: nil, as_org: nil, category: nil, network_role: nil,
                 core_verdict: "unknown", core_sources: ["unrouted"] }.freeze

    # A spool record built exactly as the projection builds one, so the JSONL
    # under test is production's own serialization.
    def record(family, start, finish, **fields)
      payload = Export::Project::Payload.new
      Export::Contract::PAYLOAD_FIELDS.each do |field|
        payload[field] = if Export::Contract::SIGNALS.include?(field)
                           fields.fetch(field, false)
                         else
                           fields.fetch(field, DEFAULTS.fetch(field))
                         end
      end
      unknown = fields.keys - Export::Contract::PAYLOAD_FIELDS
      raise ArgumentError, "unknown payload field(s) #{unknown.inspect}" unless unknown.empty?

      Export::Project::Record.new(family, start, finish, payload)
    end

    def write_spool(records, name: "records.jsonl")
      path = File.join(@dir, name)
      File.open(path, "wb") { |io| records.each { |r| io.write(Export::Spool.line_for(r)) } }
      path
    end

    # A minimal stand-in for the real export metadata.json. It carries only
    # the keys the MMDB writer reads; the production file (PRD §10.2) carries
    # many more for the other writers.
    def write_metadata(ipv4:, ipv6:, name: "metadata.json")
      path = File.join(@dir, name)
      File.write(path, JSON.generate(
                         "schema_version" => Export::Contract::SCHEMA_VERSION,
                         "schema_revision" => Export::Contract::SCHEMA_REVISION,
                         "classification_profile" => Export::Contract::CLASSIFICATION_PROFILE,
                         "lookup_policy_version" => Export::Contract::LOOKUP_POLICY_VERSION,
                         "scope" => Export::Contract::SCOPE,
                         "build_id" => BUILD_ID,
                         "built_at" => BUILD_ID,
                         "build_unix_ts" => BUILD_TS,
                         "records_ipv4" => ipv4,
                         "records_ipv6" => ipv6,
                         "records_total" => ipv4 + ipv6,
                         "attribution" => ATTRIBUTION
                       ))
      path
    end

    def build_db(records, with_stderr: false, summary: false)
      ipv4 = records.count { |r| r.family == :ipv4 }
      output = File.join(@dir, "out.mmdb")
      status, stdout, stderr = run_tool("build",
                                        "--records", write_spool(records),
                                        "--metadata", write_metadata(ipv4: ipv4, ipv6: records.length - ipv4),
                                        "--output", output)
      assert_equal 0, status, "build failed:\n#{stderr}"

      db = MiniMMDB.new(output)
      return [db, stderr] if with_stderr
      return [db, JSON.parse(stdout)] if summary

      db
    end

    def assert_gate_failure(gated_record, prefix)
      status, _stdout, stderr = run_tool("build",
                                         "--records", write_spool([gated_record]),
                                         "--metadata", write_metadata(ipv4: 0, ipv6: 1),
                                         "--output", File.join(@dir, "out.mmdb"))

      refute_equal 0, status, "native IPv6 inside #{prefix} must fail generation"
      assert_match(/address representation/, stderr)
      assert_match(/reviewed representation change/, stderr)
      refute_path_exists File.join(@dir, "out.mmdb"),
                         "a gated build must not leave a database behind"
    end

    def run_tool(*args)
      stdout, stderr, status = Open3.capture3(@tool, *args)
      [status.exitstatus, stdout, stderr]
    end

    # A MaxMind DB reader written straight from the published format, used
    # here as an independent third opinion. It handles only what this export
    # stores: 28-bit records, maps, strings, uint32, booleans, arrays and
    # pointers. Anything else raises rather than guesses.
    class MiniMMDB
      MARKER = "\xab\xcd\xef".b + "MaxMind.com".b
      SEPARATOR_SIZE = 16

      attr_reader :metadata

      def initialize(path)
        @buf = File.binread(path).b
        marker = @buf.rindex(MARKER)
        raise "no MaxMind metadata marker in #{path}" if marker.nil?

        metadata_start = marker + MARKER.bytesize
        @metadata, = decode(metadata_start, metadata_start)
        @node_count = @metadata.fetch("node_count")
        @record_size = @metadata.fetch("record_size")
        raise "unsupported record size #{@record_size}" unless @record_size == 28

        @node_bytes = @record_size * 2 / 8
        @tree_size = @node_count * @node_bytes
        @data_start = @tree_size + SEPARATOR_SIZE
      end

      def lookup(text) = lookup_with_offset(text)&.first

      # Returns [value, data_offset] so a test can prove two intervals share
      # one stored record.
      def lookup_with_offset(text)
        pointer = search(address_bits(text))
        return nil if pointer.nil?

        offset = @data_start + (pointer - @node_count - SEPARATOR_SIZE)
        value, = decode(offset, @data_start)
        [value, offset]
      end

      # The stored MMDB type of one field, so a test can tell a uint32 from a
      # uint64 that happens to hold the same number.
      def kind_of_field(text, field)
        pointer = search(address_bits(text))
        return nil if pointer.nil?

        offset = @data_start + (pointer - @node_count - SEPARATOR_SIZE)
        type, size, cursor = control(offset)
        raise "record is type #{type}, not a map" unless type == 7

        size.times do
          key, cursor = decode(cursor, @data_start)
          value_type, = control(follow(cursor))
          return TYPE_NAMES.fetch(value_type) if key == field

          _, cursor = decode(cursor, @data_start)
        end
        nil
      end

      private

      TYPE_NAMES = { 1 => :pointer, 2 => :utf8_string, 5 => :uint16, 6 => :uint32,
                     7 => :map, 11 => :array, 14 => :boolean }.freeze

      # IPv4 is stored in the low ::/96 subtree, so every address is searched
      # as its 128-bit form from the root. That is the representation, not a
      # convenience: it is exactly why ::808:808 finds 8.8.8.8.
      def address_bits(text)
        ip = IPAddr.new(text)
        bytes = ip.ipv4? ? ("\0".b * 12) + ip.hton : ip.hton
        bytes.unpack("C*")
      end

      def search(bytes)
        node = 0
        128.times do |i|
          bit = (bytes[i / 8] >> (7 - (i % 8))) & 1
          node = read_record(node, bit)
          return nil if node == @node_count
          return node if node > @node_count
        end
        raise "search ran off the end of the tree"
      end

      def read_record(node, bit)
        base = node * @node_bytes
        raw = @buf.byteslice(base, @node_bytes).unpack("C*")
        if bit.zero?
          ((raw[3] >> 4) << 24) | (raw[0] << 16) | (raw[1] << 8) | raw[2]
        else
          ((raw[3] & 0x0f) << 24) | (raw[4] << 16) | (raw[5] << 8) | raw[6]
        end
      end

      def byte(offset) = @buf.getbyte(offset)

      # Returns [type, size, offset_of_payload].
      def control(offset)
        ctrl = byte(offset)
        type = ctrl >> 5
        cursor = offset + 1
        if type.zero?
          type = byte(cursor) + 7
          cursor += 1
        end
        size = ctrl & 0x1f
        case size
        when 29
          size = 29 + byte(cursor)
          cursor += 1
        when 30
          size = 285 + int_at(cursor, 2)
          cursor += 2
        when 31
          size = 65_821 + int_at(cursor, 3)
          cursor += 3
        end
        [type, size, cursor]
      end

      def int_at(offset, length)
        return 0 if length.zero?

        @buf.byteslice(offset, length).unpack("C*").inject(0) { |acc, b| (acc << 8) | b }
      end

      # Resolves a pointer at `offset` to the offset it points at, for kind
      # inspection.
      def follow(offset)
        ctrl = byte(offset)
        return offset unless (ctrl >> 5) == 1

        target, = pointer_target(offset, @data_start)
        target
      end

      def pointer_target(offset, base)
        ctrl = byte(offset)
        size = (ctrl >> 3) & 0x3
        value = ctrl & 0x7
        cursor = offset + 1
        pointer = case size
                  when 0 then (value << 8) | byte(cursor)
                  when 1 then ((value << 16) | int_at(cursor, 2)) + 2048
                  when 2 then ((value << 24) | int_at(cursor, 3)) + 526_336
                  else int_at(cursor, 4)
                  end
        [base + pointer, cursor + size + 1]
      end

      # Returns [value, next_offset]. `base` is what pointers are relative to:
      # the data section for records, the metadata section for metadata.
      def decode(offset, base)
        ctrl = byte(offset)
        return pointer_value(offset, base) if (ctrl >> 5) == 1

        type, size, cursor = control(offset)
        case type
        when 2 then [@buf.byteslice(cursor, size).force_encoding(Encoding::UTF_8), cursor + size]
        when 5, 6, 9 then [int_at(cursor, size), cursor + size]
        when 7 then decode_map(size, cursor, base)
        when 11 then decode_array(size, cursor, base)
        when 14 then [size == 1, cursor]
        else raise "unsupported MMDB type #{type} at offset #{offset}"
        end
      end

      def pointer_value(offset, base)
        target, after = pointer_target(offset, base)
        value, = decode(target, base)
        [value, after]
      end

      def decode_map(size, cursor, base)
        map = {}
        size.times do
          key, cursor = decode(cursor, base)
          value, cursor = decode(cursor, base)
          map[key] = value
        end
        [map, cursor]
      end

      def decode_array(size, cursor, base)
        list = []
        size.times do
          value, cursor = decode(cursor, base)
          list << value
        end
        [list, cursor]
      end
    end
  end
end
