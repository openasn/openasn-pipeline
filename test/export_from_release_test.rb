# frozen_string_literal: true

# `rake exports:from_release` (PRD §14): reproduce the exports from an
# already published snapshot, verify it thoroughly, and stay incapable of
# publishing what it produces.
#
# The interesting tests here are the refusals. A task that re-exports a
# downloaded release is, if it is careless, a route around every legal gate
# the project has: fetch nothing, check no license, run no drift gate, and
# hand the result to the publisher. So each fixture below breaks exactly
# one promise of the snapshot (a digest, a length, a missing input, a
# mismatched build id, an absent source catalogue) and asserts the task
# refuses by name, and two more assert that a SUCCESSFUL run still cannot
# be published.
#
# The release directories are packed by hand rather than produced by a
# build: the point is that the task must not trust the directory.

require_relative "test_helper"
require "digest"
require "json"
require_relative "../pipeline/export/from_release"

module OpenASNPipeline
  class ExportFromReleaseTest < Minitest::Test
    BUILD_TS = 1_789_755_195
    BUILD_ID = Time.at(BUILD_TS).utc.iso8601
    ISP_ACCESS = 65 # category isp, role access_provider

    def setup
      @dir = File.join(WORK_DIR, "test-#{name}")
      @release = File.join(@dir, "release")
      @output = File.join(@dir, "out")
      FileUtils.mkdir_p(@release)
    end

    def teardown
      FileUtils.rm_rf(@dir)
    end

    # --- the happy path --------------------------------------------------

    def test_a_complete_verified_snapshot_reproduces_its_exports
      write_release
      result = Export::FromRelease.call(input: @release, output: @output)

      assert_equal BUILD_ID, result.build_id
      assert_equal 2, result.run.counts.ipv4
      assert_equal 1, result.run.counts.ipv6
      assert_equal %w[openasn.csv.gz openasn.sqlite.gz], result.run.outputs.map(&:name)
      assert_path_exists File.join(@output, "openasn.csv")
      assert_path_exists File.join(@output, "openasn.sqlite")

      # The snapshot's own attribution and source catalogue, not today's.
      meta = JSON.parse(File.read(File.join(@output, "metadata.json")))
      assert_equal "Attribution for build #{BUILD_ID}\n", meta.fetch("attribution")
      assert_equal "sapics-origin-asn", JSON.parse(meta.fetch("sources")).first.fetch("id")
      assert_equal BUILD_ID, meta.fetch("build_id")
    end

    # --- and why it can never become a release ---------------------------

    def test_the_reproduction_records_unknown_revisions_and_a_dirty_tree
      write_release
      result = Export::FromRelease.call(input: @release, output: @output)
      meta = JSON.parse(File.read(File.join(@output, "metadata.json")))

      # Not today's HEAD: these bytes were compiled by some other checkout,
      # and claiming otherwise would be a false provenance claim.
      assert_equal "unknown", meta.fetch("data_repo_commit")
      assert_equal "unknown", meta.fetch("pipeline_repo_commit")
      assert_equal "true", meta.fetch("working_tree_dirty")

      reasons = Export::Metadata.nonpublishable_reasons(meta)
      refute_empty reasons
      assert_equal reasons, result.nonpublishable_reasons
    end

    def test_a_real_build_metadata_is_publishable_so_the_refusal_means_something
      # The guard above is only evidence if the same function accepts the
      # provenance a genuine build produces.
      meta = { "data_repo_commit" => "a" * 40, "pipeline_repo_commit" => "b" * 40,
               "working_tree_dirty" => "false" }

      assert_empty Export::Metadata.nonpublishable_reasons(meta)
      assert_equal ["working_tree_dirty is true"],
                   Export::Metadata.nonpublishable_reasons(meta.merge("working_tree_dirty" => "true"))
    end

    def test_the_output_carries_a_marker_naming_the_gates_that_did_not_run
      write_release
      result = Export::FromRelease.call(input: @release, output: @output)
      marker = File.read(result.marker)

      assert_equal File.join(@output, "NOT-PUBLISHABLE.txt"), result.marker
      assert_includes marker, BUILD_ID
      assert_includes marker, "license gate"
      assert_includes marker, "drift gate"
    end

    def test_it_refuses_to_run_at_all_while_publish_is_set
      write_release
      with_env("PUBLISH" => "1") do
        error = assert_raises(StageFailure) { Export::FromRelease.call(input: @release, output: @output) }
        assert_match(/cannot be published/, error.message)
      end
      refute_path_exists @output, "nothing may be written on the publishing path"
    end

    def test_it_refuses_to_write_into_the_release_directory
      write_release
      error = assert_raises(StageFailure) do
        Export::FromRelease.call(input: @release, output: File.join(DIST_DIR, "from-release"))
      end
      assert_match(/refuses to write into/, error.message)
    end

    # --- verification of the snapshot ------------------------------------

    def test_a_release_without_the_org_sidecar_fails_by_name
      write_release(omit: "openasn-orgs.bin")
      error = assert_raises(StageFailure) { Export::FromRelease.call(input: @release, output: @output) }

      assert_match(/lists no openasn-orgs\.bin/, error.message)
      assert_match(/does not carry an input the exports require/, error.message)
    end

    def test_a_release_without_its_attribution_fails_by_name
      write_release(omit: "ATTRIBUTION.md")
      error = assert_raises(StageFailure) { Export::FromRelease.call(input: @release, output: @output) }
      assert_match(/lists no ATTRIBUTION\.md/, error.message)
    end

    def test_a_tampered_input_fails_on_its_digest
      write_release
      path = File.join(@release, "ATTRIBUTION.md")
      File.write(path, "Attribution for build #{BUILD_ID}\nand one extra line\n")
      error = assert_raises(StageFailure) { Export::FromRelease.call(input: @release, output: @output) }

      # Length is checked first, so that is the honest failure to report.
      assert_match(/ATTRIBUTION\.md: \d+ bytes on disk, manifest says/, error.message)
    end

    def test_an_input_of_the_right_length_but_the_wrong_bytes_fails_on_its_digest
      write_release
      path = File.join(@release, "ATTRIBUTION.md")
      File.write(path, File.read(path).sub("Attribution", "attribution"))
      error = assert_raises(StageFailure) { Export::FromRelease.call(input: @release, output: @output) }

      assert_match(/sha256 .* does not match the manifest/, error.message)
      assert_match(/not the bytes this release published/, error.message)
    end

    def test_a_manifest_describing_another_build_fails
      write_release(build_id: "2020-01-01T00:00:00Z")
      error = assert_raises(StageFailure) { Export::FromRelease.call(input: @release, output: @output) }

      assert_match(/manifest\.json says build 2020-01-01T00:00:00Z but the artifacts carry #{BUILD_ID}/,
                   error.message)
    end

    def test_two_oasn_files_from_different_builds_fail_before_anything_is_written
      write_release(v6_build_ts: BUILD_TS + 60)
      error = assert_raises(StageFailure) { Export::FromRelease.call(input: @release, output: @output) }

      assert_match(/build timestamps differ/, error.message)
      refute_path_exists @output
    end

    def test_a_release_with_no_source_catalogue_fails
      write_release(sources: [])
      error = assert_raises(StageFailure) { Export::FromRelease.call(input: @release, output: @output) }
      assert_match(/cannot invent the source provenance/, error.message)
    end

    def test_a_directory_with_no_manifest_fails_before_reading_any_bytes
      write_release
      File.delete(File.join(@release, "manifest.json"))
      error = assert_raises(StageFailure) { Export::FromRelease.call(input: @release, output: @output) }
      assert_match(/has no manifest\.json/, error.message)
    end

    def test_a_corrupt_org_sidecar_fails_through_the_normal_input_validation
      write_release(orgs_bytes: "OORG\x01\x00\x00\x00\x00\x00\x09\x00\x00\x00\x09".b)
      error = assert_raises(StageFailure) { Export::FromRelease.call(input: @release, output: @output) }
      assert_match(/openasn-orgs\.bin/, error.message)
    end

    private

    def with_env(values)
      previous = values.to_h { |key, _| [key, ENV[key]] }
      values.each { |key, value| ENV[key] = value }
      yield
    ensure
      previous.each { |key, value| ENV[key] = value }
    end

    # A release directory as a consumer would unpack it: the three native
    # inputs, ATTRIBUTION.md, and a manifest that describes them.
    def write_release(omit: nil, build_id: BUILD_ID, sources: nil, v6_build_ts: BUILD_TS, orgs_bytes: nil)
      files = {
        "openasn-ipv4.bin" => oasn(:ipv4, BUILD_TS, base: [[0x01000000, 0x01000004, 100, ISP_ACCESS],
                                                           [0x02000000, 0x02000004, 200, ISP_ACCESS]]),
        "openasn-ipv6.bin" => oasn(:ipv6, v6_build_ts, base: [[1, 9, 300, ISP_ACCESS]]),
        "openasn-orgs.bin" => orgs_bytes || orgs(100 => "Access A", 200 => "Access B", 300 => "Six C"),
        "ATTRIBUTION.md" => "Attribution for build #{BUILD_ID}\n"
      }

      entries = files.map do |name, bytes|
        File.binwrite(File.join(@release, name), bytes)
        { "name" => name, "sha256" => Digest::SHA256.hexdigest(bytes), "bytes" => bytes.bytesize, "records" => 0 }
      end
      if omit
        entries.reject! { |entry| entry["name"] == omit }
        File.delete(File.join(@release, omit))
      end

      File.write(File.join(@release, "manifest.json"), JSON.pretty_generate(
        "format_version" => 1, "edition" => "core", "build_id" => build_id, "files" => entries,
        "sources" => sources || [{ "id" => "sapics-origin-asn", "url" => "https://example.invalid",
                                   "license" => "PDDL-1.0", "license_sha256" => "ab" * 32,
                                   "fetched_at" => "2026-09-01T00:00:00Z" }]
      ))
    end

    def oasn(family, build_ts, base: [])
      out = +"".b
      out << MAGIC.b << [FORMAT_VERSION, family == :ipv4 ? 0x04 : 0x06, 0].pack("CCn")
      out << [build_ts].pack("Q>") << [base.length, 0, 0, 0].pack("NNNN")
      base.each do |(s, e, asn, flags)|
        out << Binary.pack_addr(s, family) << Binary.pack_addr(e, family) << [asn, flags].pack("Nn")
      end
      out
    end

    def orgs(names)
      index = +"".b
      blob = +"".b
      names.sort.each do |(asn, name)|
        index << [asn, blob.bytesize].pack("NN")
        blob << name.b
      end
      Orgs::MAGIC.b + [Orgs::VERSION, 0, 0].pack("CCn") + [names.length, blob.bytesize].pack("NN") + index + blob
    end
  end
end
