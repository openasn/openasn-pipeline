# frozen_string_literal: true

# Export stage orchestration (PRD §14): validated snapshot in, validated
# output descriptors out.
#
# What this stage does NOT do is as important as what it does. It does not
# publish, upload, promote a directory, or decide that an artifact's
# existence means anything about permission. It writes into a staging
# directory it was handed and returns descriptors; whoever called it owns
# the release inventory and the only publication flag in the system.
#
# The order below is the acyclic dependency of PRD §9 and cannot be
# rearranged for convenience: the spool has to exist before the counts are
# known, the counts have to be in the metadata before a writer runs, and the
# output hashes only exist after the writers - which is precisely why no
# output hash may appear inside the metadata that the outputs embed.
#
# Raw .csv and .sqlite stay in staging. They are inputs to the transport
# gzip and to local installation, not a second pair of release assets, so
# the descriptors returned here are the .gz files with the raw name, size
# and digest recorded inside their export block.

require "digest"
require_relative "../lib/env"
require_relative "contract"
require_relative "csv"
require_relative "gzip"
require_relative "metadata"
require_relative "spool"
require_relative "sqlite"
require_relative "validate"

module OpenASNPipeline
  module Export
    module Run
      RECORDS_NAME  = "records.jsonl"
      METADATA_NAME = "metadata.json"

      # name/path/bytes/sha256/records plus the manifest `export` block
      # (PRD §15.3). The registry that assembles a release consumes these.
      Descriptor = Struct.new(:name, :path, :bytes, :sha256, :records, :export, keyword_init: true) do
        def to_h
          { "name" => name, "sha256" => sha256, "bytes" => bytes,
            "records" => records, "export" => export }
        end
      end

      Result = Struct.new(:mode, :records_path, :metadata_path, :counts, :outputs, :report,
                          keyword_init: true)

      module_function

      # snapshot: Export::Inputs.load result
      # context:  Export::Metadata.context result
      # mode:     Contract::EXPORT_MODES member
      # staging:  a build-owned directory; the writers only ever create
      #           files inside it and refuse to overwrite anything.
      def call(snapshot:, context:, staging:, mode: "portable")
        unless Contract::EXPORT_MODES.include?(mode)
          Env.fail_stage!("export mode #{mode.inspect} is not one of #{Contract::EXPORT_MODES.join('/')}")
        end
        return Result.new(mode: mode, counts: nil, outputs: [], report: nil) if mode == "none"

        # The MMDB writer is a later work package. Failing here, before any
        # work, is the point of having a mode vocabulary at all: a build
        # asking for `all` must not quietly ship two of the three formats.
        Env.fail_stage!("export mode 'all' requires the MMDB writer: MMDB not yet implemented") if mode == "all"

        FileUtils.mkdir_p(staging)
        records_path  = File.join(staging, RECORDS_NAME)
        metadata_path = File.join(staging, METADATA_NAME)
        [records_path, metadata_path].each do |path|
          Env.fail_stage!("export staging is not clean: #{path} already exists") if File.exist?(path)
        end

        started = Time.now
        counts = Spool.write(snapshot, path: records_path)
        Env.log("export: spooled #{counts.total} effective intervals " \
                "(ipv4=#{counts.ipv4} ipv6=#{counts.ipv6}, #{counts.bytes} bytes)")

        meta = Metadata.build(snapshot: snapshot, counts: counts, context: context)
        Metadata.write(meta, path: metadata_path)

        outputs = []
        outputs << write_csv(records_path, staging: staging, counts: counts)
        outputs << write_sqlite(records_path, metadata_path, staging: staging, counts: counts)

        report = Validate.call(records: records_path, metadata: metadata_path,
                               csv: File.join(staging, "openasn.csv"),
                               csv_gz: File.join(staging, "openasn.csv.gz"),
                               sqlite: File.join(staging, "openasn.sqlite"),
                               sqlite_gz: File.join(staging, "openasn.sqlite.gz"))

        outputs.each do |output|
          Env.log("export PASS #{output.export.fetch('format')} build=#{context.build_id} " \
                  "rows4=#{counts.ipv4} rows6=#{counts.ipv6} bytes=#{output.bytes} " \
                  "raw_bytes=#{output.export.dig('uncompressed', 'bytes')} sha256=#{output.sha256}")
        end
        Env.log(format("export: %s complete in %.1fs", mode, Time.now - started))

        Result.new(mode: mode, records_path: records_path, metadata_path: metadata_path,
                   counts: counts, outputs: outputs, report: report)
      end

      def write_csv(records_path, staging:, counts:)
        raw = Csv.write(records_path, path: File.join(staging, "openasn.csv"))
        unless [raw.ipv4, raw.ipv6] == [counts.ipv4, counts.ipv6]
          Env.fail_stage!("csv wrote #{raw.ipv4}/#{raw.ipv6} records, the spool holds #{counts.ipv4}/#{counts.ipv6}")
        end
        gz = Gzip.compress(raw.path, output: "#{raw.path}.gz")

        descriptor(gz, raw_name: "openasn.csv", raw_bytes: raw.bytes, raw_sha256: raw.sha256,
                   counts: counts, format: "csv", media_type: "text/csv; charset=utf-8")
      end

      def write_sqlite(records_path, metadata_path, staging:, counts:)
        output = File.join(staging, "openasn.sqlite")
        report = Sqlite.build(records: records_path, metadata: metadata_path, output: output)
        rows = report.fetch("rows")
        unless [rows["v4"], rows["v6"]] == [counts.ipv4, counts.ipv6]
          Env.fail_stage!("sqlite holds #{rows['v4']}/#{rows['v6']} rows, the spool holds " \
                          "#{counts.ipv4}/#{counts.ipv6}")
        end
        gz = Gzip.compress(output, output: "#{output}.gz")

        descriptor(gz, raw_name: "openasn.sqlite", raw_bytes: File.size(output),
                   raw_sha256: Digest::SHA256.file(output).hexdigest, counts: counts,
                   format: "sqlite", media_type: "application/vnd.sqlite3")
      end

      def descriptor(gz, raw_name:, raw_bytes:, raw_sha256:, counts:, format:, media_type:)
        Descriptor.new(
          name: File.basename(gz.path), path: gz.path, bytes: gz.bytes, sha256: gz.sha256,
          records: counts.total,
          export: {
            "format" => format,
            "media_type" => media_type,
            "content_encoding" => "gzip",
            "schema_version" => Contract::SCHEMA_VERSION,
            "schema_revision" => Contract::SCHEMA_REVISION,
            "classification_profile" => Contract::CLASSIFICATION_PROFILE,
            "lookup_policy_version" => Contract::LOOKUP_POLICY_VERSION,
            "scope" => Contract::SCOPE,
            "tier_b_included" => Contract::TIER_B_INCLUDED,
            "records_by_family" => { "ipv4" => counts.ipv4, "ipv6" => counts.ipv6 },
            "uncompressed" => { "name" => raw_name, "bytes" => raw_bytes, "sha256" => raw_sha256 }
          }
        )
      end
    end
  end
end
