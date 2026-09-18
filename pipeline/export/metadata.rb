# frozen_string_literal: true

# The common export metadata (PRD §9 and §10.2): everything a consumer needs
# to decide whether it may read this file, plus the provenance that makes
# the answer auditable. It lands verbatim in SQLite's `meta` table and feeds
# the MMDB description, so it is assembled exactly once per build.
#
# THE ACYCLIC RULE, which is the only reason this is its own module: the
# metadata may not contain the hash of anything it is embedded in. The
# dependency order is
#
#   validated bytes + provenance + revisions -> spool + counts -> metadata
#     -> CSV/SQLite bytes -> export descriptors -> manifest.json -> SHA256SUMS
#
# so `records_ipv4`/`records_ipv6` are knowable here (the spool has already
# been streamed) while the output hashes and the final manifest are not.
# Embedding the manifest in SQLite would mean hashing a file that contains
# its own hash. Native input hashes and the attribution text are fine: they
# are upstream of everything here.
#
# EVERY VALUE IS TEXT. meta.v is a TEXT column, so an integer stored as an
# integer would read back as a number in one consumer and a string in
# another; integers are base-10 without leading zeros, booleans are the
# words true/false, and the JSON-valued keys are compact with lexically
# sorted object keys so two builds of the same data produce the same bytes.

require "json"
require "open3"
require "time"
require "zlib"
require_relative "../lib/env"
require_relative "contract"

module OpenASNPipeline
  module Export
    module Metadata
      # The complete key set for schema 1 revision 0. A build that cannot
      # fill one of these is a build that must not publish.
      REQUIRED_KEYS = %w[
        schema_version schema_revision classification_profile lookup_policy_version
        edition scope tier_b_included
        build_id built_at build_unix_ts
        records_ipv4 records_ipv6 records_total
        source_format_version input_layer_counts input_artifacts
        data_repo_commit pipeline_repo_commit working_tree_dirty
        exporter_version producer sources license attribution
      ].freeze

      # Keys whose value is canonical JSON rather than a bare scalar.
      JSON_KEYS = %w[input_layer_counts input_artifacts producer sources].freeze
      INTEGER_KEYS = %w[schema_version schema_revision lookup_policy_version build_unix_ts
                        records_ipv4 records_ipv6 records_total source_format_version].freeze
      BOOLEAN_KEYS = %w[tier_b_included working_tree_dirty].freeze

      # Allowed only when publishing is off, and only after saying so out
      # loud - a released file that claims `unknown` provenance is worse
      # than a failed build.
      UNKNOWN = "unknown"

      Context = Struct.new(:build_id, :build_unix_ts, :sources, :attribution, :producer,
                           :data_repo_commit, :pipeline_repo_commit, :working_tree_dirty,
                           keyword_init: true)

      module_function

      # Gathers everything that is NOT derived from the records themselves.
      # `sources` comes from the publisher's provenance helper so the export
      # and the manifest describe the same fetches; it is passed in rather
      # than reached for, because this module must stay usable before the
      # manifest exists at all.
      def context(snapshot:, sources:, attribution: File.read(Env.attribution_path),
                  producer: producer_versions, publishing: ENV["PUBLISH"] == "1")
        Context.new(
          build_id: Time.at(snapshot.build_ts).utc.iso8601,
          build_unix_ts: snapshot.build_ts,
          sources: sources,
          attribution: attribution,
          producer: producer,
          data_repo_commit: repo_commit(Env.data_repo, "data repo", publishing: publishing),
          pipeline_repo_commit: repo_commit(ROOT, "pipeline repo", publishing: publishing),
          working_tree_dirty: dirty?(Env.data_repo) || dirty?(ROOT)
        )
      end

      # snapshot: Export::Inputs::Snapshot, counts: Export::Spool::Counts.
      def build(snapshot:, counts:, context:)
        meta = {
          "schema_version" => integer(Contract::SCHEMA_VERSION),
          "schema_revision" => integer(Contract::SCHEMA_REVISION),
          "classification_profile" => Contract::CLASSIFICATION_PROFILE,
          "lookup_policy_version" => integer(Contract::LOOKUP_POLICY_VERSION),
          "edition" => Contract::EDITION,
          "scope" => Contract::SCOPE,
          "tier_b_included" => boolean(Contract::TIER_B_INCLUDED),
          "build_id" => context.build_id,
          # Same instant, twice, on purpose: `build_id` is the release
          # identity a consumer compares against its manifest, `built_at` is
          # the human-readable stamp it displays. They are equal by contract.
          "built_at" => context.build_id,
          "build_unix_ts" => integer(context.build_unix_ts),
          "records_ipv4" => integer(counts.ipv4),
          "records_ipv6" => integer(counts.ipv6),
          "records_total" => integer(counts.total),
          "source_format_version" => integer(FORMAT_VERSION),
          "input_layer_counts" => canonical_json(snapshot.layer_counts),
          "input_artifacts" => canonical_json(snapshot.artifacts.map(&:to_h)),
          "data_repo_commit" => context.data_repo_commit,
          "pipeline_repo_commit" => context.pipeline_repo_commit,
          "working_tree_dirty" => boolean(context.working_tree_dirty),
          "exporter_version" => Contract::EXPORTER_VERSION,
          "producer" => canonical_json(context.producer),
          "sources" => canonical_json(context.sources),
          # CC0 covers OpenASN's own contribution and output contract; the
          # upstream attribution notices travel with it, which is what the
          # next key is for.
          "license" => "CC0-1.0",
          "attribution" => context.attribution
        }

        validate!(meta)
        meta.sort.to_h
      end

      def validate!(meta)
        missing = REQUIRED_KEYS - meta.keys
        Env.fail_stage!("export metadata is missing #{missing.join(', ')}") unless missing.empty?
        extra = meta.keys - REQUIRED_KEYS
        Env.fail_stage!("export metadata has unknown key(s) #{extra.join(', ')}") unless extra.empty?

        meta.each do |key, value|
          unless value.is_a?(String)
            Env.fail_stage!("export metadata #{key} is #{value.class}, not a string (meta.v is TEXT)")
          end
          Env.fail_stage!("export metadata #{key} is empty") if value.empty?
        end
        INTEGER_KEYS.each do |key|
          unless meta[key].match?(/\A(0|[1-9][0-9]*)\z/)
            Env.fail_stage!("export metadata #{key} is #{meta[key].inspect}, not a base-10 integer")
          end
        end
        BOOLEAN_KEYS.each do |key|
          unless %w[true false].include?(meta[key])
            Env.fail_stage!("export metadata #{key} is #{meta[key].inspect}, not true/false")
          end
        end
        JSON_KEYS.each do |key|
          parsed = begin
            JSON.parse(meta[key])
          rescue JSON::ParserError => e
            Env.fail_stage!("export metadata #{key} is not JSON: #{e.message}")
          end
          unless canonical_json(parsed) == meta[key]
            Env.fail_stage!("export metadata #{key} is not canonical JSON (compact, sorted keys)")
          end
        end
        meta
      end

      def write(meta, path:)
        File.write(path, "#{JSON.pretty_generate(meta)}\n")
        path
      end

      # Compact, UTF-8, object keys lexically sorted at every depth; array
      # order is preserved because array order is meaning here (ordered
      # sources, ordered layer descriptors).
      def canonical_json(value) = JSON.generate(sort_keys(value))

      def sort_keys(value)
        case value
        when Hash  then value.map { |k, v| [k.to_s, sort_keys(v)] }.sort_by(&:first).to_h
        when Array then value.map { |item| sort_keys(item) }
        else value
        end
      end

      def integer(value)
        unless value.is_a?(Integer) && !value.negative?
          Env.fail_stage!("export metadata expected a nonnegative integer, got #{value.inspect}")
        end
        value.to_s
      end

      def boolean(value)
        Env.fail_stage!("export metadata expected a boolean, got #{value.inspect}") unless [true, false].include?(value)
        value.to_s
      end

      # The toolchain that produced the bytes. Go/mmdbwriter stay null until
      # the MMDB writer is enabled; null means "not used for this build",
      # which is different from "unknown".
      def producer_versions(python: nil)
        {
          "go" => nil,
          "mmdbwriter" => nil,
          "python" => python&.version,
          "python_command" => python&.command,
          "python_path" => python&.path,
          "ruby" => RUBY_VERSION,
          "sqlite" => python&.sqlite_version,
          "zlib" => Zlib.zlib_version
        }
      end

      def repo_commit(path, label, publishing:)
        commit = git(path, "rev-parse", "HEAD")
        return commit if commit&.match?(/\A[0-9a-f]{40}\z/)

        if publishing
          Env.fail_stage!("cannot read the #{label} commit at #{path}, and PUBLISH=1 - a published export " \
                          "must record exactly which revision produced it")
        end
        Env.warn("export metadata: #{label} at #{path} has no readable git revision; recording #{UNKNOWN}. " \
                 "This build must not be published.")
        UNKNOWN
      end

      # Ignored files (build/, docs/) are excluded by git itself, so this
      # asks exactly the question PRD §10.2 asks: are the TRACKED inputs
      # clean? A dirty local build is allowed and useful; a dirty published
      # one is not, and the publisher gates on this value.
      def dirty?(path)
        status = git(path, "status", "--porcelain")
        return true if status.nil?

        !status.empty?
      end

      def git(path, *arguments)
        stdout, _stderr, status = Open3.capture3("git", "-C", path.to_s, *arguments)
        status.success? ? stdout.strip : nil
      rescue Errno::ENOENT
        nil
      end
    end
  end
end
