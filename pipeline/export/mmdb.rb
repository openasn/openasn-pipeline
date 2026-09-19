# frozen_string_literal: true

# The Ruby side of the MMDB export: it decides WHICH openasn-mmdb binary
# writes the release, drives its build/verify modes, and reports the
# toolchain versions the bytes depend on.
#
# The Go tool (tools/mmdbwriter) is a BUILD dependency, never a runtime one:
# nothing a consumer installs needs Go. It is compiled into the disposable
# build workspace rather than into the source tree, and never onto a path a
# release inventory looks at.
#
# Go is only required in `all` mode. A `none` or `portable` build must not
# need a Go toolchain to exist, which is why nothing here runs at require
# time and why the error, when Go is genuinely missing, names the mode that
# asked for it instead of failing somewhere inside a subprocess.
#
# Subprocesses are argument arrays, never shell strings - the same rule as
# the SQLite writer, and for the same reason: paths with spaces and JSON
# with quotes reach this code.

require "json"
require "open3"
require_relative "../lib/env"

module OpenASNPipeline
  module Export
    module Mmdb
      TOOL_DIR = File.expand_path("../../tools/mmdbwriter", __dir__)
      TOOL_NAME = "openasn-mmdb"
      DATABASE_TYPE = "OpenASN-Core-v1"

      Toolchain = Struct.new(:path, :go, :mmdbwriter, keyword_init: true) do
        def to_s = "#{path} (#{go}, mmdbwriter #{mmdbwriter})"
      end

      module_function

      # OPENASN_MMDB_TOOL wins if set (CI can prebuild once and reuse it);
      # otherwise the tool is compiled from the pinned module in this repo.
      def toolchain
        @toolchain ||= begin
          go = go_version
          path = ENV["OPENASN_MMDB_TOOL"]
          if path
            unless File.executable?(path)
              Env.fail_stage!("OPENASN_MMDB_TOOL=#{path} is not an executable file")
            end
          else
            path = build_tool!(go)
          end

          found = Toolchain.new(path: path, go: go, mmdbwriter: module_version("github.com/maxmind/mmdbwriter"))
          Env.log("export: mmdb writer will run as #{found}")
          found
        end
      end

      def build_tool!(go)
        Env.fail_stage!(mmdb_needs_go) if go.nil?

        path = File.join(WORK_DIR, "export-mmdb-tool", TOOL_NAME)
        FileUtils.mkdir_p(File.dirname(path))
        output, status = Open3.capture2e("go", "build", "-o", path, ".", chdir: TOOL_DIR)
        Env.fail_stage!("could not build the MMDB writer:\n#{output}") unless status.success?

        path
      end

      def mmdb_needs_go
        "export mode 'all' needs the Go toolchain to build #{TOOL_NAME} from #{TOOL_DIR}, and `go` is not " \
          "available. Install Go, set OPENASN_MMDB_TOOL=/path/to/#{TOOL_NAME}, or select a mode without MMDB."
      end

      # "go version go1.24.0 darwin/arm64" -> "go1.24.0", or nil when Go is
      # not installed. Recorded in metadata's producer block: the tree bytes
      # depend on the writer, and the writer depends on this compiler.
      def go_version
        stdout, _stderr, status = Open3.capture3("go", "version")
        return nil unless status.success?

        stdout.split[2]
      rescue Errno::ENOENT
        nil
      end

      # The pinned dependency version, read from the checked-in go.mod
      # rather than from a resolved module cache: go.mod/go.sum are the
      # lockfile, and what they pin is what a reproducing build gets.
      def module_version(module_path)
        line = File.readlines(File.join(TOOL_DIR, "go.mod")).find { |l| l.strip.start_with?("#{module_path} ") }
        line&.split&.last
      end

      # Versions for metadata's `producer` block. Resolving the toolchain
      # here (before the metadata is written) is deliberate: the description
      # embedded in the database is built from that metadata, so the tool
      # has to be known before anything is written, not after.
      def producer_versions
        found = toolchain
        { "go" => found.go, "mmdbwriter" => found.mmdbwriter }
      end

      def build(records:, metadata:, output:)
        run("build", "--records", records, "--metadata", metadata, "--output", output)
      end

      def verify(database:, records:, metadata:)
        run("verify", "--database", database, "--records", records, "--metadata", metadata)
      end

      def run(*arguments)
        tool = toolchain
        stdout, stderr, status = Open3.capture3(tool.path, *arguments)
        unless status.success?
          Env.fail_stage!("mmdb #{arguments.first} failed under #{tool.path}: " \
                          "#{stderr.strip.empty? ? "exit #{status.exitstatus}" : stderr.strip}")
        end
        # The gate counts (PRD §12.4 low/mapped prefix overlaps) come back on
        # stderr on a SUCCESSFUL run too; they belong in the build log so a
        # future violation is visible before it fails a nightly.
        stderr.each_line { |line| Env.log("mmdb: #{line.strip}") unless line.strip.empty? }
        JSON.parse(stdout)
      rescue JSON::ParserError
        Env.fail_stage!("mmdb #{arguments.first} returned unparseable output: #{stdout.inspect}")
      end

      def reset! = (@toolchain = nil)
    end
  end
end
