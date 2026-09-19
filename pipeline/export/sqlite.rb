# frozen_string_literal: true

# The Ruby side of the SQLite export: it decides WHICH interpreter writes
# the release, drives sqlite.py, and reports the engine versions that the
# bytes depend on.
#
# This file exists because of a measured trap. On the development machine a
# bare `python3` resolves to /Library/Frameworks/Python.framework/Versions/
# 3.4/bin/python3, which is killed on startup (exit 137) - a build failure
# whose message would be "signal 9" and nothing else. And even among healthy
# interpreters the choice is not cosmetic: /usr/bin/python3 carries SQLite
# 3.43.2 and /opt/homebrew/bin/python3 carries 3.53.4, and two engine
# versions write physically different (equally valid) database files. PRD
# §17.1 scopes byte reproducibility to a RECORDED producer, which is only
# meaningful if the default is deterministic rather than "first on PATH".
#
# So: OPENASN_PYTHON wins if set, otherwise an ordered candidate list, and
# every candidate must pass a probe that imports sqlite3 and reports its
# versions before it is allowed anywhere near a release. The winner's path,
# `sys.version` and `sqlite3.sqlite_version` go into metadata's `producer`.
#
# Subprocesses are invoked as argument arrays (never a shell string): org
# names and JSON reach this code, and a path with a space is the least
# interesting thing a shell would do with them.

require "json"
require "open3"
require_relative "../lib/env"

module OpenASNPipeline
  module Export
    module Sqlite
      SCRIPT = File.expand_path("sqlite.py", __dir__)
      MINIMUM = [3, 9].freeze

      # Absolute paths first, in the order we want them chosen; bare
      # "python3" is the last resort precisely because PATH is what we are
      # defending against.
      CANDIDATES = %w[
        /usr/bin/python3
        /opt/homebrew/bin/python3
        /usr/local/bin/python3
        python3
      ].freeze

      PROBE = <<~PY
        import json, sqlite3, sys
        json.dump({"executable": sys.executable,
                   "version": sys.version.split()[0],
                   "version_full": sys.version,
                   "sqlite_version": sqlite3.sqlite_version}, sys.stdout)
      PY

      # `command` is what we invoke, `path` is what actually ran. On macOS
      # /usr/bin/python3 is a shim whose sys.executable points into Xcode;
      # the command is the stable thing to invoke and the executable is the
      # honest thing to record, so both are kept.
      Interpreter = Struct.new(:command, :path, :version, :sqlite_version, keyword_init: true) do
        def to_h = { "command" => command, "path" => path, "version" => version,
                     "sqlite_version" => sqlite_version }
        def to_s = "#{command} -> #{path} (python #{version}, sqlite #{sqlite_version})"
      end

      module_function

      # Returns the Interpreter that will write the database, or fails with
      # every candidate and the reason it was rejected.
      def interpreter
        @interpreter ||= begin
          override = ENV["OPENASN_PYTHON"]
          candidates = override ? [override] : CANDIDATES
          rejected = []
          found = nil

          candidates.each do |candidate|
            result = probe(candidate)
            if result.is_a?(Interpreter)
              found = result
              break
            end
            rejected << "#{candidate}: #{result}"
          end

          unless found
            Env.fail_stage!("no usable Python for the SQLite export (need >= #{MINIMUM.join('.')} with " \
                            "sqlite3). Tried:\n  #{rejected.join("\n  ")}\n" \
                            "Set OPENASN_PYTHON=/path/to/python3 to choose one explicitly.")
          end
          Env.log("export: sqlite writer will run under #{found}")
          found
        end
      end

      def probe(candidate)
        stdout, stderr, status = Open3.capture3(candidate, "-c", PROBE)
        return "exited #{status.exitstatus || status.to_s}: #{stderr.lines.first&.strip}" unless status.success?

        data = JSON.parse(stdout)
        version = data.fetch("version").split(".").map(&:to_i)
        return "python #{data['version']} is below #{MINIMUM.join('.')}" if (version <=> MINIMUM) < 0

        Interpreter.new(command: candidate, path: data.fetch("executable"), version: data.fetch("version"),
                        sqlite_version: data.fetch("sqlite_version"))
      rescue Errno::ENOENT
        "not found"
      rescue JSON::ParserError, KeyError => e
        "probe returned nothing usable (#{e.class})"
      end

      # `build --records --metadata --output`: writes the candidate database
      # and validates it in the same invocation. Returns the writer's
      # structured report.
      def build(records:, metadata:, output:)
        run("build", "--records", records, "--metadata", metadata, "--output", output)
      end

      # `verify --database --records --metadata`: re-validates a finished
      # database against the inputs it claims to describe.
      def verify(database:, records:, metadata:)
        run("verify", "--database", database, "--records", records, "--metadata", metadata)
      end

      def run(*arguments)
        python = interpreter
        stdout, stderr, status = Open3.capture3(python.command, SCRIPT, *arguments)
        unless status.success?
          Env.fail_stage!("sqlite #{arguments.first} failed under #{python}: " \
                          "#{stderr.strip.empty? ? "exit #{status.exitstatus}" : stderr.strip}")
        end
        Env.warn("sqlite #{arguments.first}: #{stderr.strip}") unless stderr.strip.empty?
        JSON.parse(stdout)
      rescue JSON::ParserError
        Env.fail_stage!("sqlite #{arguments.first} returned unparseable output: #{stdout.inspect}")
      end
    end
  end
end
