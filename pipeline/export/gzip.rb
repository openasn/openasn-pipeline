# frozen_string_literal: true

# Deterministic gzip for the transport-compressed exports (PRD §11).
#
# "Level 6, mtime 0, no original filename or comment header" is not a
# stylistic preference: `openasn.csv.gz` is hashed into manifest.json, and a
# build that produces different bytes for identical rows makes every
# downstream "did the data change?" question unanswerable. Two gzip fields
# are timestamps in disguise - MTIME and the original filename - and both
# default to something that moves.
#
# Measured on ruby 3.4.2 / zlib 1.2.12: `GzipWriter.new(io, 6,
# DEFAULT_STRATEGY)` with `mtime = 0` writes the header
# `1f 8b 08 00 00000000 00 03` (FLG=0 so no name and no comment, XFL=0,
# OS=3) and repeats byte-for-byte across runs. That is the whole reason we
# do NOT shell out to the gzip CLI: its header carries the source filename
# and its OS byte and deflate tuning vary by implementation.
#
# Byte identity is scoped to a RECORDED producer - Zlib::OS_CODE alone
# differs on a Windows builder - which is why metadata's `producer` block
# names the zlib version that wrote the file.

require "digest"
require "zlib"
require_relative "../lib/env"

module OpenASNPipeline
  module Export
    module Gzip
      LEVEL = 6
      CHUNK = 1 << 20

      Result = Struct.new(:path, :bytes, :sha256, keyword_init: true)

      module_function

      # Compresses `source` to `output` in bounded memory and returns the
      # digest of the exact bytes an end user will download.
      def compress(source, output:)
        Env.fail_stage!("gzip source missing: #{source}") unless File.file?(source)

        File.open(output, "wb") do |raw|
          gz = Zlib::GzipWriter.new(raw, LEVEL, Zlib::DEFAULT_STRATEGY)
          gz.mtime = 0
          begin
            # An explicit chunked loop rather than IO.copy_stream, so the
            # resident cost of compressing a 70MB CSV is one CHUNK and is
            # visible in the code rather than left to a helper's internals.
            File.open(source, "rb") do |io|
              while (chunk = io.read(CHUNK))
                gz.write(chunk)
              end
            end
          ensure
            gz.close
          end
        end

        Result.new(path: output, bytes: File.size(output), sha256: Digest::SHA256.file(output).hexdigest)
      end

      # The header a consumer (and our own C04 test) can assert on: no
      # timestamp, no filename, so identical payloads compress identically.
      def header(path) = File.binread(path, 10)
    end
  end
end
