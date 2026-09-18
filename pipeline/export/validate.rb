# frozen_string_literal: true

# The cross-format gate (PRD §19.1 / §19.3 step 3): after the writers have
# finished, read the FINISHED FILES back and prove they say the same thing
# as the spool that produced them.
#
# The distinction that makes this worth its runtime: the writers validate
# their own inputs, this validates their outputs. A CSV that quoted a field
# wrong, a gzip that lost its last block, a database whose lookup query
# silently degraded to a table scan - none of those are visible from inside
# the writer that caused them. So everything here re-reads bytes from disk
# with an independent parser (stdlib CSV, Zlib::GzipReader, a read-only
# SQLite connection) and compares field by field, streamed, in order.
#
# Two invariants are re-derived from the DATA rather than trusted to the
# DDL, because a CHECK constraint can only see one row at a time:
#
#   * non-overlap: consecutive intervals in a family must not touch.
#   * maximal coalescing: two ADJACENT intervals must never carry an
#     identical payload, or the projection failed to merge them and the
#     export ships a boundary that means nothing.
#
# The SQLite half is delegated to sqlite.py's `verify` mode - not to save
# work, but because Ruby here is stdlib-only and has no SQLite engine at
# all. The engine that reads the file back is the one that wrote it, which
# is why the PHP/C# consumer examples exist as the genuinely independent
# readers.

require "csv"
require "digest"
require "ipaddr"
require "json"
require "zlib"
require_relative "../lib/env"
require_relative "contract"
require_relative "csv"
require_relative "gzip"
require_relative "metadata"
require_relative "sqlite"

module OpenASNPipeline
  module Export
    module Validate
      module_function

      # csv:/sqlite: are the RAW files, *_gz their transport-compressed
      # twins with the sha256/bytes that were advertised for them.
      def call(records:, metadata:, csv: nil, csv_gz: nil, sqlite: nil, sqlite_gz: nil)
        report = { "records" => records, "checks" => {} }
        meta = Metadata.validate!(JSON.parse(File.read(metadata)))
        report["checks"]["metadata"] = { "keys" => meta.keys.length }

        if csv
          report["checks"]["csv"] = validate_csv(csv, records: records, meta: meta)
          report["checks"]["csv_gz"] = validate_gzip(csv_gz, raw: csv) if csv_gz
        end

        if sqlite
          report["checks"]["sqlite"] = Sqlite.verify(database: sqlite, records: records, metadata: metadata)
          report["checks"]["sqlite_gz"] = validate_gzip(sqlite_gz, raw: sqlite) if sqlite_gz
        end

        report
      end

      # Every logical CSV record against the spool, in order, field by
      # field, with the addresses checked NUMERICALLY (IPAddr parses fine
      # even where it formats wrong) and the text checked against §11's
      # rules independently of the formatter that wrote it.
      def validate_csv(path, records:, meta:)
        counts = { 4 => 0, 6 => 0 }
        previous = { 4 => nil, 6 => nil }
        spool = File.open(records, "r")
        line_number = 0

        # Read as UTF-8, which is what the file claims to be: a binary read
        # would compare org names byte-string against the spool's UTF-8 and
        # "fail" on every accented name for no reason.
        File.open(path, "r:UTF-8") do |io|
          header = io.readline("\n")
          Env.fail_stage!("csv: file starts with a UTF-8 BOM") if header.start_with?("﻿")
          unless header == "#{Contract::CSV_HEADER}\n"
            Env.fail_stage!("csv: header is #{header.inspect}, expected the v1 header verbatim")
          end

          ::CSV.new(io, headers: Contract::CSV_HEADER.split(","), row_sep: "\n").each do |row|
            line_number += 1
            expected = spool.gets
            Env.fail_stage!("csv: record #{line_number} has no spool line") if expected.nil?

            compare_row(row, JSON.parse(expected), line_number)
            version = Integer(row.fetch("ip_version"))
            counts[version] += 1
            check_order(version, row, previous, line_number)
          end
        end

        leftover = spool.gets
        Env.fail_stage!("csv: the spool has records the CSV does not (#{leftover.byteslice(0, 120)})") if leftover
        spool.close

        %w[records_ipv4 records_ipv6].zip([4, 6]).each do |key, version|
          next if meta[key] == counts[version].to_s

          Env.fail_stage!("csv: metadata #{key} is #{meta[key]}, the CSV holds #{counts[version]}")
        end

        { "ipv4" => counts[4], "ipv6" => counts[6], "total" => counts[4] + counts[6],
          "bytes" => File.size(path), "sha256" => Digest::SHA256.file(path).hexdigest }
      end

      def compare_row(row, want, line_number)
        version = Integer(row.fetch("ip_version"))
        unless version == want.fetch("ip_version")
          Env.fail_stage!("csv line #{line_number}: ip_version #{version} != spool #{want['ip_version']}")
        end

        %w[start end].each do |edge|
          text = row.fetch("#{edge}_ip")
          value = Integer(want.fetch("#{edge}_hex"), 16)
          check_address_text(text, value, version, line_number, edge)
        end

        Contract::PAYLOAD_FIELDS.each do |name|
          got = cell_value(name, row.fetch(name.to_s))
          expected = want[name.to_s]
          next if got == expected

          Env.fail_stage!("csv line #{line_number}: #{name} is #{got.inspect}, spool says #{expected.inspect}")
        end
      end

      # IPAddr is trusted to PARSE (it is correct there) but never to
      # format: a value inside ::ffff:0:0/96 comes back from IPAddr#to_s as
      # an embedded dotted quad, which §11 forbids. So the numeric identity
      # is checked through IPAddr and the shape is checked directly.
      def check_address_text(text, value, version, line_number, edge)
        parsed = begin
          IPAddr.new(text)
        rescue IPAddr::Error => e
          Env.fail_stage!("csv line #{line_number}: #{edge}_ip #{text.inspect} does not parse (#{e.message})")
        end
        unless parsed.to_i == value
          Env.fail_stage!("csv line #{line_number}: #{edge}_ip #{text.inspect} is #{parsed.to_i}, spool says #{value}")
        end

        if version == 6
          Env.fail_stage!("csv line #{line_number}: #{edge}_ip #{text.inspect} is not lowercase") if text != text.downcase
          if text.include?(".")
            Env.fail_stage!("csv line #{line_number}: #{edge}_ip #{text.inspect} embeds dotted-quad notation; " \
                            "§11 requires pure hextets")
          end
          unless parsed.ipv6?
            Env.fail_stage!("csv line #{line_number}: #{edge}_ip #{text.inspect} parsed as IPv4")
          end
        elsif text.match?(/\A0\d|\.0\d/)
          Env.fail_stage!("csv line #{line_number}: #{edge}_ip #{text.inspect} has a leading zero octet")
        end
      end

      def cell_value(name, text)
        return nil if text.nil? || text.empty?

        case name
        when :asn then Integer(text, 10)
        when :core_sources then text.split("|")
        else
          if Contract::SIGNALS.include?(name)
            return true if text == "1"
            return false if text == "0"

            Env.fail_stage!("csv: #{name} is #{text.inspect}, expected 0 or 1")
          else
            text
          end
        end
      end

      # Family grouping, strict ordering, no overlap, and maximal
      # coalescing - all from the emitted text, with no DDL involved.
      def check_order(version, row, previous, line_number)
        start = IPAddr.new(row.fetch("start_ip")).to_i
        finish = IPAddr.new(row.fetch("end_ip")).to_i
        Env.fail_stage!("csv line #{line_number}: end precedes start") if finish < start

        last = previous[version]
        if last
          if start <= last[:end]
            Env.fail_stage!("csv line #{line_number}: interval #{start}..#{finish} overlaps the previous one " \
                            "(ending #{last[:end]})")
          end
          payload = row.fields[3..]
          if start == last[:end] + 1 && payload == last[:payload]
            Env.fail_stage!("csv line #{line_number}: adjacent to the previous interval with an identical " \
                            "payload; the projection must coalesce these")
          end
        end
        previous[version] = { end: finish, payload: row.fields[3..] }
      end

      # The .gz must decompress to EXACTLY the raw file: same length, same
      # digest, one member, nothing trailing. A truncated or double-member
      # gzip decompresses "fine" for a naive reader and silently loses rows.
      def validate_gzip(path, raw:)
        digest = Digest::SHA256.new
        bytes = 0
        File.open(path, "rb") do |io|
          reader = Zlib::GzipReader.new(io)
          while (chunk = reader.read(1 << 20))
            digest << chunk
            bytes += chunk.bytesize
          end
          trailing = reader.unused
          reader.finish
          if trailing && !trailing.empty?
            Env.fail_stage!("#{File.basename(path)}: #{trailing.bytesize} bytes follow the gzip member")
          end
        end

        expected = Digest::SHA256.file(raw).hexdigest
        unless digest.hexdigest == expected && bytes == File.size(raw)
          Env.fail_stage!("#{File.basename(path)}: decompresses to #{bytes} bytes / #{digest.hexdigest}, " \
                          "but #{File.basename(raw)} is #{File.size(raw)} bytes / #{expected}")
        end

        header = Gzip.header(path)
        unless header[3].ord.zero? && header[4, 4] == "\0\0\0\0".b
          Env.fail_stage!("#{File.basename(path)}: gzip header carries flags/mtime " \
                          "(#{header.unpack1('H*')}); it must be reproducible")
        end

        { "bytes" => File.size(path), "sha256" => Digest::SHA256.file(path).hexdigest,
          "uncompressed_bytes" => bytes, "uncompressed_sha256" => expected }
      end
    end
  end
end
