# frozen_string_literal: true

# The range CSV (PRD §11): one both-family UTF-8 file, header plus one line
# per effective interval, streamed straight from the JSONL spool.
#
# It reads the spool rather than the projection because CSV and SQLite must
# be provably the same rows: one producer, two serializers, and a validator
# that replays the spool against both. A second traversal of the sweep would
# be a second chance to disagree.
#
# THE ADDRESS TEXT IS WRITTEN HERE, BY HAND, ON PURPOSE. IPAddr#to_s renders
# anything inside ::ffff:0:0/96 as an embedded dotted quad - measured on
# ruby 3.4.2, `IPAddr.new(0x...ffff_0808_0808, AF_INET6).to_s` is
# "::ffff:8.8.8.8" - and §11 requires pure hextets. IPMath.int_to_v6 is
# built on IPAddr and inherits the defect, so CSV emission cannot use
# either. What follows is RFC 5952 §4 spelled out: lowercase, no leading
# zeros, compress the LONGEST run of two or more zero hextets, leftmost on
# a tie, never compress a single zero hextet, all-zero is "::".
#
# The quoting is hand-written too, for the same reason a fixed spool is:
# the writer must be decided by this file and not by a CSV library's
# defaults, which differ on whether a lone CR is quotable. It is ordinary
# RFC 4180 quoting (double the quotes, wrap if the field holds a comma,
# quote, CR or LF), and the tests parse the result back with the stdlib CSV
# parser, so "standard" is asserted rather than assumed. We deliberately do
# NOT prefix org names that begin with = + - @: spreadsheet formula
# sanitization mutates data, and this file is a data-import input.

require "digest"
require "json"
require_relative "../lib/env"
require_relative "contract"

module OpenASNPipeline
  module Export
    module Csv
      # Any of these in a field forces quoting (RFC 4180). CR is included
      # even though we never write CRLF line endings: a CR inside an org
      # name would otherwise split the record for a lenient parser.
      QUOTABLE = /["\r\n,]/
      # Rows are written in blocks so the digest and the file see the same
      # bytes without a syscall per record.
      FLUSH_ROWS = 4096

      Result = Struct.new(:path, :bytes, :sha256, :ipv4, :ipv6, keyword_init: true) do
        def total = ipv4 + ipv6
      end

      module_function

      # Streams `records_path` (the JSONL spool) to `path` and returns the
      # digest of the exact bytes written, plus the logical per-family
      # counts - logical, because an org name may contain a newline and the
      # physical line count is then simply wrong (PRD C03).
      def write(records_path, path:)
        digest = Digest::SHA256.new
        bytes = 0
        counts = { 4 => 0, 6 => 0 }
        seen_v6 = false
        previous = nil

        File.open(path, "wb") do |io|
          buffer = +"#{Contract::CSV_HEADER}\n"
          rows = 0

          File.foreach(records_path) do |json|
            row = JSON.parse(json)
            version = row["ip_version"]
            start_hex = row["start_hex"]

            # The spool promises family order and ascending endpoints; a CSV
            # whose order silently broke would still parse, and every
            # consumer doing a predecessor search would get wrong answers
            # for the addresses nobody spot-checks.
            case version
            when 4
              Env.fail_stage!("csv: an IPv4 record follows an IPv6 record at #{start_hex}") if seen_v6
            when 6
              previous = nil unless seen_v6
              seen_v6 = true
            else
              Env.fail_stage!("csv: record has ip_version #{version.inspect}")
            end
            if previous && start_hex <= previous
              Env.fail_stage!("csv: record starting at #{start_hex} follows #{previous}; the spool is " \
                              "unordered or overlapping (fixed-width lowercase hex sorts numerically)")
            end
            previous = row["end_hex"]

            buffer << line_for(row)
            counts[version] += 1
            rows += 1
            next unless (rows % FLUSH_ROWS).zero?

            io.write(buffer)
            digest << buffer
            bytes += buffer.bytesize
            buffer = +""
          end

          unless buffer.empty?
            io.write(buffer)
            digest << buffer
            bytes += buffer.bytesize
          end
        end

        Result.new(path: path, bytes: bytes, sha256: digest.hexdigest,
                   ipv4: counts.fetch(4), ipv6: counts.fetch(6))
      end

      # One spool object -> one CSV record, in CSV_HEADER order.
      def line_for(row)
        version = row.fetch("ip_version")
        out = +"#{version},#{address(row.fetch('start_hex'), version)},#{address(row.fetch('end_hex'), version)}"
        Contract::PAYLOAD_FIELDS.each { |name| out << "," << cell(name, row[name.to_s]) }
        out << "\n"
      end

      # Null is an empty cell, booleans are 0/1, core_sources is the ordered
      # list joined with a literal "|" (no frozen source token contains one),
      # everything else is its own text.
      def cell(name, value)
        case value
        when nil   then ""
        when true  then "1"
        when false then "0"
        when Array then field(join_sources(value))
        else            field(value.to_s)
        end
      end

      # The separator is safe only because the frozen source tokens contain
      # no "|". If a future profile ever allocated one, splitting this cell
      # would silently yield two sources, so the writer refuses instead.
      def join_sources(sources)
        sources.each do |token|
          next unless token.include?("|")

          Env.fail_stage!("csv: core_source #{token.inspect} contains the list separator; core-v1 tokens " \
                          "must not, and a consumer splitting this cell would invent an explanation")
        end
        sources.join("|")
      end

      def field(text)
        return text unless text.match?(QUOTABLE)

        %("#{text.gsub('"', '""')}")
      end

      def address(hex, version)
        value = Integer(hex, 16)
        version == 4 ? v4_text(value) : v6_text(value)
      end

      # Dotted decimal, no leading zeros (Integer#to_s never writes any).
      def v4_text(value)
        Env.fail_stage!("csv: #{value} is outside the IPv4 bound") unless value.between?(0, Contract::ADDRESS_MAX[:ipv4])

        "#{value >> 24}.#{(value >> 16) & 0xff}.#{(value >> 8) & 0xff}.#{value & 0xff}"
      end

      # RFC 5952 §4. See the file header for why this is not IPAddr#to_s.
      def v6_text(value)
        Env.fail_stage!("csv: #{value} is outside the IPv6 bound") unless value.between?(0, Contract::ADDRESS_MAX[:ipv6])

        hextets = Array.new(8) { |i| (value >> (16 * (7 - i))) & 0xffff }
        start, length = longest_zero_run(hextets)
        parts = hextets.map { |h| h.to_s(16) }
        return parts.join(":") unless start

        "#{parts[0, start].join(':')}::#{parts[(start + length)..].join(':')}"
      end

      # Leftmost longest run of at least two zero hextets, or nil. Strict >
      # is what makes a tie resolve leftmost; the >= 2 floor is what keeps a
      # single zero hextet spelled out ("0:1:0:1:0:1:0:1" is canonical).
      def longest_zero_run(hextets)
        best_start = nil
        best_length = 0
        index = 0
        while index < 8
          unless hextets[index].zero?
            index += 1
            next
          end

          finish = index
          finish += 1 while finish < 8 && hextets[finish].zero?
          length = finish - index
          if length >= 2 && length > best_length
            best_start = index
            best_length = length
          end
          index = finish
        end
        [best_start, best_length]
      end
    end
  end
end
