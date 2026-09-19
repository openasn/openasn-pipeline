# frozen_string_literal: true

# The internal JSONL spool (PRD §9): one line per effective interval, the
# single stream every export writer consumes.
#
# It is a BUILD PROTOCOL, not a release format - nobody downloads it - but
# it is written canonically anyway, because "the CSV and the SQLite disagree"
# is a bug that costs a day to find and a fixed byte stream is a bug that
# costs a diff. Fixed key order, compact UTF-8, IPv4 rows then IPv6 rows,
# each numerically ascending.
#
# Endpoints are FIXED-WIDTH LOWERCASE HEX, never JSON numbers: a 128-bit
# address in a JSON number field is a double the moment any consumer parses
# it with a default parser, and the corruption is silent for exactly the
# addresses nobody spot-checks. 8 hex characters for IPv4, 32 for IPv6, no
# 0x prefix, so a lexical sort of the spool is also a numeric sort.

require "digest"
require "json"
require_relative "../lib/env"
require_relative "contract"
require_relative "project"

module OpenASNPipeline
  module Export
    module Spool
      Counts = Struct.new(:ipv4, :ipv6, :bytes, :sha256, keyword_init: true) do
        def total = ipv4 + ipv6
        def to_h = { "ipv4" => ipv4, "ipv6" => ipv6, "total" => total,
                     "bytes" => bytes, "sha256" => sha256 }
      end

      module_function

      # Streams the projection of both families to `path` and returns the
      # per-family counts plus the digest of the exact bytes written. The
      # digest is computed as we write: re-reading the file to hash it would
      # hash whatever is on disk now, not what this build produced.
      def write(snapshot, path:)
        digest = Digest::SHA256.new
        bytes = 0
        counts = { ipv4: 0, ipv6: 0 }

        File.open(path, "wb") do |io|
          Contract::FAMILIES.each do |family|
            Project.each(snapshot, family: family) do |record|
              line = line_for(record)
              io.write(line)
              digest << line
              bytes += line.bytesize
              counts[family] += 1
            end
          end
        end

        Counts.new(ipv4: counts[:ipv4], ipv6: counts[:ipv6], bytes: bytes, sha256: digest.hexdigest)
      end

      def line_for(record)
        family = record.family
        row = {
          "ip_version" => Contract::IP_VERSIONS.fetch(family),
          "start_hex" => hex(record.start, family),
          "end_hex" => hex(record.end, family)
        }
        payload = record.payload
        Contract::PAYLOAD_FIELDS.each { |name| row[name.to_s] = payload[name] }
        "#{JSON.generate(row)}\n"
      end

      def hex(address, family)
        max = Contract::ADDRESS_MAX.fetch(family)
        if address.negative? || address > max
          Env.fail_stage!("#{family} endpoint #{address} is outside the family bound - an internal " \
                          "sweep sentinel must never reach serialization")
        end
        format("%0#{Contract::HEX_WIDTH.fetch(family)}x", address)
      end
    end
  end
end
