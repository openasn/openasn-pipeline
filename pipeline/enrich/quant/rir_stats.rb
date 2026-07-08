# frozen_string_literal: true

require_relative "../../lib/env"
require_relative "../../lib/http"

module OpenASNPipeline
  module Quant
    # RIR delegated-extended statistics — the authoritative bulk source for an ASN's
    # allocation date, owning RIR, registered country and status, plus an opaque
    # per-org hash that groups the ASNs one org holds (free sibling detection).
    # Published openly by each of the 5 RIRs; the fields we keep are facts, CC0-safe.
    #
    # Line format: rir|cc|type|start|count|date|status|opaque-id   (type == "asn")
    #
    # BLOCK EXPANSION (fixed 2026-07-08 after the adversarial audit): an asn record
    # with count>1 covers the CONTIGUOUS range [start, start+count) — e.g.
    # `apnic|JP|asn|2497|32|20020405|allocated|A91A7381` delegates AS2497..AS2528.
    # We MUST expand it: keying only on `start` (the old bug) left ~19,700 interior
    # block members with null allocated/status/org_hash and broke org_hash sibling
    # grouping. Every ASN in a block shares one row (same date/status/org_hash) — which
    # is exactly the sibling signal.
    #
    # Sentinels -> nil (never a fabricated value): date "00000000" and the Unix-epoch
    # "19700101" (impossible ASN allocation date); country "" / "*" / "ZZ" (RIR
    # "unknown"). `status` is .strip'd because 7-field lines (no opaque-id column)
    # leave a trailing newline on the last token.
    module RirStats
      FILES = {
        "arin"    => "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
        "ripencc" => "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
        "apnic"   => "https://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest",
        "lacnic"  => "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
        "afrinic" => "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
      }.freeze

      module_function

      # "" / whitespace -> nil (RIR lines can have an empty opaque-id column, e.g.
      # `arin||asn|940|1||reserved|` -> f[7]="" ; an empty org_hash is meaningless and
      # would falsely group unrelated reserved ASNs).
      def blank_nil(s) = (s.nil? || s.strip.empty?) ? nil : s.strip

      # Parse a delegated-extended file body -> { asn(Integer) => Hash }. Pure.
      def parse(body)
        out = {}
        body.each_line do |line|
          f = line.split("|")
          next unless f[2] == "asn"   # only ASN records
          next if f[3] == "*"         # skip the "|*|asn|*|N|summary" header
          start = Integer(f[3].to_s, exception: false) or next
          count = [f[4].to_i, 1].max
          date  = f[5].to_s
          cc    = f[1].to_s.strip
          row = {
            "rir"       => f[0],
            "country"   => (cc.empty? || cc == "*" || cc == "ZZ" ? nil : cc),
            "allocated" => (date.length == 8 && date != "00000000" && date != "19700101" ? "#{date[0, 4]}-#{date[4, 2]}-#{date[6, 2]}" : nil),
            "status"    => f[6]&.strip,
            "org_hash"  => blank_nil(f[7]),
          }
          # Expand the delegation block: every ASN in [start, start+count) shares row
          # (same allocation date/status/org_hash — this IS the sibling grouping).
          (start...(start + count)).each { |asn| out[asn] = row }
        end
        out
      end

      # Fetch all 5 RIR files (cached, conditional-GET, keep-last-good via Http) and
      # merge -> { asn => Hash }. A dead RIR warns and is skipped.
      def fetch_all(http: Http.new, only: nil)
        out = {}
        FILES.each do |rir, url|
          next if only && !only.include?(rir)
          begin
            path = http.fetch(url, "quant/rir/#{rir}.txt")
            out.merge!(parse(File.read(path)))
            Env.log("quant/rir: #{rir} -> #{out.size} ASNs cumulative")
          rescue StandardError => e
            Env.warn("quant/rir: #{rir} failed (#{e.message}); continuing")
          end
        end
        out
      end
    end
  end
end
