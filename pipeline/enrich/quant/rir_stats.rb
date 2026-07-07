# frozen_string_literal: true

require_relative "../../lib/env"
require_relative "../../lib/http"

module OpenASNPipeline
  module Quant
    # RIR delegated-extended statistics — the authoritative bulk source for an
    # ASN's allocation date, owning RIR, registered country and status, plus an
    # opaque per-org hash that groups the ASNs one org holds (free sibling
    # detection). Published openly by each of the 5 RIRs for anyone to use; the
    # fields we keep are facts, CC0-safe.
    #
    # Line format: rir|cc|type|start|count|date|status|opaque-id   (type == "asn")
    # `date` is YYYYMMDD, or "00000000" for legacy/unknown allocations (e.g. the
    # single-digit ASNs) — those become allocated=nil (never a fabricated date).
    module RirStats
      FILES = {
        "arin"    => "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
        "ripencc" => "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
        "apnic"   => "https://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest",
        "lacnic"  => "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
        "afrinic" => "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
      }.freeze

      module_function

      # Parse a delegated-extended file body -> { asn(Integer) => Hash }. Pure.
      def parse(body)
        out = {}
        body.each_line do |line|
          f = line.split("|")
          next unless f[2] == "asn"      # only ASN records
          next if f[3] == "*"            # skip the "|*|asn|*|N|summary" header
          asn = Integer(f[3].to_s, exception: false) or next
          date = f[5].to_s
          out[asn] = {
            "rir"       => f[0],                                   # lowercase: arin/ripencc/...
            "country"   => (f[1].to_s.empty? || f[1] == "*" ? nil : f[1]),
            "allocated" => (date.length == 8 && date != "00000000" ? "#{date[0, 4]}-#{date[4, 2]}-#{date[6, 2]}" : nil),
            "status"    => f[6],
            "org_hash"  => f[7]&.strip,
          }
        end
        out
      end

      # Fetch all 5 RIR files (cached, conditional-GET, keep-last-good via Http)
      # and merge -> { asn => Hash }. A dead RIR warns and is skipped.
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
