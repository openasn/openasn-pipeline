# frozen_string_literal: true

require "json"
require_relative "../../lib/env"
require_relative "../../lib/http"

module OpenASNPipeline
  module Quant
    # APNIC AS-Pop — estimated end-user ("eyeball") population per ASN, derived by
    # APNIC Labs from Google-ads sampling over a rolling 60-day window. Best OPEN
    # proxy for "how many real users sit behind this AS" (corrects for NAT/legacy
    # allocations far better than raw address counts). License (feed header, verbatim):
    # "(C) APNIC Pty/Ltd. Re-use with attribution permitted" -> CC0-safe as derived
    # facts + attribution (D-ENRICH-6). Credit APNIC in ATTRIBUTION.md.
    #
    # Source: https://stats.labs.apnic.net/cgi-bin/aspop?f=j  (JSON)
    #   { "Date","Window","Data":[ { "rank","AS","Description","CC","Users",
    #     "Percent of CC Pop","Percent of Internet","Samples" } ] }
    #
    # CRITICAL PARSING NUANCE (fixed 2026-07-08 after the adversarial audit found a
    # last-wins bug): the feed is ONE ROW PER (AS, economy), NOT per AS. ~1,622 ASNs
    # span multiple economies, each row carrying only that economy's user count, and
    # the array is globally sorted by descending Users — so a naive `out[asn]=row`
    # keeps each AS's SMALLEST economy and undercounts multinationals by up to 6
    # orders of magnitude. We therefore AGGREGATE per AS: sum Users and
    # Percent-of-Internet across all its economy rows, and recompute a global
    # `eyeball_rank` by total users. Only ASNs with a measurable user population
    # appear (~39k), so an absent ASN = "no eyeball signal", not zero users -> nil.
    module Apnic
      URL = "https://stats.labs.apnic.net/cgi-bin/aspop?f=j"

      module_function

      # Parse the feed body -> { asn(Integer) => Hash }. Pure; offline-testable.
      def parse(body)
        agg = {}
        (JSON.parse(body)["Data"] || []).each do |e|
          asn = Integer(e["AS"].to_s, exception: false) or next
          a = (agg[asn] ||= { "eyeball_users" => 0, "eyeball_pct_internet" => 0.0 })
          a["eyeball_users"] += (e["Users"] || 0)
          a["eyeball_pct_internet"] += (e["Percent of Internet"] || 0.0)
        end
        # Global eyeball rank = position when ASNs are sorted by TOTAL users (dense,
        # 1-based). Cleaner + correct-per-AS vs the feed's per-(AS,economy) row rank.
        agg.sort_by { |_asn, a| -a["eyeball_users"] }.each_with_index do |(_asn, a), i|
          a["eyeball_rank"] = i + 1
          a["eyeball_pct_internet"] = a["eyeball_pct_internet"].round(4)
        end
        agg
      end

      def fetch_all(http: Http.new)
        parse(File.read(http.fetch(URL, "quant/apnic-aspop.json")))
      rescue StandardError => e
        Env.warn("quant/apnic: failed (#{e.message}); continuing")
        {}
      end
    end
  end
end
