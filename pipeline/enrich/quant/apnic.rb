# frozen_string_literal: true

require "json"
require_relative "../../lib/env"
require_relative "../../lib/http"

module OpenASNPipeline
  module Quant
    # APNIC AS-Pop — estimated end-user ("eyeball") population per ASN, derived by
    # APNIC Labs from Google-ads sampling over a rolling 60-day window. This is the
    # best OPEN proxy for "how many real users sit behind this AS" and corrects for
    # NAT/legacy allocations far better than raw announced-address counts (a /8 with
    # 3 users vs a /22 CGNAT behind millions). License, verbatim from the feed
    # header: "(C) APNIC Pty/Ltd. Re-use with attribution permitted" -> CC0-safe as
    # derived facts + attribution (D-ENRICH-6). Credit APNIC in ATTRIBUTION.md.
    #
    # Source: https://stats.labs.apnic.net/cgi-bin/aspop?f=j  (JSON)
    #   { "Date","Window","Data":[ { "rank","AS","Description","CC","Users",
    #     "Percent of CC Pop","Percent of Internet","Samples" } ] }
    # ONLY ASNs with a measurable user population appear (~70k of ~121k), so an
    # absent ASN means "no eyeball signal", NOT zero users -> leave the fields nil.
    module Apnic
      URL = "https://stats.labs.apnic.net/cgi-bin/aspop?f=j"

      module_function

      # Parse the feed body -> { asn(Integer) => Hash }. Pure; offline-testable.
      def parse(body)
        out = {}
        (JSON.parse(body)["Data"] || []).each do |e|
          asn = Integer(e["AS"].to_s, exception: false) or next
          out[asn] = {
            "eyeball_users"        => e["Users"],
            "eyeball_pct_internet" => e["Percent of Internet"],
            "eyeball_rank"         => e["rank"],
          }
        end
        out
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
