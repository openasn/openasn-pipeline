# frozen_string_literal: true

# The published per-ASN `country` (asn-categories.csv). CC0 sources only; see
# the data repo's DECISIONS.md D-SRC-2 (country).
#
# Until 2026-09 the column carried ipverse as-metadata `countryCode`, which
# ipverse sources "from regional internet registries (RIR)": registry data
# under the RIRs' terms, which ipverse's CC0 cannot license (the same finding
# as the org names). It is now filled, first hit wins, from:
#   1. data/overrides/asn_country.txt: our curated, sourced lines
#   2. Wikidata: P17 (else P159 -> P17) of the ASN's admitted P3797 item
#      (lib/wikidata_countries.rb)
# An ASN with neither has an empty country. That is an honest blank, never a
# guess. Nothing from ipverse's countryCode may reach the CSV; the tripwire is
# test/country_test.rb.
#
# Meaning: the country the ASN's operator is based in (seat or headquarters),
# ISO 3166-1 alpha-2. This is close to the registry country it replaces but
# not identical: a subsidiary's ASN linked to its group's Wikidata item gets
# the group's country.

module OpenASNPipeline
  module Countries
    module_function

    # override: { asn => { "cc", "src" } } (Overrides#countries)
    # wikidata: { asn => { "cc", "qid", "via" } } (WikidataCountries.for_asns)
    # -> { asn => { "cc", "source" } }, source "override" or "wikidata:<QID>:<P17|P159>"
    def merge(override, wikidata)
      out = {}
      (wikidata || {}).each do |asn, r|
        out[asn] = { "cc" => r["cc"], "source" => "wikidata:#{r['qid']}:#{r['via']}" }
      end
      (override || {}).each { |asn, r| out[asn] = { "cc" => r["cc"], "source" => "override" } }
      out
    end

    # -> { "total" => n, "override" => n, "wikidata" => n }
    def source_counts(countries)
      counts = { "total" => countries.size, "override" => 0, "wikidata" => 0 }
      countries.each_value { |r| counts[r["source"].split(":").first] += 1 }
      counts
    end
  end
end
