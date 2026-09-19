# frozen_string_literal: true

# The published per-ASN `country` (asn-categories.csv). CC0 sources only; see
# the data repo's DECISIONS.md D-SRC-2 (country).
#
# Until 2026-09 the column carried ipverse as-metadata `countryCode`, which
# ipverse sources "from regional internet registries (RIR)": registry data
# under the RIRs' terms, which ipverse's CC0 cannot license (the same finding
# as the org names). It is now filled, first hit wins, from:
#   1. data/overrides/asn_country.txt: our curated, sourced lines. A line
#      whose code is `--` publishes NO country for that ASN and stops the
#      Wikidata fallback (a Wikidata value we checked and found wrong, or a
#      group item linked to a subsidiary's ASN we cannot place).
#   2. Wikidata: P17 (else P159 -> P17) of the ASN's admitted P3797 item,
#      refined for occupied territories
#      (lib/wikidata_countries.rb)
# An ASN with neither has an empty country. That is an honest blank, never a
# guess. Nothing from ipverse's countryCode may reach the CSV; the tripwire is
# test/country_test.rb.
#
# Meaning: the country the ASN's operator is based in (seat or headquarters),
# ISO 3166-1 alpha-2. This is close to the registry country it replaces but
# not identical: a subsidiary's ASN linked to its group's Wikidata item gets
# the group's country unless asn_country.txt says otherwise.
#
# OCCUPIED AND BREAKAWAY TERRITORIES (coordinator decision CD-19a): an
# operator based in one of them gets the internationally recognised (UN)
# state, never the de facto controller's code. asn_country.txt marks such a
# line `# territory: <key>; src: ...`; the key must be one of TERRITORY_STATES
# and the code must be that state, or the build fails. The de facto
# controller is recorded in the enrichment dossier, not here.

require_relative "env"

module OpenASNPipeline
  module Countries
    # territory key (asn_country.txt `territory:` tag) -> recognised state.
    TERRITORY_STATES = {
      "crimea" => "UA", "sevastopol" => "UA", "donetsk" => "UA", "luhansk" => "UA",
      "zaporizhzhia" => "UA", "kherson" => "UA",
      "abkhazia" => "GE", "south_ossetia" => "GE",
      "transnistria" => "MD",
      "northern_cyprus" => "CY"
    }.freeze

    # Codes that must never be published for an operator in a territory of
    # that state: the de facto controller's. A Wikidata item placed in the
    # territory whose own P17/P159 says anything outside {state, controller}
    # is treated as ambiguous and publishes nothing (lib/wikidata_countries.rb).
    DE_FACTO_CONTROLLERS = { "UA" => %w[RU], "GE" => %w[RU], "MD" => %w[RU], "CY" => %w[TR] }.freeze

    # asn_country.txt code for "publish no country, and no Wikidata fallback".
    NONE = "--"

    module_function

    # override: { asn => { "cc" (nil for `--`), "src", "territory"? } } (Overrides#countries)
    # wikidata: { asn => { "cc", "qid", "via" } } (WikidataCountries.for_asns)
    # -> { asn => { "cc", "source" } }, source "override" or "wikidata:<QID>:<via>"
    def merge(override, wikidata)
      out = {}
      (wikidata || {}).each do |asn, r|
        out[asn] = { "cc" => r["cc"], "source" => "wikidata:#{r['qid']}:#{r['via']}" }
      end
      (override || {}).each do |asn, r|
        if r["cc"].nil?
          out.delete(asn) # `--`: we looked, and publish nothing
        else
          out[asn] = { "cc" => r["cc"], "source" => "override" }
        end
      end
      check_territories!(override, out)
      out
    end

    # Belt and braces for CD-19a: whatever path a value took, an ASN tagged
    # with a territory publishes that territory's recognised state or nothing.
    def check_territories!(override, merged)
      (override || {}).each do |asn, r|
        next unless (key = r["territory"])

        state = TERRITORY_STATES.fetch(key)
        got = merged.dig(asn, "cc")
        next if got.nil? || got == state

        Env.fail_stage!("AS#{asn} (territory #{key}) would publish #{got.inspect}; CD-19a requires #{state}")
      end
    end

    # -> { "total" => n, "override" => n, "wikidata" => n }
    def source_counts(countries)
      counts = { "total" => countries.size, "override" => 0, "wikidata" => 0 }
      countries.each_value { |r| counts[r["source"].split(":").first] += 1 }
      counts
    end
  end
end
