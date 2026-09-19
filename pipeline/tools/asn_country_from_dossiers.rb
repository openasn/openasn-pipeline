# frozen_string_literal: true

# Curation aid: draft `data/overrides/asn_country.txt` lines from the
# enrichment dossiers (docs/enrichment/dossiers-*.jsonl in the data repo,
# owner-private, extended tier). NEVER part of `rake build`. The output is a
# candidate file that a human reviews and graduates into the data repo, like
# org_names:draft (pipeline/tools/org_names_from_dossiers.rb, whose source
# rules this tool mirrors).
#
#   ruby pipeline/tools/asn_country_from_dossiers.rb path/to/dossiers.jsonl [more.jsonl]
#   -> build/work/candidates/asn_country.txt         lines ready for review
#      build/work/candidates/asn_country-review.txt  lines that need a closer look
#   (+ a summary on stderr)
#
# WHAT IS DRAFTED. The dossier's org.hq_country (ISO 3166-1 alpha-2): where
# the operator is based. That is the published meaning of the `country`
# column since D-SRC-2 (country). The line carries only the code and one
# source URL. It never carries dossier prose (extended tier).
#
# SOURCE CHOICE per line, strongest first. Only first-party pages or CC0/
# reference pages count. Registry and aggregator pages never do (RIR
# WHOIS/RDAP, PeeringDB, bgp.he.net, CAIDA, ...; WikidataNames::
# RESTRICTED_REF_HOSTS). A country must never rest on the kind of source it
# replaces.
#   1. an evidence URL on the operator's own domain or on Wikipedia/Wikidata
#      whose claim names the country (or the HQ city). It evidences the
#      location itself
#   2. the operator's Wikidata item (CC0; its P17/P159 is what a reviewer
#      checks)
#   3. the operator's own website (the reviewer checks its imprint/contact)
# A dossier with none of the three is skipped and counted.
#
# REVIEW SPLIT. If the build cache holds ipverse as-metadata, a draft whose
# code differs from the registry country goes to the review file instead
# (occupied territories, a group's country on a subsidiary's ASN, a bad
# dossier value). The registry value is CONSULTED here and never copied: it
# decides only which file a line lands in, it is not written into either
# file, and nothing in the build reads it (D-CUR-1 consultation; D-SRC-1).

require "json"
require "uri"
require "fileutils"
require_relative "../lib/env"
require_relative "../lib/asjson"
require_relative "../lib/overrides"
require_relative "../lib/wikidata_names"
require_relative "org_names_from_dossiers"

module OpenASNPipeline
  module AsnCountryFromDossiers
    OUT = File.join(WORK_DIR, "candidates", "asn_country.txt")
    REVIEW = File.join(WORK_DIR, "candidates", "asn_country-review.txt")
    REFERENCE_DOMAINS = OrgNamesFromDossiers::REFERENCE_DOMAINS

    # Names and demonyms a claim may use for a country. ISO 3166 short names
    # plus the forms dossier claims actually use. A code missing here can
    # still match through the HQ city.
    ALIASES = {
      "US" => ["United States", "US", "U.S.", "USA", "American", "US-based", "US-headquartered"],
      "GB" => ["United Kingdom", "UK", "U.K.", "British", "England", "Scotland", "Wales", "London"],
      "DE" => %w[Germany German], "FR" => %w[France French], "ES" => %w[Spain Spanish],
      "IT" => %w[Italy Italian], "NL" => ["Netherlands", "Dutch"], "BE" => %w[Belgium Belgian],
      "CH" => %w[Switzerland Swiss], "AT" => %w[Austria Austrian], "SE" => %w[Sweden Swedish],
      "NO" => %w[Norway Norwegian], "DK" => %w[Denmark Danish], "FI" => %w[Finland Finnish],
      "PL" => %w[Poland Polish], "CZ" => %w[Czechia Czech], "PT" => %w[Portugal Portuguese],
      "IE" => %w[Ireland Irish], "GR" => %w[Greece Greek], "RO" => %w[Romania Romanian],
      "RU" => %w[Russia Russian], "UA" => %w[Ukraine Ukrainian], "TR" => %w[Turkey Türkiye Turkish],
      "CN" => ["China", "Chinese", "PRC"], "HK" => ["Hong Kong"], "MO" => %w[Macau Macao],
      "TW" => %w[Taiwan Taiwanese], "JP" => %w[Japan Japanese], "KR" => ["South Korea", "Korea", "Korean"],
      "IN" => %w[India Indian], "ID" => %w[Indonesia Indonesian], "VN" => %w[Vietnam Vietnamese],
      "TH" => %w[Thailand Thai], "PH" => %w[Philippines Philippine Filipino], "MY" => %w[Malaysia Malaysian],
      "SG" => %w[Singapore Singaporean], "AU" => %w[Australia Australian], "NZ" => ["New Zealand"],
      "CA" => %w[Canada Canadian], "MX" => %w[Mexico Mexican], "BR" => %w[Brazil Brazilian],
      "AR" => %w[Argentina Argentine], "CL" => %w[Chile Chilean], "CO" => %w[Colombia Colombian],
      "PE" => %w[Peru Peruvian], "VE" => %w[Venezuela Venezuelan], "EC" => %w[Ecuador Ecuadorian],
      "ZA" => ["South Africa", "South African"], "NG" => %w[Nigeria Nigerian], "EG" => %w[Egypt Egyptian],
      "KE" => %w[Kenya Kenyan], "MA" => %w[Morocco Moroccan], "SA" => ["Saudi Arabia", "Saudi"],
      "AE" => ["United Arab Emirates", "UAE", "Emirati"], "IL" => %w[Israel Israeli], "IR" => %w[Iran Iranian],
      "PK" => %w[Pakistan Pakistani], "BD" => %w[Bangladesh Bangladeshi], "KZ" => %w[Kazakhstan Kazakh],
      "LU" => %w[Luxembourg], "HU" => %w[Hungary Hungarian], "BG" => %w[Bulgaria Bulgarian],
      "RS" => %w[Serbia Serbian], "HR" => %w[Croatia Croatian], "SK" => %w[Slovakia Slovak],
      "SI" => %w[Slovenia Slovenian], "LT" => %w[Lithuania Lithuanian], "LV" => %w[Latvia Latvian],
      "EE" => %w[Estonia Estonian], "BY" => %w[Belarus Belarusian], "GE" => %w[Georgia Georgian],
      "AM" => %w[Armenia Armenian], "AZ" => %w[Azerbaijan Azerbaijani], "UZ" => %w[Uzbekistan Uzbek],
      "IQ" => %w[Iraq Iraqi], "QA" => %w[Qatar Qatari], "KW" => %w[Kuwait Kuwaiti], "OM" => %w[Oman Omani],
      "CY" => %w[Cyprus Cypriot], "MT" => %w[Malta Maltese], "IS" => %w[Iceland Icelandic]
    }.freeze

    module_function

    # dossier Hash -> [[asn, cc, src_url, basis], nil] or [nil, reason]
    def draft(rec)
      asn = Integer(rec["asn"], exception: false) or return [nil, "bad_asn"]
      org = rec["org"] || {}
      cc = org["hq_country"].to_s.strip.upcase
      return [nil, "no_hq_country"] if cc.empty?
      return [nil, "bad_code"] if !cc.match?(Overrides::ISO2) || Overrides::NOT_COUNTRIES.include?(cc)

      site_domain = OrgNamesFromDossiers.registrable_domain(org["website"])
      matcher = claim_matcher(cc, org["hq_city"])
      first_party = (rec["evidence"] || []).select do |e|
        d = OrgNamesFromDossiers.registrable_domain(e["url"])
        d && (d == site_domain || REFERENCE_DOMAINS.include?(d)) && !WikidataNames.restricted_url?(e["url"].to_s)
      end
      if (e = first_party.find { |ev| ev["claim"].to_s.match?(matcher) })
        return [[asn, cc, e["url"], "evidence_names_country"], nil]
      end
      if (qid = rec.dig("external_ids", "wikidata_qid").to_s).match?(/\AQ\d+\z/)
        return [[asn, cc, "https://www.wikidata.org/wiki/#{qid}", "wikidata_item"], nil]
      end
      if (site = org["website"].to_s).start_with?("http") && !WikidataNames.restricted_url?(site)
        return [[asn, cc, site, "operator_website"], nil]
      end

      [nil, "no_admissible_source"]
    end

    def claim_matcher(cc, city)
      words = (ALIASES[cc] || []).dup
      words << city.to_s.split(",").first.to_s.strip if city.to_s.strip.length >= 3
      words.reject!(&:empty?)
      return /\A\z/ if words.empty? # matches no real claim

      /(?<![[:alnum:]])(?:#{words.map { |w| Regexp.escape(w) }.join('|')})(?![[:alnum:]])/
    end

    def line(asn, cc, url, date) = "AS#{asn}  #{cc}  # src: #{url} (#{date})"

    # Registry countries, consulted for the review split only. {} without a cache.
    def registry_countries
      path = File.join(CACHE_DIR, "ipverse", "as.json")
      return {} unless File.exist?(path)

      out = {}
      AsJson.each_record(path) { |r| out[r.asn] = r.country.to_s }
      out
    end

    def run(paths, date: Time.now.utc.strftime("%Y-%m-%d"), registry: registry_countries)
      drafted = {}
      skipped = Hash.new(0)
      paths.each do |path|
        File.foreach(path) do |raw|
          next if raw.strip.empty?

          row, why = draft(JSON.parse(raw))
          row ? drafted[row[0]] = row : skipped[why] += 1 # later files win
        end
      end
      ready, review = drafted.keys.sort.partition { |a| registry.empty? || registry[a] == drafted[a][1] }
      basis = drafted.values.map { |r| r[3] }.tally
      FileUtils.mkdir_p(File.dirname(OUT))
      File.write(OUT, ready.map { |a| line(*drafted[a][0, 3], date) }.join("\n") + "\n")
      File.write(REVIEW, review.map { |a| line(*drafted[a][0, 3], date) }.join("\n") + "\n")
      warn "asn_country_from_dossiers: #{ready.size} drafted -> #{OUT}; #{review.size} to review -> #{REVIEW}; " \
           "basis #{basis}; skipped #{skipped.to_h}"
      [drafted, ready, review]
    end
  end
end

OpenASNPipeline::AsnCountryFromDossiers.run(ARGV) if $PROGRAM_NAME == __FILE__
