# frozen_string_literal: true

# Curation aid: draft `data/overrides/org_names.txt` lines from the enrichment
# dossiers (docs/enrichment/dossiers-*.jsonl in the data repo, owner-private,
# extended tier). NEVER part of `rake build`: the output is a candidate file a
# human reviews and graduates into the data repo, like overrides:candidates.
#
#   ruby pipeline/tools/org_names_from_dossiers.rb path/to/dossiers.jsonl [more.jsonl]
#   -> build/work/candidates/org_names.txt  (+ a summary on stderr)
#
# WHY A DOSSIER NAME MAY ENTER THE CC0 CORE (and an ipverse description may
# not): each dossier was researched per record, one ASN at a time, and cites
# its evidence. An operator's name is a bare fact, and writing it down from a
# cited, per-record lookup is ordinary curation under D-CUR-1. That is not
# the same act as republishing a bulk copy of a registry's WHOIS table. The
# drafted line carries only the name and one source URL. It never carries
# dossier prose (extended tier, CC BY-SA by default under D-DATA-1).
#
# Source choice per line, strongest first. Only first-party pages or CC0/
# reference pages count as the citation. Registry and aggregator pages never
# do: RIR WHOIS/RDAP, PeeringDB, bgp.he.net, CAIDA AS Rank (whose names are
# AS2Org, which is WHOIS-derived), db-ip, and similar. A line must never rest
# on the kind of source it replaces.
#   1. an evidence URL on the operator's own domain (the same registrable
#      domain as org.website) or on Wikipedia/Wikidata, whose claim names this
#      ASN ("AS<n>"). It evidences the ASN->operator link itself
#   2. the operator's own website (org.website), which evidences the name
#   3. the operator's Wikidata item (CC0)
# A dossier with none of the three is skipped and counted.
#
# Name choice: org.display_name (the operator's common name, e.g. "Cogent
# Communications"), else org.legal_name. The legal name is often a holding
# parent rather than the operating registrant. Names are single-line and
# stripped of " # " (the comment delimiter).

require "json"
require "uri"
require "fileutils"
require_relative "../lib/env"
require_relative "../lib/wikidata_names"

module OpenASNPipeline
  module OrgNamesFromDossiers
    OUT = File.join(WORK_DIR, "candidates", "org_names.txt")

    module_function

    # dossier Hash -> [asn, name, src_url, basis] or nil (with reason)
    def draft(rec)
      asn = Integer(rec["asn"], exception: false) or return [nil, "bad_asn"]
      org = rec["org"] || {}
      name = clean(org["display_name"]) || clean(org["legal_name"])
      return [nil, "no_name"] unless name

      site_domain = registrable_domain(org["website"])
      first_party = (rec["evidence"] || []).select do |e|
        d = registrable_domain(e["url"])
        d && (d == site_domain || REFERENCE_DOMAINS.include?(d))
      end
      if (e = first_party.find { |ev| ev["claim"].to_s.match?(/\bAS#{asn}\b/) })
        return [[asn, name, e["url"], "evidence_names_asn"], nil]
      end
      if (site = org["website"].to_s).start_with?("http") && !WikidataNames.restricted_url?(site)
        return [[asn, name, site, "operator_website"], nil]
      end
      if (qid = rec.dig("external_ids", "wikidata_qid").to_s).match?(/\AQ\d+\z/)
        return [[asn, name, "https://www.wikidata.org/wiki/#{qid}", "wikidata_item"], nil]
      end

      [nil, "no_admissible_source"]
    end

    REFERENCE_DOMAINS = %w[wikipedia.org wikidata.org].freeze

    # "https://www.telekom.com/en" -> "telekom.com"; "www.bell.ca" -> "bell.ca".
    # Last two labels, or three when the second-level label is a generic one
    # (co.jp, com.au, ac.uk, ...). Good enough to match an operator's own pages.
    def registrable_domain(url)
      host = URI.parse(url.to_s).host.to_s.downcase.sub(/\Awww\./, "")
      return nil if host.empty?

      labels = host.split(".")
      n = labels.length >= 3 && labels[-2].match?(/\A(co|com|net|org|ac|ad|ne|or|go|gov|edu)\z/) ? 3 : 2
      labels.last(n).join(".")
    rescue URI::InvalidURIError
      nil
    end

    # Drop self-references to the ASN that some dossiers wrote into the display
    # name ("Lumen Technologies (CenturyLink) — AS209", "Verizon (UUNET / AS701)").
    def clean(s)
      s = s.to_s.gsub(/[[:cntrl:]]/, " ").gsub(" # ", " ")
      s = s.gsub(/\s*[—–-]\s*AS\d+\b/, "").gsub(%r{\s*/\s*AS\d+\b}, "")
           .gsub(/\bAS\d+\s*(,|\/)\s*/, "").gsub(/\s+AS\d+\b/, "").gsub(/\(\s*AS\d+\s*\)/, "")
      s = s.gsub(/\(\s*\)/, "").squeeze(" ").strip
      s.empty? ? nil : s
    end

    def line(asn, name, url, date) = "AS#{asn}  #{name}  # src: #{url} (#{date})"

    def run(paths, date: Time.now.utc.strftime("%Y-%m-%d"))
      drafted = {}
      skipped = Hash.new(0)
      basis = Hash.new(0)
      paths.each do |path|
        File.foreach(path) do |raw|
          next if raw.strip.empty?

          row, why = draft(JSON.parse(raw))
          if row
            drafted[row[0]] = row # later files win: pass the freshest dossier set last
          else
            skipped[why] += 1
          end
        end
      end
      drafted.each_value { |r| basis[r[3]] += 1 }
      FileUtils.mkdir_p(File.dirname(OUT))
      File.write(OUT, drafted.keys.sort.map { |a| line(*drafted[a][0, 3], date) }.join("\n") + "\n")
      warn "org_names_from_dossiers: #{drafted.size} drafted -> #{OUT}; basis #{basis.to_h}; skipped #{skipped.to_h}"
      drafted
    end
  end
end

OpenASNPipeline::OrgNamesFromDossiers.run(ARGV) if $PROGRAM_NAME == __FILE__
