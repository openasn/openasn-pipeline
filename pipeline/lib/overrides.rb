# frozen_string_literal: true

# Loader for data/overrides/ - OpenASN's own curated layer (CC0), the part
# of the dataset we own outright. It corrects and extends ipverse
# as-metadata with the classes it lacks (vpn_provider, mobile_carrier,
# enterprise_gateway, cdn) plus per-ASN corrections.
#
# CURATION DISCIPLINE, ENFORCED MECHANICALLY: every ASN line must carry a
# comment containing a source URL (or an explicit `src:` pointer). A line
# without provenance fails the build. This is what keeps the override layer
# reviewable in PRs and trustworthy years from now - "why is AS9009 here?"
# must always be answerable from the file itself.
#
# File format (one ASN per line):
#   AS9009  # M247 Europe SRL - NordVPN/major VPN infra. src: https://... (2026-07-04)
#
# org_names.txt format (one ASN per line; the published org name, CC0):
#   AS15169  Google  # src: https://peering.google.com/ (2026-09-19)
# The name is everything between the ASN and " # ". The source must be a
# first-party or CC0 page: a registry/aggregator host
# (WikidataNames::RESTRICTED_REF_HOSTS: RIR WHOIS/RDAP, PeeringDB, CAIDA, ...)
# fails the build, because a name resting on WHOIS is exactly what D-SRC-2
# took out of the core. These ASNs are NOT flag members: org_names never feeds
# all_asns (no gap-fill, no classification effect).
#
# asn_country.txt format (one ASN per line; the published `country` column):
#   AS15169  US  # src: https://about.google/intl/en/locations/ (2026-09-19)
#   AS201776 UA  # territory: crimea; src: https://... (2026-09-19)
#   AS9002   --  # none: <why the Wikidata value is not published>; src: https://... (2026-09-19)
# `--` publishes no country and stops the Wikidata fallback. A `territory:`
# tag (occupied / breakaway territory, lib/countries.rb TERRITORY_STATES)
# requires the recognised state's code (CD-19a).
# ISO 3166-1 alpha-2, upper case: the country the ASN's operator is based in
# (seat or headquarters), written down from the cited source. Same source rule
# as org_names.txt: a registry/aggregator host fails the build, because a
# country resting on WHOIS or RIR stats is exactly what D-SRC-2 (country) took
# out of the core. Not a flag file: no classification effect, never in all_asns.
#
# corrections.yml format (asn -> correction):
#   64496:
#     category: hosting          # one of: isp hosting business education_research
#                                #         government_admin none
#     network_role: stub         # optional; same vocabulary as ipverse or none
#     reason: "why upstream is wrong"
#     source_url: "https://..."
#     date: 2026-07-04

require "set"
require "yaml"
require_relative "env"
require_relative "asjson"
require_relative "wikidata_names"
require_relative "countries"

module OpenASNPipeline
  class Overrides
    FLAG_FILES = {
      vpn_provider: "vpn_provider.txt",
      hosting_extra: "hosting_extra.txt",
      mobile_carrier: "mobile_carrier.txt",
      enterprise_gateway: "enterprise_gateway.txt",
      cdn: "cdn.txt",
      eyeball_confirm: "eyeball_confirm.txt"
    }.freeze

    VALID_CATEGORIES = (AsJson::CATEGORY_CODES.keys.compact + ["none"]).freeze
    VALID_ROLES      = (AsJson::ROLE_CODES.keys.compact + ["none"]).freeze

    ORG_NAMES_FILE = "org_names.txt"
    COUNTRY_FILE = "asn_country.txt"
    ISO2 = /\A[A-Z]{2}\z/
    # User-assigned / reserved codes that name no country (XX is ipverse's
    # "unknown", ZZ the RIRs', EU/AP the RIRs' regional pseudo-codes).
    NOT_COUNTRIES = %w[XX ZZ EU AP AA QM QN QO QP QQ QR QS QT QU QV QW QX QY QZ].freeze
    MAX_ORG_NAME_CHARS = 200

    attr_reader :sets, :corrections, :org_names, :countries

    def self.load(dir = Env.overrides_dir)
      new(dir)
    end

    def initialize(dir)
      @dir = dir
      @sets = FLAG_FILES.transform_values { |file| parse_asn_file(File.join(dir, file)) }
      @corrections = parse_corrections(File.join(dir, "corrections.yml"))
      @org_names = parse_org_names(File.join(dir, ORG_NAMES_FILE))
      @countries = parse_countries(File.join(dir, COUNTRY_FILE))
      sanity_check!
    end

    def all_asns
      @sets.values.reduce(Set.new, :|) | @corrections.keys.to_set
    end

    private

    def parse_asn_file(path)
      return Set.new unless File.exist?(path)

      asns = Set.new
      File.foreach(path).with_index(1) do |line, lineno|
        stripped = line.strip
        next if stripped.empty? || stripped.start_with?("#")

        unless (m = stripped.match(/\AAS(\d+)\s*#\s*(.+)\z/))
          Env.fail_stage!("#{File.basename(path)}:#{lineno}: expected `AS<number>  # comment`, got: #{stripped.inspect}")
        end
        asn, comment = m[1].to_i, m[2]
        unless comment.match?(%r{https?://|\bsrc:}i)
          Env.fail_stage!("#{File.basename(path)}:#{lineno}: AS#{asn} has no source URL in its comment - " \
                          "every override line must be traceable (add `src: <url>`)")
        end
        Env.warn("#{File.basename(path)}:#{lineno}: duplicate AS#{asn}") if asns.include?(asn)
        asns << asn
      end
      asns
    end

# -> { asn => { "name" => String, "src" => url } }
def parse_org_names(path)
  return {} unless File.exist?(path)

  out = {}
  File.foreach(path, encoding: "UTF-8").with_index(1) do |line, lineno|
    stripped = line.strip
    next if stripped.empty? || stripped.start_with?("#")

    where = "#{ORG_NAMES_FILE}:#{lineno}"
    unless (m = stripped.match(/\AAS(\d+)\s+(.+?)\s+#\s*(.+)\z/))
      Env.fail_stage!("#{where}: expected `AS<number>  <name>  # src: <url> (<date>)`, got: #{stripped.inspect}")
    end
    asn, name, comment = m[1].to_i, m[2].strip, m[3]
    Env.fail_stage!("#{where}: AS#{asn} name is not valid UTF-8") unless name.valid_encoding?
    Env.fail_stage!("#{where}: AS#{asn} name longer than #{MAX_ORG_NAME_CHARS} chars") if name.length > MAX_ORG_NAME_CHARS
    url = comment[%r{https?://\S+}]
    Env.fail_stage!("#{where}: AS#{asn} has no source URL - every name must be traceable") unless url
    if WikidataNames.restricted_url?(url)
      Env.fail_stage!("#{where}: AS#{asn} cites #{url}, a registry/aggregator host - an org name must rest on a " \
                      "first-party or CC0 source (D-SRC-2), never on WHOIS or its repackagers")
    end
    Env.fail_stage!("#{where}: duplicate AS#{asn}") if out.key?(asn)
    out[asn] = { "name" => name.unicode_normalize(:nfc), "src" => url }
  end
  out
end

    # -> { asn => { "cc" => "US", "src" => url } }
    def parse_countries(path)
      return {} unless File.exist?(path)

      out = {}
      File.foreach(path, encoding: "UTF-8").with_index(1) do |line, lineno|
        stripped = line.strip
        next if stripped.empty? || stripped.start_with?("#")

        where = "#{COUNTRY_FILE}:#{lineno}"
        unless (m = stripped.match(/\AAS(\d+)\s+(\S+)\s+#\s*(.+)\z/))
          Env.fail_stage!("#{where}: expected `AS<number>  <CC>  # src: <url> (<date>)`, got: #{stripped.inspect}")
        end
        asn, cc, comment = m[1].to_i, m[2], m[3]
        if cc == Countries::NONE
          cc = nil # publish no country; stops the Wikidata fallback
        elsif !cc.match?(ISO2) || NOT_COUNTRIES.include?(cc)
          Env.fail_stage!("#{where}: AS#{asn} country #{cc.inspect} is not an ISO 3166-1 alpha-2 country code " \
                          "(or `#{Countries::NONE}` for none)")
        end
        territory = comment[/\bterritory:\s*([a-z_]+)/, 1]
        if comment.match?(/\bterritory:/) || territory
          state = Countries::TERRITORY_STATES[territory]
          Env.fail_stage!("#{where}: AS#{asn} territory #{territory.inspect} is not one of " \
                          "#{Countries::TERRITORY_STATES.keys.join(', ')}") unless state
          unless cc == state
            Env.fail_stage!("#{where}: AS#{asn} is in #{territory}; its country is the recognised state " \
                            "#{state}, not #{cc.inspect} (CD-19a)")
          end
        end
        url = comment[%r{https?://\S+}]
        Env.fail_stage!("#{where}: AS#{asn} has no source URL - every country must be traceable") unless url
        if WikidataNames.restricted_url?(url)
          Env.fail_stage!("#{where}: AS#{asn} cites #{url}, a registry/aggregator host - a country must rest on a " \
                          "first-party or CC0 source (D-SRC-2, country), never on WHOIS, RIR stats or their repackagers")
        end
        Env.fail_stage!("#{where}: duplicate AS#{asn}") if out.key?(asn)
        out[asn] = { "cc" => cc, "src" => url }
        out[asn]["territory"] = territory if territory
      end
      out
    end

    def parse_corrections(path)
      return {} unless File.exist?(path)

      raw = YAML.safe_load_file(path, permitted_classes: [Date]) || {}
      raw.to_h do |asn, fields|
        Env.fail_stage!("corrections.yml: key #{asn.inspect} is not an integer ASN") unless asn.is_a?(Integer)
        %w[reason source_url date].each do |req|
          Env.fail_stage!("corrections.yml: AS#{asn} missing required field `#{req}`") if fields[req].to_s.empty?
        end
        if fields["category"] && !VALID_CATEGORIES.include?(fields["category"])
          Env.fail_stage!("corrections.yml: AS#{asn} invalid category #{fields['category'].inspect}")
        end
        if fields["network_role"] && !VALID_ROLES.include?(fields["network_role"])
          Env.fail_stage!("corrections.yml: AS#{asn} invalid network_role #{fields['network_role'].inspect}")
        end
        [asn, fields]
      end
    end

    # Curation conflicts are bugs in OUR data - fail, don't guess.
    # An ASN cannot simultaneously be a confirmed eyeball network and VPN
    # infrastructure; if reality is genuinely mixed (an ISP that also sells
    # VPS), the answer is a corrections.yml entry + honest :unknown, never
    # membership in both lists.
    def sanity_check!
      infra = @sets[:vpn_provider] | @sets[:hosting_extra] | @sets[:enterprise_gateway] | @sets[:cdn]
      conflicts = @sets[:eyeball_confirm] & infra
      return if conflicts.empty?

      Env.fail_stage!("overrides conflict: ASNs in eyeball_confirm AND an infrastructure list: " \
                      "#{conflicts.to_a.sort.map { |a| "AS#{a}" }.join(', ')}")
    end
  end
end
