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

    attr_reader :sets, :corrections

    def self.load(dir = Env.overrides_dir)
      new(dir)
    end

    def initialize(dir)
      @dir = dir
      @sets = FLAG_FILES.transform_values { |file| parse_asn_file(File.join(dir, file)) }
      @corrections = parse_corrections(File.join(dir, "corrections.yml"))
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
