# frozen_string_literal: true

# Stage 4: apply semantics and pack the artifacts.
#
#   1. Merge ipverse categories with our corrections + override flag sets
#      into a per-ASN u16 flags value (layout: lib/binary.rb / FORMAT.md).
#   2. Stamp flags onto every backbone range.
#   3. Gap-fill override ASNs that the BGP backbone doesn't carry, using
#      ipverse as-ip-blocks announced prefixes (the backbone stays
#      authoritative: we only fill space it does not already claim).
#   4. Write openasn-ipv4.bin / openasn-ipv6.bin into build/dist/.
#
# Precedence inside this stage (data precedence, not lookup precedence):
#   corrections.yml > eyeball_confirm.txt > ipverse as-metadata
# Lookup-time precedence between flags and overlays is the client's job
# (PRD §9); we just record every independent bit faithfully (PRD D10: the
# X4B VPN and DC overlays overlap only ~70% - they are independent signals,
# never a hierarchy).

require "set"
require_relative "lib/env"
require_relative "lib/ipmath"
require_relative "lib/binary"
require_relative "lib/asjson"
require_relative "lib/overrides"
require_relative "lib/sources"
require_relative "lib/http"
require_relative "lib/orgs"
require_relative "normalize" # for sanitize_overlaps! after gap-filling

module OpenASNPipeline
  module Compile
    # Politeness cap for per-ASN prefix fetches from ipverse. If overrides
    # ever list more missing ASNs than this, we fetch the first N (sorted,
    # deterministic) and warn - add caching time between builds rather than
    # hammering raw.githubusercontent.com in one run.
    MAX_AS_BLOCKS_FETCHES = 300

    module_function

    def run(normalized, overrides: Overrides.load, http: Http.new, offline: ENV["OFFLINE"] == "1")
      build_ts = Time.now.to_i
      meta     = normalized[:asn_meta]

      flags_by_asn = build_flags(meta, overrides, normalized[:bad_asns])

      base_v4 = stamp_flags(normalized[:base_v4], flags_by_asn)
      base_v6 = stamp_flags(normalized[:base_v6], flags_by_asn)

      fill_missing_override_asns!(base_v4, base_v6, overrides, flags_by_asn, http, offline)

      v4_path = File.join(DIST_DIR, "openasn-ipv4.bin")
      v6_path = File.join(DIST_DIR, "openasn-ipv6.bin")
      orgs_path = File.join(DIST_DIR, "openasn-orgs.bin")

      Binary.write(v4_path, family: :ipv4, build_ts: build_ts,
                   base_rows: base_v4,
                   vpn_rows: normalized[:vpn_v4],
                   dc_rows: normalized[:dc_v4])
      # X4B overlays are IPv4-only; the v6 artifact ships empty overlay
      # layers (count 0) and relies on ASN-level flags for VPN/hosting
      # signal. Documented lower confidence for v6 - see README.
      Binary.write(v6_path, family: :ipv6, build_ts: build_ts,
                   base_rows: base_v6, vpn_rows: [], dc_rows: [])
      # Org names ship as an optional sidecar (clients fetch it on refresh;
      # it is deliberately NOT part of the gem's bundled seed - size budget).
      Orgs.write(orgs_path, normalized[:asn_meta])

      Env.log("compiled: ipv4 #{File.size(v4_path) / 1024}KB (#{base_v4.length} base, " \
              "#{normalized[:vpn_v4].length} vpn, #{normalized[:dc_v4].length} dc) | " \
              "ipv6 #{File.size(v6_path) / 1024}KB (#{base_v6.length} base)")

      { build_ts: build_ts, v4_path: v4_path, v6_path: v6_path, orgs_path: orgs_path,
        base_v4: base_v4, base_v6: base_v6,
        flags_by_asn: flags_by_asn, overrides: overrides }
    end

    # ASN -> u16 flags. Only ASNs that end up nonzero are stored; the
    # default 0 means "no category, no role, no flags" (verdict :unknown).
    def build_flags(meta, overrides, bad_asns)
      flags = Hash.new(0)

      meta.each do |asn, rec|
        f = AsJson::CATEGORY_CODES.fetch(rec.category, 0)
        f |= AsJson::ROLE_CODES.fetch(rec.network_role, 0) << Binary::ROLE_SHIFT
        flags[asn] = f if f != 0
      end

      # eyeball_confirm: our curators verified this ASN is a real
      # residential/eyeball access network - force isp/access_provider.
      overrides.sets[:eyeball_confirm].each do |asn|
        flags[asn] = AsJson::CATEGORY_CODES["isp"] |
                     (AsJson::ROLE_CODES["access_provider"] << Binary::ROLE_SHIFT) |
                     (flags[asn] & ~(Binary::CATEGORY_MASK | Binary::ROLE_MASK))
      end

      # corrections.yml wins over everything upstream.
      overrides.corrections.each do |asn, fields|
        f = flags[asn]
        if (cat = fields["category"])
          f = (f & ~Binary::CATEGORY_MASK) | AsJson::CATEGORY_CODES.fetch(cat == "none" ? nil : cat)
        end
        if (role = fields["network_role"])
          f = (f & ~Binary::ROLE_MASK) | (AsJson::ROLE_CODES.fetch(role == "none" ? nil : role) << Binary::ROLE_SHIFT)
        end
        flags[asn] = f
      end

      bad_asns.each { |asn| flags[asn] |= Binary::FLAG_BAD_ASN }
      overrides.sets[:vpn_provider].each { |asn| flags[asn] |= Binary::FLAG_VPN_PROVIDER }
      overrides.sets[:mobile_carrier].each { |asn| flags[asn] |= Binary::FLAG_MOBILE }
      overrides.sets[:enterprise_gateway].each { |asn| flags[asn] |= Binary::FLAG_ENTERPRISE_GW }
      overrides.sets[:cdn].each { |asn| flags[asn] |= Binary::FLAG_CDN }
      overrides.sets[:hosting_extra].each { |asn| flags[asn] |= Binary::FLAG_HOSTING_EXTRA }

      flags
    end

    def stamp_flags(base_rows, flags_by_asn)
      base_rows.map { |(s, e, asn)| [s, e, asn, flags_by_asn[asn]] }
    end

    # Override ASNs with no backbone presence (commonly: VPN providers whose
    # v6 space isn't in origin-asn, or freshly assigned ASNs) get their
    # announced prefixes from ipverse as-ip-blocks - but ONLY into gaps the
    # backbone leaves. If origin-asn and as-ip-blocks disagree about who
    # announces a range, the BGP-derived backbone wins.
    def fill_missing_override_asns!(base_v4, base_v6, overrides, flags_by_asn, http, offline)
      flagged = overrides.sets.values_at(:vpn_provider, :hosting_extra, :mobile_carrier,
                                         :enterprise_gateway, :cdn).reduce(Set.new, :|)
      present = Set.new
      base_v4.each { |r| present << r[2] }
      base_v6.each { |r| present << r[2] }
      missing = (flagged - present).to_a.sort
      return if missing.empty?

      if missing.length > MAX_AS_BLOCKS_FETCHES
        Env.warn("#{missing.length} override ASNs missing from backbone; fetching first #{MAX_AS_BLOCKS_FETCHES} only")
        missing = missing.first(MAX_AS_BLOCKS_FETCHES)
      end
      Env.log("gap-filling #{missing.length} override ASNs absent from backbone: " \
              "#{missing.first(10).map { |a| "AS#{a}" }.join(', ')}#{missing.length > 10 ? ', …' : ''}")

      added = { ipv4: 0, ipv6: 0 }
      missing.each do |asn|
        { ipv4: base_v4, ipv6: base_v6 }.each do |family, base|
          suffix = family == :ipv4 ? "ipv4" : "ipv6"
          path = http.fetch_optional(format(Sources::IPVERSE_AS_BLOCKS_RAW, asn, suffix),
                                     "asblocks/#{asn}-#{suffix}.txt", offline: offline)
          next unless path

          covered = base.map { |r| [r[0], r[1]] } # sorted disjoint by construction
          File.foreach(path) do |line|
            stripped = line.strip
            next if stripped.empty? || stripped.start_with?("#")

            begin
              s, e, fam = IPMath.cidr_to_range(stripped)
            rescue IPAddr::Error
              next
            end
            next unless fam == family

            IPMath.subtract_covered(s, e, covered).each do |(gs, ge)|
              base << [gs, ge, asn, flags_by_asn[asn]]
              added[family] += 1
            end
          end
        end
        sleep(0.15) unless offline # politeness to raw.githubusercontent.com
      end

      [base_v4, base_v6].each do |base|
        base.sort_by!(&:first)
        # Gap-filled rows were computed against pre-insert coverage; two
        # missing ASNs claiming the same unrouted space could still collide
        # with each other, so re-run the sanitizer to guarantee disjointness.
        Normalize.sanitize_overlaps!(base, "post-gap-fill")
      end
      Env.log("gap-fill added #{added[:ipv4]} ipv4 + #{added[:ipv6]} ipv6 ranges")
    end
  end
end
