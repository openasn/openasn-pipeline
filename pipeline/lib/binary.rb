# frozen_string_literal: true

# OASN binary artifact format v1 - writer and reference reader.
#
# This file is BYTE-EXACT LAW. The Ruby gem (openasn/ruby) implements an
# independent reader against the same spec (FORMAT.md at the repo root);
# any layout change here requires a FORMAT_VERSION bump and a coordinated
# gem release. Integers are big-endian (network order) throughout.
#
#   Header (32 bytes):
#     offset  size  field
#     0       4     magic = "OASN"
#     4       1     format_version = 0x01
#     5       1     address_family: 0x04 | 0x06
#     6       2     reserved (0x0000)
#     8       8     build_unix_ts (u64)
#     16      4     base_record_count (u32)
#     20      4     vpn_overlay_count (u32)
#     24      4     dc_overlay_count  (u32)
#     28      4     relay_overlay_count (u32)   # always 0 in the canonical
#                   artifact - relay data is Tier B, fetched client-side; the
#                   slot exists so future editions can ship prebuilt overlays
#                   without a format bump.
#
#   Layer 1 - base records, sorted by start, non-overlapping:
#     IPv4: start u32 · end u32 · asn u32 · flags u16   = 14 bytes
#     IPv6: start u128 · end u128 · asn u32 · flags u16 = 38 bytes
#
#   Layers 2/3/4 - vpn / dc / relay overlays, sorted, merged, anonymous:
#     IPv4: start u32 · end u32   =  8 bytes
#     IPv6: start u128 · end u128 = 32 bytes
#
#   flags (u16) bit layout:
#     bits 0-3   category:      0=nil 1=isp 2=hosting 3=business
#                               4=education_research 5=government_admin
#                               (6-15 reserved)
#     bits 4-7   network_role:  0=nil 1=tier1_transit 2=major_transit
#                               3=midsize_transit 4=access_provider
#                               5=content_network 6=stub (7-15 reserved)
#     bit 8      bad_asn        (brianhama/bad-asn-list membership)
#     bit 9      vpn_provider   (overrides: known VPN infrastructure ASN)
#     bit 10     mobile_carrier (overrides)
#     bit 11     enterprise_gw  (overrides: SWG/corporate egress ASN)
#     bit 12     cdn            (overrides)
#     bit 13     hosting_extra  (overrides: hosting missed by upstream category)
#     bits 14-15 reserved
#
# Provenance note: this widens the proven prototype format (13-byte records,
# u8 flags) to u16 flags + a real header; the packed-string + binary-search
# reading strategy is unchanged from the benchmarked prototype
# (19.2µs/lookup pure Ruby at 433k records).

require_relative "env"

module OpenASNPipeline
  module Binary
    HEADER_SIZE = 32

    FLAG_BAD_ASN       = 1 << 8
    FLAG_VPN_PROVIDER  = 1 << 9
    FLAG_MOBILE        = 1 << 10
    FLAG_ENTERPRISE_GW = 1 << 11
    FLAG_CDN           = 1 << 12
    FLAG_HOSTING_EXTRA = 1 << 13

    CATEGORY_MASK = 0x000F
    ROLE_SHIFT    = 4
    ROLE_MASK     = 0x00F0

    module_function

    def addr_size(family)  = family == :ipv4 ? 4 : 16
    def base_rec_size(family) = family == :ipv4 ? 14 : 38
    def overlay_rec_size(family) = family == :ipv4 ? 8 : 32

    def pack_addr(int, family)
      if family == :ipv4
        [int].pack("N")
      else
        [int >> 64, int & 0xFFFF_FFFF_FFFF_FFFF].pack("Q>Q>")
      end
    end

    def unpack_addr(bytes, family)
      if family == :ipv4
        bytes.unpack1("N")
      else
        hi, lo = bytes.unpack("Q>Q>")
        (hi << 64) | lo
      end
    end

    # base_rows:    sorted array of [start, end, asn, flags]
    # vpn/dc/relay: sorted arrays of [start, end]
    def write(path, family:, build_ts:, base_rows:, vpn_rows: [], dc_rows: [], relay_rows: [])
      verify_sorted_disjoint!(base_rows, "base")

      header = MAGIC.dup.b
      header << [FORMAT_VERSION, family == :ipv4 ? 0x04 : 0x06, 0].pack("CCn")
      header << [build_ts].pack("Q>")
      header << [base_rows.length, vpn_rows.length, dc_rows.length, relay_rows.length].pack("NNNN")

      File.open("#{path}.tmp", "wb") do |io|
        io.write(header)
        base_rows.each do |(s, e, asn, flags)|
          io.write(pack_addr(s, family), pack_addr(e, family), [asn, flags].pack("Nn"))
        end
        [vpn_rows, dc_rows, relay_rows].each do |rows|
          rows.each { |(s, e)| io.write(pack_addr(s, family), pack_addr(e, family)) }
        end
      end
      File.rename("#{path}.tmp", path)
      path
    end

    # Reference reader. Returns a Hash with header fields and lazily-sliced
    # layer strings + lookup helpers. Loads the whole file into memory
    # (artifacts are single-digit MB; that is the design).
    class Artifact
      attr_reader :family, :build_ts, :counts

      def initialize(path)
        data = File.binread(path)
        magic, version, fam, _reserved = data.unpack("a4CCn")
        raise "bad magic #{magic.inspect} in #{path}" unless magic == MAGIC
        raise "unsupported format_version #{version}" unless version == FORMAT_VERSION

        @family   = fam == 0x04 ? :ipv4 : :ipv6
        @build_ts = data[8, 8].unpack1("Q>")
        base_n, vpn_n, dc_n, relay_n = data[16, 16].unpack("NNNN")
        @counts = { base: base_n, vpn: vpn_n, dc: dc_n, relay: relay_n }

        asz  = Binary.addr_size(@family)
        brec = Binary.base_rec_size(@family)
        orec = Binary.overlay_rec_size(@family)

        offset = HEADER_SIZE
        @base = data[offset, base_n * brec];  offset += base_n * brec
        @vpn  = data[offset, vpn_n * orec];   offset += vpn_n * orec
        @dc   = data[offset, dc_n * orec];    offset += dc_n * orec
        @rel  = data[offset, relay_n * orec]; offset += relay_n * orec
        raise "trailing garbage: file #{data.bytesize} bytes, expected #{offset}" unless offset == data.bytesize

        @asz = asz
        @brec = brec
        @orec = orec
      end

      # -> [start, end, asn, flags] | nil
      def find_base(ip_int)
        find(@base, @brec, ip_int) do |off|
          s = Binary.unpack_addr(@base[off, @asz], @family)
          e = Binary.unpack_addr(@base[off + @asz, @asz], @family)
          asn, flags = @base[off + 2 * @asz, 6].unpack("Nn")
          [s, e, asn, flags]
        end
      end

      def in_vpn?(ip_int) = !find(@vpn, @orec, ip_int) { |off| off }.nil?
      def in_dc?(ip_int)  = !find(@dc, @orec, ip_int) { |off| off }.nil?

      def each_base
        (@counts[:base]).times do |i|
          off = i * @brec
          s = Binary.unpack_addr(@base[off, @asz], @family)
          e = Binary.unpack_addr(@base[off + @asz, @asz], @family)
          asn, flags = @base[off + 2 * @asz, 6].unpack("Nn")
          yield [s, e, asn, flags]
        end
      end

      private

      # Binary search over fixed-size records. Comparison happens on the raw
      # big-endian address bytes - for unsigned big-endian values, bytewise
      # String comparison IS numeric comparison, which is what lets one code
      # path serve IPv4 (4B) and IPv6 (16B) alike.
      def find(layer, rec_size, ip_int)
        n = layer.bytesize / rec_size
        key = Binary.pack_addr(ip_int, @family)
        lo = 0
        hi = n - 1
        while lo <= hi
          mid = (lo + hi) / 2
          off = mid * rec_size
          if key < layer[off, @asz]
            hi = mid - 1
          elsif key > layer[off + @asz, @asz]
            lo = mid + 1
          else
            return yield(off)
          end
        end
        nil
      end
    end

    def verify_sorted_disjoint!(rows, label)
      prev_end = -1
      rows.each do |r|
        Env.fail_stage!("#{label} layer not sorted/disjoint at start=#{r[0]} (prev_end=#{prev_end})") if r[0] <= prev_end
        Env.fail_stage!("#{label} layer has inverted range #{r[0]}..#{r[1]}") if r[1] < r[0]
        prev_end = r[1]
      end
    end
  end
end
