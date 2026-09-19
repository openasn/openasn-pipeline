# frozen_string_literal: true

# Validated adapter over the OASN v4/v6 artifacts and the OORG sidecar -
# the only door through which bytes enter an export (PRD §8.1).
#
# The exports materialize a verdict per interval, so a malformed input does
# not degrade gracefully here the way it does for a native client: it
# publishes a wrong answer to consumers who cannot see the bits. Hence every
# structural promise the format makes is re-checked, including the ones the
# writer already makes, because:
#
#   * Binary.write calls verify_sorted_disjoint! on the BASE layer ONLY.
#     vpn/dc/relay go out unchecked - they happen to be clean because
#     IPMath.merge_ranges coalesces them, which is a property of today's
#     normalize stage, not of the file format.
#   * reserved category/role codes and reserved flag bits 14-15 are
#     evidence core-v1 cannot name. A native reader is told to ignore
#     reserved bits; an EXPORT PRODUCER must refuse them, or it silently
#     publishes a guess. If upstream ever allocates them, that is a new
#     profile, not a dropped field.
#   * a nonzero relay layer is Tier B data appearing in canonical bytes.
#     core-v1 has no vocabulary for it and must not import it as a shortcut.
#
# OORG is optional for native clients and MANDATORY here: `as_org` is a
# published column, and an export that silently shipped 574k null names
# because a sidecar was missing would look like a data change rather than a
# broken build. A missing NAME for a present ASN is still just nil.
#
# The org index is loaded ONCE. Orgs.read(path, asn) re-reads the whole 4MB
# file per call; at 574k rows that is ~2.3TB of file reads for data that
# fits in a Hash.

require "digest"
require_relative "../lib/env"
require_relative "../lib/binary"
require_relative "../lib/orgs"
require_relative "contract"

module OpenASNPipeline
  module Export
    module Inputs
      # One address family's three canonical layers, already validated.
      Layers = Struct.new(:family, :base, :vpn, :dc) do
        def counts = { base: base.length, vpn: vpn.length, dc: dc.length, relay: 0 }
      end

      Descriptor = Struct.new(:name, :sha256, :bytes) do
        def to_h = { "name" => name, "sha256" => sha256, "bytes" => bytes }
      end

      # ASN -> org name, resolved once into memory.
      class OrgIndex
        attr_reader :count

        def initialize(names)
          @names = names
          @count = names.size
        end

        def name_for(asn) = asn.nil? ? nil : @names[asn]
      end

      Snapshot = Struct.new(:build_ts, :ipv4, :ipv6, :orgs, :artifacts, keyword_init: true) do
        def layers(family) = family == :ipv4 ? ipv4 : ipv6

        def layer_counts
          { "ipv4" => ipv4.counts.transform_keys(&:to_s),
            "ipv6" => ipv6.counts.transform_keys(&:to_s) }
        end
      end

      module_function

      def load(v4_path:, v6_path:, orgs_path:)
        v4 = read_oasn(v4_path, :ipv4)
        v6 = read_oasn(v6_path, :ipv6)

        # Equal timestamps are how we know both families describe the same
        # build. Projecting a v4 file against a v6 file from a different run
        # would produce a coherent-looking export of two different datasets.
        unless v4[:build_ts] == v6[:build_ts]
          Env.fail_stage!("OASN build timestamps differ: #{File.basename(v4_path)}=#{v4[:build_ts]} " \
                          "#{File.basename(v6_path)}=#{v6[:build_ts]} - these are not the same build")
        end

        orgs_descriptor = describe(orgs_path)
        Snapshot.new(
          build_ts: v4[:build_ts],
          ipv4: v4[:layers],
          ipv6: v6[:layers],
          orgs: read_orgs(orgs_path, orgs_descriptor),
          artifacts: [v4[:descriptor], v6[:descriptor], orgs_descriptor].sort_by(&:name)
        )
      end

      def describe(path)
        Env.fail_stage!("export input missing: #{path}") unless File.file?(path)
        Descriptor.new(File.basename(path), Digest::SHA256.file(path).hexdigest, File.size(path))
      end

      def read_oasn(path, family)
        descriptor = describe(path)
        header = File.open(path, "rb") { |io| io.read(Binary::HEADER_SIZE) }
        unless header && header.bytesize == Binary::HEADER_SIZE
          Env.fail_stage!("#{descriptor.name}: truncated OASN header (#{descriptor.bytes} bytes)")
        end

        magic, version, family_byte, reserved = header.unpack("a4CCn")
        Env.fail_stage!("#{descriptor.name}: bad magic #{magic.inspect}") unless magic == MAGIC
        Env.fail_stage!("#{descriptor.name}: unsupported format_version #{version}") unless version == FORMAT_VERSION
        expected_byte = family == :ipv4 ? 0x04 : 0x06
        unless family_byte == expected_byte
          Env.fail_stage!(format("%s: address_family 0x%02x, expected 0x%02x", descriptor.name, family_byte, expected_byte))
        end
        Env.fail_stage!("#{descriptor.name}: header reserved u16 is #{reserved}, not 0") unless reserved.zero?

        base_n, vpn_n, dc_n, relay_n = header[16, 16].unpack("NNNN")
        expected_bytes = Binary::HEADER_SIZE +
                         base_n * Binary.base_rec_size(family) +
                         (vpn_n + dc_n + relay_n) * Binary.overlay_rec_size(family)
        unless expected_bytes == descriptor.bytes
          Env.fail_stage!("#{descriptor.name}: header counts (base=#{base_n} vpn=#{vpn_n} dc=#{dc_n} " \
                          "relay=#{relay_n}) describe #{expected_bytes} bytes, file is #{descriptor.bytes}")
        end
        unless relay_n.zero?
          Env.fail_stage!("#{descriptor.name}: relay overlay layer has #{relay_n} rows. Relay data is Tier B; " \
                          "core-v1 has no vocabulary for it and must not import it as a shortcut")
        end

        artifact = Binary::Artifact.new(path)
        build_ts = artifact.build_ts
        unless build_ts.is_a?(Integer) && build_ts.positive?
          Env.fail_stage!("#{descriptor.name}: implausible build_unix_ts #{build_ts}")
        end

        base = artifact.each_base.to_a
        verify_ranges!(base, family, "#{descriptor.name} base")
        verify_base_evidence!(base, descriptor.name)
        vpn = artifact.each_overlay(:vpn).to_a
        verify_ranges!(vpn, family, "#{descriptor.name} vpn")
        dc = artifact.each_overlay(:dc).to_a
        verify_ranges!(dc, family, "#{descriptor.name} dc")

        { build_ts: build_ts, descriptor: descriptor, layers: Layers.new(family, base, vpn, dc) }
      end

      # Ascending, disjoint, inclusive, inside the family bound. Every layer,
      # every time - see the header note on Binary.write.
      def verify_ranges!(rows, family, label)
        max = Contract::ADDRESS_MAX.fetch(family)
        previous_end = -1
        rows.each_with_index do |(s, e), i|
          Env.fail_stage!("#{label}: row #{i} has inverted range #{s}..#{e}") if e < s
          Env.fail_stage!("#{label}: row #{i} start #{s} exceeds the #{family} bound") if s > max
          Env.fail_stage!("#{label}: row #{i} end #{e} exceeds the #{family} bound") if e > max
          if s <= previous_end
            Env.fail_stage!("#{label}: row #{i} starts at #{s}, at or before the previous end #{previous_end} " \
                            "- the layer is unsorted or overlapping")
          end
          previous_end = e
        end
      end

      def verify_base_evidence!(rows, name)
        checked = {} # a few hundred distinct flag words cover 440k rows
        rows.each_with_index do |(_s, _e, asn, flags), i|
          unless asn.is_a?(Integer) && asn >= 0 && asn <= Contract::ASN_MAX
            Env.fail_stage!("#{name} base: row #{i} has asn #{asn.inspect}, not a uint32")
          end
          next if checked.key?(flags)

          Contract.decode_flags(flags) # raises on reserved codes / reserved bits
          checked[flags] = true
        end
      end

      def read_orgs(path, descriptor = describe(path))
        data = File.binread(path)
        Env.fail_stage!("#{descriptor.name}: truncated OORG header") if data.bytesize < Orgs::HEADER_SIZE
        magic = data[0, 4]
        Env.fail_stage!("#{descriptor.name}: bad magic #{magic.inspect}") unless magic == Orgs::MAGIC
        version, reserved_hi, reserved_lo = data[4, 4].unpack("CCn")
        Env.fail_stage!("#{descriptor.name}: unsupported OORG version #{version}") unless version == Orgs::VERSION
        unless reserved_hi.zero? && reserved_lo.zero?
          Env.fail_stage!("#{descriptor.name}: header reserved bytes are not zero")
        end

        count, blob_size = data[8, 8].unpack("NN")
        blob_base = Orgs::HEADER_SIZE + count * 8
        expected_bytes = blob_base + blob_size
        unless expected_bytes == descriptor.bytes
          Env.fail_stage!("#{descriptor.name}: header (#{count} entries, #{blob_size} blob bytes) describes " \
                          "#{expected_bytes} bytes, file is #{descriptor.bytes}")
        end

        names = {}
        previous_asn = nil
        offsets = Array.new(count)
        asns = Array.new(count)
        count.times do |i|
          asn, offset = data[Orgs::HEADER_SIZE + i * 8, 8].unpack("NN")
          if previous_asn && asn <= previous_asn
            Env.fail_stage!("#{descriptor.name}: index entry #{i} has asn #{asn} after #{previous_asn} " \
                            "- the index is unsorted or has duplicates")
          end
          if offset > blob_size
            Env.fail_stage!("#{descriptor.name}: entry #{i} (AS#{asn}) points at blob offset #{offset}, " \
                            "past the #{blob_size}-byte blob")
          end
          asns[i] = asn
          offsets[i] = offset
          previous_asn = asn
        end

        count.times do |i|
          finish = i + 1 < count ? offsets[i + 1] : blob_size
          length = finish - offsets[i]
          if length <= 0
            Env.fail_stage!("#{descriptor.name}: entry #{i} (AS#{asns[i]}) has length #{length}; " \
                            "names are nonempty and offsets ascend")
          end
          name = data[blob_base + offsets[i], length].force_encoding(Encoding::UTF_8)
          unless name.valid_encoding?
            Env.fail_stage!("#{descriptor.name}: entry #{i} (AS#{asns[i]}) is not valid UTF-8")
          end
          if name.bytesize > Orgs::MAX_NAME
            Env.fail_stage!("#{descriptor.name}: entry #{i} (AS#{asns[i]}) is #{name.bytesize} bytes, " \
                            "over the #{Orgs::MAX_NAME}-byte cap")
          end
          names[asns[i]] = name.freeze
        end

        OrgIndex.new(names)
      end
    end
  end
end
