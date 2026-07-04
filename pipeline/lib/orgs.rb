# frozen_string_literal: true

# openasn-orgs.bin - the ASN -> organization-name sidecar artifact.
#
# WHY A SEPARATE FILE: the main artifacts stay lean (they're bundled as the
# gem's seed, budget-capped), while org names (~3MB) are optional richness
# that clients download on their first data refresh. A lookup works fully
# without this file - Result#as_org just returns nil until it's present.
#
# Layout (all integers big-endian; "OORG" v1):
#   header (16 bytes):
#     0  4  magic = "OORG"
#     4  1  version = 0x01
#     5  3  reserved (zeros)
#     8  4  entry_count (u32)
#     12 4  blob_size (u32)
#   index: entry_count × (asn u32 · blob_offset u32), sorted by asn ascending
#   blob:  concatenated UTF-8 names; entry length = next offset - own offset
#          (last entry runs to blob_size). No per-entry length prefix needed.
#
# Names are the ipverse as-metadata descriptions, truncated to MAX_NAME
# bytes on a valid UTF-8 boundary.

require_relative "env"

module OpenASNPipeline
  module Orgs
    MAGIC = "OORG"
    VERSION = 0x01
    HEADER_SIZE = 16
    MAX_NAME = 96

    module_function

    # asn_meta: { asn => AsJson::Record }
    def write(path, asn_meta)
      entries = asn_meta.keys.sort.filter_map do |asn|
        name = asn_meta[asn].description.to_s.strip
        next if name.empty?

        [asn, truncate_utf8(name, MAX_NAME)]
      end

      blob = +""
      index = +""
      entries.each do |(asn, name)|
        index << [asn, blob.bytesize].pack("NN")
        blob << name.b
      end

      File.open("#{path}.tmp", "wb") do |io|
        io.write(MAGIC.b)
        io.write([VERSION, 0, 0].pack("CCn"))
        io.write([entries.length, blob.bytesize].pack("NN"))
        io.write(index, blob)
      end
      File.rename("#{path}.tmp", path)
      Env.log("orgs: #{entries.length} names, #{File.size(path) / 1024}KB")
      path
    end

    def truncate_utf8(str, max_bytes)
      return str if str.bytesize <= max_bytes

      truncated = str.byteslice(0, max_bytes)
      truncated = truncated.byteslice(0, truncated.bytesize - 1) until truncated.valid_encoding?
      truncated
    end

    # Reference reader (validation + rake lookup). The gem has its own.
    def read(path, asn)
      data = File.binread(path)
      raise "bad orgs magic" unless data[0, 4] == MAGIC

      count, blob_size = data[8, 8].unpack("NN")
      blob_base = HEADER_SIZE + count * 8
      lo = 0
      hi = count - 1
      while lo <= hi
        mid = (lo + hi) / 2
        a, off = data[HEADER_SIZE + mid * 8, 8].unpack("NN")
        if asn < a
          hi = mid - 1
        elsif asn > a
          lo = mid + 1
        else
          nxt = mid + 1 < count ? data[HEADER_SIZE + (mid + 1) * 8 + 4, 4].unpack1("N") : blob_size
          return data[blob_base + off, nxt - off].force_encoding(Encoding::UTF_8)
        end
      end
      nil
    end
  end
end
