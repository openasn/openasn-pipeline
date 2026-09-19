# frozen_string_literal: true

# openasn-orgs.bin - the ASN -> organization-name sidecar artifact.
#
# WHY A SEPARATE FILE: the main artifacts stay lean (they're bundled as the
# gem's seed, budget-capped), while org names are optional richness
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
# WHERE THE NAMES COME FROM (data-repo DECISIONS.md D-SRC-2, org names;
# byte layout unchanged, still OORG v1). Precedence, first hit wins:
#   1. data/overrides/org_names.txt: our own curated, sourced names (CC0)
#   2. Wikidata P3797 item labels (CC0), admissible statements only
#      (lib/wikidata_names.rb)
# ASNs with neither get no entry, and clients see as_org == nil. Until
# 2026-09 this file carried the ipverse as-metadata descriptions (~125k
# names), which are bulk RIR WHOIS `descr`. Those left the CC0 core. They
# are now a Tier B recipe (`ipverse_org_names` in fetch-manifest.json) that
# clients fetch themselves. Nothing from ipverse's `description` may reach
# write(); test/org_names_test.rb guards that.
#
# Names are truncated to MAX_NAME bytes on a valid UTF-8 boundary.

require_relative "env"

module OpenASNPipeline
  module Orgs
    MAGIC = "OORG"
    VERSION = 0x01
    HEADER_SIZE = 16
    MAX_NAME = 96

    module_function

    # Precedence merge. override_names: { asn => { "name", "src" } } from
    # Overrides#org_names; wikidata_names: { asn => { "name", "qid" } } from
    # WikidataNames.parse. -> { asn => { "name", "source" } } where source is
    # "override" or "wikidata:<QID>" (provenance for the manifest stats).
    def merge(override_names, wikidata_names)
      out = {}
      (wikidata_names || {}).each { |asn, r| out[asn] = { "name" => r["name"], "source" => "wikidata:#{r['qid']}" } }
      (override_names || {}).each { |asn, r| out[asn] = { "name" => r["name"], "source" => "override" } }
      out
    end

    # -> { "total" => n, "override" => n, "wikidata" => n }
    def source_counts(names)
      counts = { "total" => names.size, "override" => 0, "wikidata" => 0 }
      names.each_value { |r| counts[r["source"].split(":").first] += 1 }
      counts
    end

    # names: { asn => { "name" => String, ... } } (Orgs.merge output)
    def write(path, names)
      entries = names.keys.sort.filter_map do |asn|
        name = names[asn]["name"].to_s.strip
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
