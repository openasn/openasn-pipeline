# frozen_string_literal: true

# Integer math over IP ranges, shared by every stage.
#
# Ranges are ALWAYS [start_int, end_int] inclusive, in host-integer form
# (0..2^32-1 for IPv4, 0..2^128-1 for IPv6). We deliberately avoid carrying
# IPAddr objects through the pipeline: 400k+ IPAddr instances are slow and
# memory-heavy, plain Integers are not.

require "ipaddr"

module OpenASNPipeline
  module IPMath
    V4_MAX = (1 << 32) - 1
    V6_MAX = (1 << 128) - 1

    module_function

    # "1.2.3.0/24" | "1.2.3.4" | "2a00::/32" -> [start_int, end_int, family]
    # family is :ipv4 | :ipv6. Raises IPAddr::Error on garbage (callers decide
    # whether a bad upstream line is fatal or skippable).
    def cidr_to_range(cidr)
      ip = IPAddr.new(cidr.strip)
      r  = ip.to_range
      [r.first.to_i, r.last.to_i, ip.ipv4? ? :ipv4 : :ipv6]
    end

    # Fast dotted-quad -> int for hot parse loops (~6x faster than IPAddr).
    # Returns nil on anything that isn't a plain IPv4 literal.
    def v4_to_int(str)
      parts = str.split(".")
      return nil unless parts.length == 4
      int = 0
      parts.each do |p|
        n = p.to_i
        return nil if n > 255 || (n == 0 && p != "0") || p.length > 3
        int = (int << 8) | n
      end
      int
    end

    def int_to_v4(int)
      [int >> 24 & 255, int >> 16 & 255, int >> 8 & 255, int & 255].join(".")
    end

    def int_to_v6(int)
      IPAddr.new(int, Socket::AF_INET6).to_s
    end

    # Merge overlapping AND adjacent ranges: [[1,5],[6,9],[8,12]] -> [[1,12]].
    # Input: array of [start, end(, *extra ignored)]. Output: new sorted array
    # of disjoint [start, end] pairs. Adjacency (s == prev_end + 1) merges too,
    # matching the prototype that produced the measured overlay counts
    # (X4B vpn 10,977 CIDRs -> 6,405 ranges; dc 42,139 -> 28,746).
    def merge_ranges(ranges)
      return [] if ranges.empty?
      sorted = ranges.sort_by { |r| [r[0], r[1]] }
      merged = [[sorted[0][0], sorted[0][1]]]
      sorted.each do |(s, e)|
        last = merged.last
        if s <= last[1] + 1
          last[1] = e if e > last[1]
        else
          merged << [s, e]
        end
      end
      merged
    end

    # Subtract `covered` (sorted, disjoint) from a single [s, e] range and
    # return the leftover gaps. Used when gap-filling override-only ASNs into
    # the backbone: the BGP backbone (origin-asn) is authoritative, so ranges
    # we synthesize from ipverse as-ip-blocks may only fill space the backbone
    # does not already claim.
    def subtract_covered(s, e, covered)
      gaps = []
      cursor = s
      covered.each do |(cs, ce)|
        break if cs > e
        next if ce < cursor
        gaps << [cursor, cs - 1] if cs > cursor
        cursor = ce + 1
        break if cursor > e
      end
      gaps << [cursor, e] if cursor <= e
      gaps
    end

    # Binary search over a sorted, disjoint array of [start, end, ...] rows.
    # Returns the matching row or nil. Used by validation (the shipped gem has
    # its own reader over the packed artifact; this one is for in-memory rows).
    def find_range(rows, ip_int)
      lo = 0
      hi = rows.length - 1
      while lo <= hi
        mid = (lo + hi) / 2
        row = rows[mid]
        if ip_int < row[0]
          hi = mid - 1
        elsif ip_int > row[1]
          lo = mid + 1
        else
          return row
        end
      end
      nil
    end
  end
end
