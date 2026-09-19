# frozen_string_literal: true

# The effective-interval projection (PRD §8.2): three sorted layers in, one
# stream of maximal disjoint intervals out, each carrying a complete payload.
#
# A boundary-event sweep, as an ITERATOR. The iterator is not a style
# preference: three writers (CSV, SQLite, MMDB) consume the same projection,
# and materializing 574k rows so each of them can walk the array again is
# how a 400MB build becomes a 1.2GB build. Writers stream; this yields.
#
# Two rules carry all the subtlety:
#
#   * at a shared position, every DEACTIVATION is applied before any
#     ACTIVATION. Ranges are inclusive, so a row ending at N and the next
#     starting at N+1 are adjacent, not overlapping - their events land at
#     N+1 as (end of A, start of B). Applying the activation first would
#     make the base state ambiguous for one elementary segment.
#   * coalescing compares the ENTIRE payload - asn, exact org bytes,
#     category, role, all eight booleans, verdict and ordered sources - and
#     only across ADJACENT intervals. Merging on equal verdicts would erase
#     the ASN boundary that a consumer joins on, and bridging a gap would
#     invent coverage that no input layer claimed.
#
# Addresses are Ruby Integers throughout, so IPv6 needs no special casing
# and nothing passes through a Float. 2**32 / 2**128 appear as end
# sentinels (a row ending at the last address deactivates one past it) and
# are never serialized: the interval that sentinel closes ends at the
# maximum address itself.

require_relative "../lib/env"
require_relative "contract"
require_relative "profile"

module OpenASNPipeline
  module Export
    module Project
      Payload = Struct.new(*Contract::PAYLOAD_FIELDS)
      Record  = Struct.new(:family, :start, :end, :payload) do
        def addresses = self.end - start + 1
      end

      # Walks one sorted, disjoint layer as a monotone stream of events:
      # row 0 start, row 0 end+1, row 1 start, ... Peeking the next position
      # lets the sweep merge three already-ordered streams instead of
      # sorting one global event array.
      class Cursor
        def initialize(rows)
          @rows = rows
          @index = 0
          @closing = false
        end

        def position
          return nil if @index >= @rows.length

          @closing ? @rows[@index][1] + 1 : @rows[@index][0]
        end

        def closing? = @closing
        def row = @rows[@index]

        def advance
          if @closing
            @index += 1
            @closing = false
          else
            @closing = true
          end
        end
      end

      module_function

      def each(snapshot, family:)
        return enum_for(:each, snapshot, family: family) unless block_given?

        layers = snapshot.layers(family)
        cursors = { base: Cursor.new(layers.base),
                    vpn: Cursor.new(layers.vpn),
                    dc: Cursor.new(layers.dc) }

        state = { base: nil, vpn: false, dc: false }
        # [asn, flags, vpn, dc] fully determines the payload, so identical
        # evidence is decoded, classified and allocated once instead of once
        # per elementary segment. Measured on the 2026-09-18 snapshot: 96,525
        # distinct payloads behind 572,357 segments.
        payloads = {}
        previous = nil
        pending = nil

        loop do
          position = cursors.each_value.filter_map(&:position).min
          break if position.nil?

          if previous && previous < position && (state[:base] || state[:vpn] || state[:dc])
            row = state[:base]
            key = [row&.[](2), row&.[](3), state[:vpn], state[:dc]]
            payload = payloads[key] ||= build_payload(snapshot, row, state[:vpn], state[:dc])

            if pending && pending.end + 1 == previous && pending.payload == payload
              pending.end = position - 1
            else
              yield pending if pending
              pending = Record.new(family, previous, position - 1, payload)
            end
          end

          cursors.each do |layer, cursor|
            while cursor.position == position && cursor.closing?
              state[layer] = layer == :base ? nil : false
              cursor.advance
            end
          end
          cursors.each do |layer, cursor|
            while cursor.position == position && !cursor.closing?
              state[layer] = layer == :base ? cursor.row : true
              cursor.advance
            end
          end

          previous = position
        end

        yield pending if pending

        # Every activation has a matching deactivation by construction, so a
        # nonempty state here means the sweep lost an event - which would
        # show up as a silently truncated export rather than an error.
        unless state[:base].nil? && !state[:vpn] && !state[:dc]
          Env.fail_stage!("projection(#{family}): state not empty after the final event: #{state.inspect}")
        end
      end

      # An overlay-only interval has no base row at all: no ASN, no org, no
      # category, no ASN-level signal - but it is still a real exported
      # record, because the overlay is evidence on its own.
      def build_payload(snapshot, row, in_vpn, in_dc)
        asn   = row&.[](2)
        flags = row ? row[3] : 0
        category, network_role, signals = Contract.decode_flags(flags)
        signals = signals.merge(vpn_range: in_vpn, datacenter_range: in_dc)
        result = Profile.call(asn: asn, category: category, network_role: network_role, signals: signals)

        payload = Payload.new
        payload.asn = asn
        payload.as_org = snapshot.orgs.name_for(asn)
        payload.category = category
        payload.network_role = network_role
        Contract::SIGNALS.each { |name| payload[name] = signals.fetch(name) }
        payload.core_verdict = result.verdict
        payload.core_sources = result.sources
        payload.freeze
      end
    end
  end
end
