# frozen_string_literal: true

# The RouteViews backbone (the default since D-SRC-2 (backbone) / CD-12; the legacy
# sapics backbone remains behind OPENASN_BACKBONE=sapics):
#
#   fetch one RIB per collector (same 2-hourly slot) -> tools/rib2origin
#   -> origin-asn-ipv{4,6}-num.csv in sapics' exact shape -> normalize.rb
#
# Everything downstream of fetch is unchanged: the backbone is just a
# different producer of the same two files.
#
# Failure policy (gates fail loudly or not at all):
#   * a collector whose slot RIB cannot be fetched falls back to its own
#     cached RIB only if that is at most MAX_FALLBACK_AGE older (WARN, and
#     the real slot is stamped in manifest stats); otherwise it is skipped
#     with a WARN. Fewer than MIN_COLLECTORS usable RIBs FAILS the build;
#   * a RIB smaller than MIN_RIB_BYTES fails (error page served as 200);
#   * rib2origin exiting non-zero fails the build;
#   * the derived table must clear the same size floors as sapics' files.

require "json"
require "open3"
require "fileutils"
require_relative "env"
require_relative "sources"

module OpenASNPipeline
  module RouteViews
    MIN_COLLECTORS = 7
    MIN_RIB_BYTES  = 5_000_000
    FETCH_THREADS  = 4
    TOOL_DIR = File.expand_path("../../tools/rib2origin", __dir__)

    module_function

    # One cache file PER SLOT (review RB-1, 2026-09-19). The first version
    # used one slot-less key per collector, so Http#fetch's keep-last-good
    # silently served a RIB of ANY age whenever a collector's file was
    # missing (collector down or retired, slot not yet written). The upstream
    # cache is restored every night, so a dead collector would have voted
    # with its last RIB forever - keeping withdrawn prefixes alive (one big
    # collector alone clears the 2-peer-AS floor) and outvoting new origins -
    # while the manifest stamped today's slot and MIN_COLLECTORS never fired.
    def cache_key(collector, slot) = "routeviews/#{collector}/rib.#{slot}.bz2"
    def legacy_cache_key(collector) = "routeviews/#{collector}.rib.bz2"

    # A collector whose slot RIB cannot be fetched may fall back to its own
    # newest cached RIB only if that RIB is at most this much older than the
    # requested slot (one nightly back, plus slack for a late run). Older than
    # that it is skipped and MIN_COLLECTORS decides. Offline builds (local
    # iteration) take the newest cached RIB of any age. Either way the slot
    # actually used is stamped per collector (manifest stats).
    MAX_FALLBACK_AGE = 36 * 3600

    def slot_time(slot) = Time.utc(slot[0, 4].to_i, slot[4, 2].to_i, slot[6, 2].to_i, slot[9, 2].to_i, slot[11, 2].to_i)

    # Cached slots for one collector, newest first: [[slot, key], ...].
    def cached_slots(http, collector)
      dir = http.path_for("routeviews/#{collector}")
      return [] unless Dir.exist?(dir)

      Dir.children(dir).filter_map { |f| f[/\Arib\.(\d{8}\.\d{4})\.bz2\z/, 1] }
         .sort.reverse.map { |s| [s, cache_key(collector, s)] }
    end

    # One RIB per collector: { collector => { path:, slot:, key: } } in the
    # configured collector order (reproducible builds). Collectors with no
    # usable RIB are absent (WARNed). Online, every other cached RIB of a
    # collector is pruned, so the upstream cache holds one RIB per collector.
    def resolve_ribs(http:, offline:, slot:)
      # Fetched FETCH_THREADS at a time: one archive stream runs at roughly
      # 1 MB/s from a European host (measured 2026-09-19), so ten sequential
      # RIBs would take ~15 min. Still a fixed list of named files, never a
      # crawl (the archive's robots.txt disallows crawlers).
      queue = Queue.new
      Sources::ROUTEVIEWS_COLLECTORS.each { |c| queue << c }
      found = {}
      lock = Mutex.new
      Array.new(FETCH_THREADS) do
        Thread.new do
          while (c = begin
            queue.pop(true)
          rescue ThreadError
            nil
          end)
            got = resolve_one(http, c, slot, offline)
            lock.synchronize { found[c] = got } if got
          end
        end
      end.each(&:join)
      ribs = Sources::ROUTEVIEWS_COLLECTORS.filter_map { |c| [c, found[c]] if found[c] }.to_h
      Sources::ROUTEVIEWS_COLLECTORS.each { |c| prune(http, c, keep: ribs.dig(c, :key), slot: slot) } unless offline
      ribs
    end

    def resolve_one(http, collector, slot, offline)
      key = cache_key(collector, slot)
      begin
        return { path: http.fetch(Sources.routeviews_rib_url(collector, slot), key, offline: offline), slot: slot, key: key }
      rescue StandardError => e
        reason = e.message.lines.first&.strip
      end
      requested = slot_time(slot)
      fallback = cached_slots(http, collector).find do |s, _k|
        s < slot && (offline || requested - slot_time(s) <= MAX_FALLBACK_AGE)
      end
      if fallback
        s, k = fallback
        Env.warn("routeviews: #{collector} slot #{slot} unavailable (#{reason}) - FALLING BACK to its cached RIB " \
                 "of slot #{s} (#{((requested - slot_time(s)) / 3600).round}h older), stamped in manifest stats")
        return { path: http.path_for(k), slot: s, key: k }
      end
      Env.warn("routeviews: #{collector} unavailable (#{reason}) and no cached RIB within " \
               "#{MAX_FALLBACK_AGE / 3600}h before slot #{slot} - skipping this collector")
      nil
    end

    # Deletes a collector's cached RIBs other than the one this build used,
    # and the pre-RB-1 slot-less file. With no usable RIB, only RIBs past the
    # fallback window go (they can never be used again).
    def prune(http, collector, keep:, slot:)
      doomed = cached_slots(http, collector).reject { |_s, k| k == keep }
      doomed.select! { |s, _k| slot_time(slot) - slot_time(s) > MAX_FALLBACK_AGE } unless keep
      (doomed.map(&:last) << legacy_cache_key(collector)).each { |k| http.forget(k) }
    end

    # Returns { backbone_v4:, backbone_v6: } paths.
    def build(http:, offline:)
      slot = Sources.routeviews_slot
      Env.log("routeviews: RIB slot #{slot} UTC, #{Sources::ROUTEVIEWS_COLLECTORS.size} collectors")
      resolved = resolve_ribs(http: http, offline: offline, slot: slot)
      @used_keys = resolved.values.map { |r| r[:key] }
      ribs = resolved.transform_values { |r| r[:path] }
      ribs.each do |c, path|
        size = File.size(path)
        Env.fail_stage!("routeviews: #{c} RIB suspiciously small: #{size} bytes (< #{MIN_RIB_BYTES})") if size < MIN_RIB_BYTES
      end
      if ribs.size < MIN_COLLECTORS
        Env.fail_stage!("routeviews: only #{ribs.size} of #{Sources::ROUTEVIEWS_COLLECTORS.size} collector RIBs usable " \
                        "(need #{MIN_COLLECTORS}) - refusing to build a thin backbone")
      end

      out_dir = File.join(WORK_DIR, "routeviews")
      FileUtils.mkdir_p(out_dir)
      tool = build_tool!
      cmd = [tool, "build", "-out", out_dir, *ribs.values]
      started = Time.now
      stdout_err, status = Open3.capture2e(*cmd)
      Env.fail_stage!("routeviews: rib2origin failed (exit #{status.exitstatus}):\n#{stdout_err}") unless status.success?

      stats = JSON.parse(File.read(File.join(out_dir, "stats.json")))
      @stamp = {
        backbone: "routeviews",
        routeviews: {
          rib_slot_utc: slot,
          collectors: ribs.keys,
          peer_ases: stats.dig("resolve", "distinct_peer_ases"),
          prefixes_kept: stats.dig("resolve", "prefixes_kept"),
          min_peers: stats.dig("config", "min_peers")
        }
      }
      # Collectors that fell back to an older cached RIB (RB-1): their real slot.
      stale = resolved.reject { |_c, r| r[:slot] == slot }.transform_values { |r| r[:slot] }
      @stamp[:routeviews][:fallback_rib_slots] = stale unless stale.empty?
      Env.log(format("routeviews: %d collectors, %d peer ASes, %d prefixes -> %d v4 + %d v6 ranges in %.0fs",
                     ribs.size, stats.dig("resolve", "distinct_peer_ases"), stats.dig("resolve", "prefixes_kept"),
                     stats["v4_ranges"], stats["v6_ranges"], Time.now - started))
      { backbone_v4: File.join(out_dir, "origin-asn-ipv4-num.csv"),
        backbone_v6: File.join(out_dir, "origin-asn-ipv6-num.csv") }
    end

    # Provenance for manifest.json `stats` (empty on a sapics build, so the
    # default manifest shape is unchanged).
    def manifest_stamp = @stamp || {}

    # Cache keys of the RIBs this build compiled from (publish.rb provenance).
    def used_keys = @used_keys || []

    # Go is a BUILD dependency only (as for tools/mmdbwriter). Rebuilt every
    # run: `go build` is a cached no-op when nothing changed.
    def build_tool!
      bin = File.join(WORK_DIR, "rib2origin")
      _out, status = Open3.capture2e("go", "-C", TOOL_DIR, "build", "-o", bin, ".")
      Env.fail_stage!("routeviews: could not build tools/rib2origin (is Go installed?)") unless status.success?
      bin
    rescue Errno::ENOENT
      Env.fail_stage!("routeviews: `go` not found on PATH - the RouteViews backbone needs the Go toolchain")
    end
  end
end
