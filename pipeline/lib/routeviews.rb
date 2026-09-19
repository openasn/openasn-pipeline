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
#   * a collector whose RIB cannot be fetched and has no cached copy is
#     skipped with a WARN; fewer than MIN_COLLECTORS usable RIBs FAILS the
#     build (a thin view would silently shrink coverage);
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

    def cache_key(collector) = "routeviews/#{collector}.rib.bz2"

    # Returns { backbone_v4:, backbone_v6: } paths.
    def build(http:, offline:)
      slot = Sources.routeviews_slot
      Env.log("routeviews: RIB slot #{slot} UTC, #{Sources::ROUTEVIEWS_COLLECTORS.size} collectors")
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
            url = Sources.routeviews_rib_url(c, slot)
            begin
              path = http.fetch(url, cache_key(c), offline: offline)
            rescue StandardError => e
              Env.warn("routeviews: #{c} unavailable (#{e.message.lines.first&.strip}) - skipping this collector")
              next
            end
            lock.synchronize { found[c] = path }
          end
        end
      end.each(&:join)
      # Keep the configured collector order so builds are reproducible.
      ribs = Sources::ROUTEVIEWS_COLLECTORS.filter_map { |c| [c, found[c]] if found[c] }.to_h
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
      Env.log(format("routeviews: %d collectors, %d peer ASes, %d prefixes -> %d v4 + %d v6 ranges in %.0fs",
                     ribs.size, stats.dig("resolve", "distinct_peer_ases"), stats.dig("resolve", "prefixes_kept"),
                     stats["v4_ranges"], stats["v6_ranges"], Time.now - started))
      { backbone_v4: File.join(out_dir, "origin-asn-ipv4-num.csv"),
        backbone_v6: File.join(out_dir, "origin-asn-ipv6-num.csv") }
    end

    # Provenance for manifest.json `stats` (empty on a sapics build, so the
    # default manifest shape is unchanged).
    def manifest_stamp = @stamp || {}

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
