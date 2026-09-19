# frozen_string_literal: true

# RIR delegated-extended statistics — the five per-RIR registry files, parsed
# into an ASN registry (RIR, registration country, first-delegation date,
# status) and HOLDER CLUSTERS (the per-RIR opaque-id groups the ASNs one
# registrant holds).
#
# ============================================================================
# LEGAL STATUS — read before wiring this into anything that is published
# ============================================================================
# This is NOT a Tier A source and nothing here feeds Compile/Publish. Terms
# re-verified from the primary pages on 2026-09-19 (research record:
# data repo docs/enrichment/research/parts/P4-S-rir-terms-2026-09-19.jsonl;
# decision proposal: DECISIONS.md D-SRC-1, PROPOSED):
#
#   apnic   "The files are freely available for download and use on the
#   afrinic  condition that <RIR> will not be held responsible for any loss
#   lacnic   or damage ..." (README-EXTENDED / disclaimer.txt). A USE grant.
#            It never says redistribute/publish.
#   arin     silent: files are "available for use via HTTPS"; no grant, no
#            restriction on the stats files (the Whois TOU does not govern them).
#   ripencc  RESTRICTED: site-wide "All rights restricted ... may not be used,
#            reproduced and made available to third parties without prior
#            written authorisation"; ToS Art. 1 extends "the Website" to every
#            ripe.net sub-domain (so ftp.ripe.net), Art. 6.2 names databases.
#
# The legal invariant (data-repo README "Legal design" rule 1) demands
# EXPLICIT redistribution rights. None of the five says that, so until the
# owner rules on D-SRC-1 the outputs of this module are build-time working
# files only (build/work/rir/), used as curation evidence under D-CUR-1.
#
# RIPE is excluded by default even from those local files; set
# OPENASN_RIR_INCLUDE_RIPE=1 to include it for private research (RIPE's own
# statement permits "research" use of unmodified materials). Never ship a
# RIPE-derived value, and never use the merged NRO file — it is served from
# ftp.ripe.net and carries RIPE rows.
#
# ============================================================================
# DATA TRAPS (measured 2026-09-19)
# ============================================================================
# * Blocks: `apnic|JP|asn|2497|32|...` delegates AS2497..AS2528. Expand.
# * NIR pools: APNIC hands whole ASN pools to the National Internet
#   Registries, and every ASN in a pool carries the NIR's opaque-id — the
#   largest "holder" in the file (5,385 ASNs, all IN) is IRINN, not an
#   operator. Seven such pools cover ~18k ASNs. A cluster that large is a
#   registry, not a sibling set: clusters above POOL_THRESHOLD are marked
#   `pool` and never propagate anything.
# * The opaque-id is only unique WITHIN one RIR: clusters are keyed
#   "<rir>:<opaque-id>".
# * Sentinels: date 00000000/19700101 and country ""/"*"/"ZZ" mean unknown.
# * 7-field lines (no opaque-id column) occur for available/reserved rows.

require "json"
require "set"
require "fileutils"
require_relative "env"
require_relative "http"

module OpenASNPipeline
  module RirStats
    # One entry per RIR. `terms` points at the license-gate id pinning the
    # text that governs the file (see LicenseGate::CURATION_TERMS); ARIN's
    # pin is an absence receipt (its README carries no terms — if that ever
    # changes the gate trips and a human re-reads it).
    REGISTRIES = {
      "arin" => {
        url: "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
        grant: :silent, terms: "arin-delegated-stats"
      },
      "ripencc" => {
        url: "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
        grant: :restricted, terms: nil
      },
      "apnic" => {
        url: "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
        grant: :use_grant, terms: "apnic-delegated-stats"
      },
      "lacnic" => {
        url: "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
        grant: :use_grant, terms: "lacnic-delegated-stats"
      },
      "afrinic" => {
        url: "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
        grant: :use_grant, terms: "afrinic-delegated-stats"
      }
    }.freeze

    INCLUDE_RIPE_ENV = "OPENASN_RIR_INCLUDE_RIPE"

    # D-SRC-1 (PROPOSED): nothing RIR-derived is publishable. A test pins this
    # to false so flipping it is a reviewed, deliberate act.
    PUBLISHABLE = false

    STATUSES  = %w[allocated assigned available reserved].freeze
    DELEGATED = %w[allocated assigned].freeze

    # Largest real single-registrant cluster outside the NIR pools is ~1,000
    # (one US government holder); the NIR pools start at 337. 250 errs on the
    # side of not propagating (false negatives over false positives).
    POOL_THRESHOLD = 250

    OUT_DIR = File.join(WORK_DIR, "rir")

    class ParseError < StandardError; end

    module_function

    # RIRs to read. RIPE only on explicit opt-in (research use, never shipped).
    def enabled_rirs(env = ENV)
      REGISTRIES.keys.reject { |rir| rir == "ripencc" && env[INCLUDE_RIPE_ENV] != "1" }
    end

    # Parse one delegated-extended body into ASN delegation records (not yet
    # expanded). Pure. With `rir:` every data line must belong to that
    # registry — the guard that stops the merged NRO file (all five RIRs,
    # RIPE-hosted) from sneaking in under one RIR's name.
    #
    # Returns [{ "rir", "cc", "start", "count", "date", "status", "opaque_id" }].
    def parse_delegations(body, rir: nil)
      out = []
      body.each_line.with_index(1) do |line, lineno|
        line = line.chomp
        next if line.empty? || line.start_with?("#")

        f = line.split("|", -1)
        next if f[1] == "*" && f[3] == "*"                 # summary line
        next if f[0].match?(/\A\d+(\.\d+)?\z/)             # version line: "2.3|arin|..."
        next unless f[2] == "asn"

        if rir && f[0] != rir
          raise ParseError, "line #{lineno}: registry #{f[0].inspect} in the #{rir} file " \
                            "(merged/NRO file? only the five per-RIR files are allowed)"
        end
        start = Integer(f[3], 10, exception: false)
        count = Integer(f[4], 10, exception: false)
        raise ParseError, "line #{lineno}: bad asn start/count in #{line.inspect}" unless start && count&.positive?

        status = f[6].to_s.strip
        raise ParseError, "line #{lineno}: unknown status #{status.inspect}" unless STATUSES.include?(status)

        out << {
          "rir" => f[0], "cc" => country(f[1]), "start" => start, "count" => count,
          "date" => date(f[5]), "status" => status, "opaque_id" => blank_nil(f[7])
        }
      end
      out
    end

    def blank_nil(s) = (s.nil? || s.strip.empty?) ? nil : s.strip

    def country(s)
      cc = s.to_s.strip
      cc.empty? || cc == "*" || cc == "ZZ" ? nil : cc
    end

    def date(s)
      d = s.to_s.strip
      return nil unless d.match?(/\A\d{8}\z/) && d != "00000000" && d != "19700101"

      "#{d[0, 4]}-#{d[4, 2]}-#{d[6, 2]}"
    end

    # Expand delegations to one row per ASN. An ASN delegated by two RIRs
    # (should not happen; NRO publishes a `conflicts` file for when it does)
    # is dropped into `conflicts` rather than guessed.
    #
    # Returns [rows, conflicts] with rows = { asn => row }, row keys:
    # rir cc registered status holder (holder = "rir:opaque-id" or nil).
    def expand(delegations)
      rows = {}
      conflicts = Set.new
      delegations.each do |d|
        holder = d["opaque_id"] && "#{d['rir']}:#{d['opaque_id']}"
        row = { "rir" => d["rir"], "cc" => d["cc"], "registered" => d["date"],
                "status" => d["status"], "holder" => holder }.freeze
        (d["start"]...(d["start"] + d["count"])).each do |asn|
          if (prev = rows[asn]) && prev["rir"] != d["rir"]
            conflicts << asn
          else
            rows[asn] = row
          end
        end
      end
      conflicts.each { |asn| rows.delete(asn) }
      [rows, conflicts.to_a.sort]
    end

    # holder -> sorted ASNs, over DELEGATED rows only (an "available" row's
    # opaque-id, where present, is the RIR's own inventory).
    def clusters(rows)
      out = Hash.new { |h, k| h[k] = [] }
      rows.each do |asn, r|
        next unless r["holder"] && DELEGATED.include?(r["status"])

        out[r["holder"]] << asn
      end
      out.transform_values(&:sort)
    end

    # :single (1 ASN), :siblings (2..POOL_THRESHOLD), :pool (> threshold —
    # a registry pool such as an APNIC NIR; never a sibling signal).
    def cluster_kind(size)
      return :single if size <= 1

      size > POOL_THRESHOLD ? :pool : :siblings
    end

    # Siblings of `asn` (same holder, excluding itself). Empty when the
    # holder is a pool or unknown — propagation must never cross a pool.
    def siblings(asn, rows, clusters)
      holder = rows.dig(asn, "holder") or return []
      members = clusters[holder] || []
      return [] unless cluster_kind(members.size) == :siblings

      members - [asn]
    end

    # Fetch the enabled per-RIR files through the shared cache. A dead RIR
    # warns and is skipped (keep-partial); the stats say which ones loaded.
    def fetch_all(http: Http.new, offline: false, rirs: enabled_rirs)
      delegations = []
      loaded = {}
      rirs.each do |rir|
        spec = REGISTRIES.fetch(rir)
        begin
          path = http.fetch(spec[:url], "rir/delegated-#{rir}-extended-latest", offline: offline)
          ds = parse_delegations(File.read(path, encoding: "ASCII-8BIT").force_encoding("UTF-8").scrub, rir: rir)
          delegations.concat(ds)
          loaded[rir] = { "url" => spec[:url], "fetched_at" => http.fetched_at("rir/delegated-#{rir}-extended-latest"),
                          "sha256" => http.sha256("rir/delegated-#{rir}-extended-latest"), "records" => ds.size }
        rescue StandardError => e
          Env.warn("rir: #{rir} skipped (#{e.message})")
        end
      end
      [delegations, loaded]
    end

    # Build the working registry: build/work/rir/{asn-registry.jsonl,
    # holders.jsonl,stats.json}. NOT published (PUBLISHABLE == false).
    def build(http: Http.new, offline: ENV["OFFLINE"] == "1", rirs: enabled_rirs, out_dir: OUT_DIR)
      delegations, loaded = fetch_all(http: http, offline: offline, rirs: rirs)
      Env.fail_stage!("rir: no RIR file could be loaded") if loaded.empty?

      rows, conflicts = expand(delegations)
      cl = clusters(rows)
      stats = stats(rows, cl, conflicts).merge("rirs" => loaded, "ripe_included" => loaded.key?("ripencc"),
                                                "publishable" => PUBLISHABLE, "pool_threshold" => POOL_THRESHOLD)
      write(out_dir, rows, cl, stats)
      Env.log("rir: #{stats['asns_total']} ASNs, #{stats['delegated']} delegated, " \
              "#{stats['sibling_clusters']} sibling clusters covering #{stats['asns_in_sibling_clusters']} ASNs, " \
              "#{stats['pool_clusters']} pools (#{stats['asns_in_pools']} ASNs) -> #{out_dir}")
      { rows: rows, clusters: cl, stats: stats }
    end

    def stats(rows, cl, conflicts)
      by_kind = cl.group_by { |_, v| cluster_kind(v.size) }
      delegated = rows.count { |_, r| DELEGATED.include?(r["status"]) }
      {
        "asns_total" => rows.size,
        "delegated" => delegated,
        "by_status" => rows.values.map { _1["status"] }.tally.sort.to_h,
        "by_rir_delegated" => rows.values.select { DELEGATED.include?(_1["status"]) }.map { _1["rir"] }.tally.sort.to_h,
        "holders" => cl.size,
        "sibling_clusters" => (by_kind[:siblings] || []).size,
        "asns_in_sibling_clusters" => (by_kind[:siblings] || []).sum { _2.size },
        "pool_clusters" => (by_kind[:pool] || []).size,
        "asns_in_pools" => (by_kind[:pool] || []).sum { _2.size },
        "largest_sibling_cluster" => (by_kind[:siblings] || []).map { _2.size }.max,
        "conflicts" => conflicts.size
      }
    end

    def write(out_dir, rows, cl, stats)
      FileUtils.mkdir_p(out_dir)
      File.open(File.join(out_dir, "asn-registry.jsonl"), "w") do |f|
        rows.keys.sort.each { |asn| f.puts JSON.generate({ "asn" => asn }.merge(rows[asn])) }
      end
      File.open(File.join(out_dir, "holders.jsonl"), "w") do |f|
        cl.keys.sort.each do |h|
          f.puts JSON.generate("holder" => h, "kind" => cluster_kind(cl[h].size).to_s, "size" => cl[h].size, "asns" => cl[h])
        end
      end
      File.write(File.join(out_dir, "stats.json"), JSON.pretty_generate(stats) + "\n")
    end
  end
end
