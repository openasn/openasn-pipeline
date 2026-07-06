# frozen_string_literal: true

# External per-ASN evidence fetchers for the enrichment loop: RIPEstat,
# PeeringDB, RDAP, reverse-DNS sampling, and website titles.
#
# LEGAL POSTURE (data repo DECISIONS.md D-CUR-1):
# LLM *inputs* do not need to be redistribution-clean; only *published data*
# does. Consulting a source to decide a label is what a human curator does;
# the label is our own fact. The rules that DO bind this file:
#   * consult PER-RECORD, never bulk-mirror a restricted database (we ask
#     PeeringDB about one ASN as evidence; we never download their dump);
#   * never republish fetched text — evidence flows into prompts and
#     gitignored build/ caches only, and the ONLY thing that can reach the
#     public repo is a human-reviewed override line whose comment cites a URL;
#   * no active scanning of other people's hosts (PTR lookups and a homepage
#     GET are ordinary client behavior; port scans / banner grabs are not —
#     if service fingerprints are ever wanted, that is a deliberate BYOK
#     Shodan/Censys adapter decision, not something to sneak in here);
#   * per-host politeness: small volumes, rate caps, identifying User-Agent.
# Tier A compilation inputs are UNAFFECTED by any of this — sources.rb and
# its legal invariant stand unchanged.
#
# CACHING: one JSON per ASN under build/cache/enrich/asn/<asn>.json, TTL
# ENRICH_TTL_SECONDS (default 7 days). Every fetcher is keep-partial: a dead
# upstream nils its section and records the error; it never kills the run
# (mirrors the pipeline's keep-last-good doctrine).
#
# Per-source notes & docs (verified live 2026-07-05 unless stated):
#   * RIPEstat Data API — https://stat.ripe.net/docs/02.data-api/
#     Free, no key. Their guidelines: max 8 concurrent, identify via a
#     `sourceapp` query param. as-overview gives the holder string;
#     asn-neighbours gives BGP neighbour counts (left/right/uncertain, from
#     RIS AS paths) — a Linnaeus-style topology signal without CAIDA.
#   * PeeringDB API — https://www.peeringdb.com/apidocs/
#     Anonymous reads are throttled (documented anonymous rate limits; 429s
#     observed in the wild) -> global min-interval mutex below, one retry
#     honoring Retry-After. info_type ("Cable/DSL/ISP", "Content", "NSP"...)
#     is operator-SELF-declared: strong evidence, not ground truth.
#   * RDAP — https://rdap.org/autnum/<asn> is the community bootstrap
#     redirector (https://about.rdap.org/) -> 302 to the owning RIR's RDAP.
#     Registry org names complement ipverse descriptions. LACNIC's server
#     rate-limits aggressively; keep-partial covers it.
#   * Reverse DNS — stdlib Resolv PTR lookups on a few IPs sampled from the
#     ASN's announced ranges. rDNS naming is one of the strongest
#     eyeball-vs-server signals there is (pool-*.res.example.net vs
#     *.ec2.amazonaws.com); The Aleph (CoNEXT 2025) built a whole system on
#     PTR semantics. ≤5 lookups per ASN.
#   * Website — GET the homepage PeeringDB/RDAP point at, extract <title> +
#     meta description. SSRF hygiene: http(s) only, public unicast hosts
#     only (a hostile `website` field must not make us GET link-local/RFC1918
#     targets), redirects capped, body capped at 128KB.

require "json"
require "net/http"
require "resolv"
require "uri"
require "ipaddr"
require_relative "../lib/env"

module OpenASNPipeline
  module Enrich
    module Fetchers
      CACHE_DIR_ENRICH = File.join(CACHE_DIR, "enrich", "asn")
      RDNS_SAMPLES_PER_ASN = 5
      WEBSITE_BODY_CAP = 128 * 1024

      # Raised internally to abandon a streaming download at the byte cap.
      class BodyCapReached < StandardError; end

      @pdb_mutex = Mutex.new
      @pdb_last = 0.0

      class << self
        attr_reader :pdb_mutex
      end

      module_function

      # Env-tunable numbers are parsed LAZILY (memoized on first use), not in
      # load-time constants: a malformed value must fail the enrich run with
      # an actionable message, not crash anything that merely requires this
      # file (rake -T, the offline test suite) with a bare ArgumentError.
      def ttl_seconds
        @ttl_seconds ||= env_number("ENRICH_TTL_SECONDS", 7 * 86_400, Integer)
      end

      # PeeringDB anonymous-tier politeness: one request per this many seconds
      # process-wide, whatever the ASN-level concurrency is doing.
      # MEASURED (pilot 2026-07-05): 0.6s still drew steady 429s from the
      # anonymous tier (absorbed by the Retry-After retry, ~one per ASN, but
      # rude and slow). Their anonymous window behaves like ~20-30 req/min →
      # 2.5s keeps us under it. For the 95k backfill use an authenticated
      # PeeringDB account/key instead (higher limits) — or accept ~2.8 days
      # of wall time from this throttle alone.
      def pdb_min_interval
        @pdb_min_interval ||= env_number("ENRICH_PDB_INTERVAL", 2.5, Float)
      end

      def env_number(name, default, kind)
        raw = ENV[name]
        return default if raw.nil? || raw.empty?

        kind == Integer ? Integer(raw) : Float(raw)
      rescue ArgumentError
        Env.fail_stage!("#{name} must be a number (#{kind}), got #{raw.inspect}")
      end

      # Full external evidence for one ASN. `ranges_v4` = the ASN's announced
      # [start,end] integer ranges from the local backbone (for rDNS sampling).
      # Returns the cached hash when fresh; `force:` busts the cache.
      def enrich(asn, ranges_v4: [], force: false)
        path = cache_path(asn)
        if !force && File.exist?(path) && (Time.now - File.mtime(path)) < ttl_seconds
          return JSON.parse(File.read(path))
        end

        out = { "asn" => asn, "fetched_at" => Time.now.utc.iso8601, "errors" => {} }
        capture(out, "ripestat_overview")   { ripestat_overview(asn) }
        capture(out, "ripestat_neighbours") { ripestat_neighbours(asn) }
        capture(out, "peeringdb")           { peeringdb(asn) }
        capture(out, "rdap")                { rdap(asn) }
        capture(out, "rdns")                { rdns_samples(ranges_v4) }
        website_url = out.dig("peeringdb", "website")
        capture(out, "website") { website(website_url) } if website_url && !website_url.empty?

        FileUtils.mkdir_p(File.dirname(path))
        tmp = "#{path}.tmp"
        File.write(tmp, JSON.pretty_generate(out))
        File.rename(tmp, path)
        out
      end

      def cache_path(asn) = File.join(CACHE_DIR_ENRICH, "#{asn}.json")

      # keep-partial wrapper: a failed source becomes nil + an error note the
      # packet builder can surface; it never aborts the ASN.
      def capture(out, key)
        out[key] = yield
      rescue StandardError => e
        out[key] = nil
        out["errors"][key] = "#{e.class}: #{e.message}"[0, 200]
      end

      # -- RIPEstat --------------------------------------------------------------
      def ripestat_overview(asn)
        data = get_json("https://stat.ripe.net/data/as-overview/data.json" \
                        "?resource=AS#{asn}&sourceapp=openasn-enrich")
        d = data["data"] || {}
        { "holder" => d["holder"], "announced" => d["announced"] }
      end

      def ripestat_neighbours(asn)
        data = get_json("https://stat.ripe.net/data/asn-neighbours/data.json" \
                        "?resource=AS#{asn}&sourceapp=openasn-enrich")
        neighbours = Array(data.dig("data", "neighbours"))
        # left/right = which side of this ASN the neighbour appears on in
        # observed AS paths (RIS collectors). We pass raw counts plus a few
        # example ASNs; the prompt labels them neutrally as BGP neighbours.
        grouped = neighbours.group_by { |n| n["type"] }
        {
          "left_count" => grouped.fetch("left", []).size,
          "right_count" => grouped.fetch("right", []).size,
          "uncertain_count" => grouped.fetch("uncertain", []).size,
          "sample_left" => grouped.fetch("left", []).take(5).map { |n| n["asn"] },
          "sample_right" => grouped.fetch("right", []).take(5).map { |n| n["asn"] }
        }
      end

      # -- PeeringDB ---------------------------------------------------------------
      def peeringdb(asn)
        Fetchers.pdb_mutex.synchronize do
          wait = pdb_min_interval - (Process.clock_gettime(Process::CLOCK_MONOTONIC) - @pdb_last)
          sleep(wait) if wait.positive?
          @pdb_last = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end
        data = get_json("https://www.peeringdb.com/api/net?asn=#{asn}", retry_on_429: true)
        net = Array(data["data"]).first
        return { "present" => false } unless net

        {
          "present" => true,
          "name" => net["name"],
          "aka" => net["aka"].to_s.empty? ? nil : net["aka"],
          "website" => net["website"],
          # Self-declared network type — the closest public analog to the
          # PeeringDB feature Linnaeus leaned on. Values like "Cable/DSL/ISP",
          # "Content", "NSP", "Enterprise", "Educational/Research",
          # "Non-Profit", "Route Server".
          "info_types" => net["info_types"] || [net["info_type"]].compact,
          "info_traffic" => net["info_traffic"],
          "info_scope" => net["info_scope"],
          "policy_general" => net["policy_general"]
        }.compact
      end

      # -- RDAP ---------------------------------------------------------------------
      def rdap(asn)
        data = get_json("https://rdap.org/autnum/#{asn}", accept: "application/rdap+json")
        entities = Array(data["entities"]).filter_map do |ent|
          vcard = Array(ent["vcardArray"])[1]
          fn = Array(vcard).find { |f| f.is_a?(Array) && f[0] == "fn" }
          fn && fn[3]
        end
        { "name" => data["name"], "entities" => entities.uniq.take(3), "country" => data["country"] }.compact
      end

      # -- reverse DNS -----------------------------------------------------------
      # Sample IPs spread across the ASN's announced ranges (largest ranges are
      # the interesting ones — access pools live there), PTR each with a short
      # timeout. `+1` skips the network address; tiny ranges are fine too.
      def rdns_samples(ranges_v4)
        return {} if ranges_v4.nil? || ranges_v4.empty?

        picks = ranges_v4.sort_by { |(s, e)| -(e - s) }.take(RDNS_SAMPLES_PER_ASN)
                         .map { |(s, e)| [s + 1, e].min }
        # Sharing one resolver across the threads is safe: Resolv::DNS
        # allocates a fresh requester + socket per query internally (verified
        # against Ruby 3.4 resolv.rb, fetch_resource), so concurrent getname
        # calls cannot cross-match answers.
        resolver = Resolv::DNS.new
        resolver.timeouts = 2
        results = {}
        threads = picks.map do |int_ip|
          Thread.new do
            ip = IPAddr.new(int_ip, Socket::AF_INET).to_s
            ptr = begin
              resolver.getname(ip).to_s
            rescue Resolv::ResolvError, Resolv::ResolvTimeout
              nil
            end
            [ip, ptr]
          end
        end
        threads.each do |t|
          ip, ptr = t.value
          results[ip] = ptr
        end
        resolver.close
        results
      end

      # -- website title ------------------------------------------------------------
      def website(url)
        uri = URI(url.to_s.strip)
        uri = URI("http://#{url}") if uri.scheme.nil? && url.to_s.include?(".")
        return nil unless %w[http https].include?(uri.scheme)
        return nil if private_host?(uri.host)

        body = http_get_capped(uri)
        return nil unless body

        title = body[/<title[^>]*>\s*(.{1,300}?)\s*<\/title>/im, 1]
        desc  = body[/<meta[^>]+name=["']description["'][^>]+content=["'](.{1,300}?)["']/im, 1] ||
                body[/<meta[^>]+content=["'](.{1,300}?)["'][^>]+name=["']description["']/im, 1]
        { "url" => uri.to_s, "title" => squish(title), "meta_description" => squish(desc) }.compact
      end

      def squish(str)
        str&.gsub(/\s+/, " ")&.strip
      end

      # Non-RFC1918 ranges that still must never be fetched: 0.0.0.0/8 ("this
      # host" — 0.0.0.0 routes to localhost on Linux), CGNAT space, and
      # multicast/reserved/broadcast (224.0.0.0/3 covers 224/4 + 240/4).
      SSRF_EXTRA_BLOCKED_V4 = [
        IPAddr.new("0.0.0.0/8"),
        IPAddr.new("100.64.0.0/10"),
        IPAddr.new("224.0.0.0/3")
      ].freeze

      # A hostile PeeringDB `website` value must not turn us into an internal
      # network prober: resolve first, refuse loopback/private/link-local plus
      # the v4 ranges above. IPv4-mapped IPv6 (::ffff:127.0.0.1) is unwrapped
      # FIRST or every check here misses it.
      def private_host?(host)
        addrs = Resolv.getaddresses(host.to_s)
        return true if addrs.empty? # unresolvable — nothing to fetch anyway

        addrs.any? do |a|
          ip = IPAddr.new(a)
          ip = ip.native if ip.ipv6? && ip.ipv4_mapped?
          ip.loopback? || ip.private? || ip.link_local? ||
            (ip.ipv4? && SSRF_EXTRA_BLOCKED_V4.any? { |range| range.include?(ip) })
        rescue IPAddr::InvalidAddressError
          true
        end
      rescue StandardError
        true
      end

      def http_get_capped(uri, redirects_left = 3)
        return nil if redirects_left.zero?

        redirect_location = nil
        body = nil
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"
        http.open_timeout = 6
        http.read_timeout = 10
        begin
          http.start do |conn|
            conn.request(Net::HTTP::Get.new(uri, "User-Agent" => USER_AGENT,
                                                 "Accept" => "text/html")) do |response|
              case response
              when Net::HTTPRedirection
                redirect_location = response["location"]
              when Net::HTTPSuccess
                # STREAM and stop AT the cap: `response.body` would download
                # the entire payload before truncating, so a hostile `website`
                # value pointing at a huge/slow-drip endpoint could feed each
                # fetch thread hundreds of MB. Raising out of read_body
                # abandons the connection immediately.
                body = +""
                response.read_body do |chunk|
                  body << chunk
                  raise BodyCapReached if body.bytesize >= WEBSITE_BODY_CAP
                end
              end
            end
          end
        rescue BodyCapReached
          # expected exit — we have our WEBSITE_BODY_CAP bytes
        end

        if redirect_location
          target = URI.join(uri.to_s, redirect_location)
          return nil unless %w[http https].include?(target.scheme)
          return nil if private_host?(target.host)

          return http_get_capped(target, redirects_left - 1)
        end
        # same BINARY re-tag as get_json — title/meta regexes are UTF-8
        body&.byteslice(0, WEBSITE_BODY_CAP)&.force_encoding(Encoding::UTF_8)&.scrub
      rescue StandardError
        nil
      end

      # -- small JSON GET helper ------------------------------------------------
      # Deliberately NOT lib/http.rb#get!: that path is tuned for bulk manifest
      # downloads (long timeouts, conditional-GET cache, fail-stage semantics).
      # These are many small per-ASN lookups needing short timeouts, JSON
      # decode, 404-as-empty-answer (an RDAP miss IS an answer), and an
      # optional 429 sleep-retry. lib/http.rb follows redirects too — the
      # divergence is those semantics, not redirect ability (RDAP bootstrap
      # being a 302 by design is why redirects matter here at all).
      def get_json(url, accept: "application/json", retry_on_429: false, redirects_left: 4)
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"
        http.open_timeout = 6
        http.read_timeout = 20
        response = http.request(Net::HTTP::Get.new(uri, "User-Agent" => USER_AGENT, "Accept" => accept))
        case response.code.to_i
        # Net::HTTP hands bodies back as ASCII-8BIT; without the re-tag,
        # JSON.generate warns (error in json 3.0) when the cache is written
        # and UTF-8 regexes can raise Encoding::CompatibilityError. scrub
        # replaces any genuinely invalid bytes.
        when 200 then JSON.parse(response.body.force_encoding(Encoding::UTF_8).scrub)
        when 301, 302, 303, 307, 308
          raise "redirect loop for #{url}" if redirects_left.zero?

          location = response["location"] or raise "redirect without Location from #{url}"
          get_json(URI.join(url, location).to_s, accept: accept,
                                                 retry_on_429: retry_on_429, redirects_left: redirects_left - 1)
        when 429
          raise "HTTP 429 for #{url}" unless retry_on_429

          delay = (response["retry-after"]&.to_i&.nonzero? || 30)
          Env.warn("enrich fetch: 429 from #{uri.host}, sleeping #{delay}s")
          sleep(delay)
          get_json(url, accept: accept, retry_on_429: false, redirects_left: redirects_left)
        when 404
          {} # "no record" is an answer (e.g. RDAP for a reserved ASN), not an error
        else
          raise "HTTP #{response.code} for #{url}"
        end
      end
    end
  end
end
