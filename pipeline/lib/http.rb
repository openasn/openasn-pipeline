# frozen_string_literal: true

# Conditional-GET HTTP client with an on-disk cache and keep-last-good
# semantics. Every upstream fetch in the pipeline goes through this.
#
# Behavior contract (matches PRD "keep last-good on failure"):
#   * 200        -> body written atomically to cache, ETag/Last-Modified saved
#   * 304        -> cached copy reused ("not modified")
#   * error/5xx  -> if a cached copy exists: WARN and reuse it (stale-ok)
#                   if not: raise (a first build with a dead source must fail)
#
# Gotchas encoded here (each observed during research, see README):
#   * GitHub release-asset downloads redirect to objects.githubusercontent.com /
#     release-assets.githubusercontent.com - we must follow cross-host redirects.
#   * Some endpoints 403 UA-less clients - we always send USER_AGENT.
#   * api.github.com unauthenticated is limited to 60 req/hr/IP - the pipeline
#     therefore never calls api.github.com; everything comes from
#     raw.githubusercontent.com or releases/download/ URLs.

require "net/http"
require "uri"
require "digest"
require_relative "env"

module OpenASNPipeline
  class Http
    MAX_REDIRECTS = 5
    OPEN_TIMEOUT  = 15
    READ_TIMEOUT  = 120 # origin-asn-ipv4.csv is ~26MB, as.json ~70MB
    RETRIES       = 3

    StateEntry = Struct.new(:etag, :last_modified, :fetched_at, :sha256, keyword_init: true)

    def initialize(cache_dir: CACHE_DIR)
      @cache_dir  = cache_dir
      @state_path = File.join(cache_dir, "http-state.json")
      @state      = load_state
    end

    # Fetch `url` into the cache under `key` (a relative filename like
    # "sapics/origin-asn-ipv4-num.csv"). Returns the absolute cached path.
    #
    # offline: true skips the network entirely and requires a cached copy
    # (used by `rake build OFFLINE=1` for fast local iteration and tests).
    def fetch(url, key, offline: false)
      path = cache_path(key)
      if offline
        return path if File.exist?(path)
        Env.fail_stage!("offline mode but no cached copy of #{key}")
      end

      entry = @state[key]
      headers = { "User-Agent" => USER_AGENT, "Accept-Encoding" => "identity" }
      # Conditional GET: only when we still hold the previous body.
      if entry && File.exist?(path)
        headers["If-None-Match"] = entry.etag if entry.etag
        headers["If-Modified-Since"] = entry.last_modified if entry.last_modified
      end

      attempt = 0
      begin
        attempt += 1
        response = get_following_redirects(url, headers)
        case response
        when Net::HTTPNotModified
          Env.log("fetch #{key}: 304 not modified (cached #{format_age(entry&.fetched_at)})")
          path
        when Net::HTTPSuccess
          write_atomically(path, response.body)
          @state[key] = StateEntry.new(
            etag: response["etag"],
            last_modified: response["last-modified"],
            fetched_at: Time.now.utc.iso8601,
            sha256: Digest::SHA256.hexdigest(response.body)
          )
          save_state
          Env.log("fetch #{key}: 200 (#{human_size(response.body.bytesize)})")
          path
        else
          raise "HTTP #{response.code} for #{url}"
        end
      rescue StandardError => e
        if attempt < RETRIES
          sleep(2**attempt) # 2s, 4s backoff; upstreams are third parties, be gentle
          retry
        end
        # Keep-last-good: a transient upstream failure must not kill the
        # nightly build if we still have yesterday's data.
        if File.exist?(path)
          Env.warn("fetch #{key}: FAILED (#{e.message}); using stale cache from #{@state[key]&.fetched_at || 'unknown time'}")
          path
        else
          Env.fail_stage!("fetch #{key}: FAILED with no cached fallback: #{e.message}")
        end
      end
    end

    # Plain GET returning the body string (no cache). For small probe files
    # like upstream LICENSE files where we always want the live copy.
    def get!(url)
      response = get_following_redirects(url, { "User-Agent" => USER_AGENT })
      raise "HTTP #{response.code} for #{url}" unless response.is_a?(Net::HTTPSuccess)

      response.body
    end

    # Like #fetch, but a 404 is a legitimate answer (nil), not a failure.
    # Used for ipverse as-ip-blocks per-ASN files: an override ASN that
    # announces no prefixes simply has no file there. Negative results are
    # cached as empty sentinel files so we don't re-ask upstream nightly.
    def fetch_optional(url, key, offline: false)
      path = cache_path(key)
      sentinel = "#{path}.404"
      # A 404 sentinel expires after 7 days: ASNs do start announcing
      # prefixes, and a stale "not found" must not hide them forever.
      if File.exist?(sentinel) && Time.now - File.mtime(sentinel) > 7 * 86_400
        File.delete(sentinel)
      end
      if offline || File.exist?(sentinel)
        return File.exist?(path) ? path : nil
      end

      response = get_following_redirects(url, { "User-Agent" => USER_AGENT })
      case response
      when Net::HTTPSuccess
        write_atomically(path, response.body)
        path
      when Net::HTTPNotFound
        File.write(sentinel, Time.now.utc.iso8601)
        nil
      else
        # Transient upstream trouble: reuse cache if we have it, else skip.
        File.exist?(path) ? path : nil
      end
    rescue StandardError
      File.exist?(path) ? path : nil
    end

    def fetched_at(key) = @state[key]&.fetched_at
    def sha256(key)     = @state[key]&.sha256

    private

    def get_following_redirects(url, headers, limit = MAX_REDIRECTS)
      raise "too many redirects for #{url}" if limit.zero?

      uri  = URI(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = OPEN_TIMEOUT
      http.read_timeout = READ_TIMEOUT

      response = http.request(Net::HTTP::Get.new(uri, headers))
      if response.is_a?(Net::HTTPRedirection)
        # Cross-host redirect is the NORM for GitHub release assets
        # (-> objects.githubusercontent.com); drop conditional headers on the
        # hop, the redirect target is a one-off signed URL.
        location = response["location"]
        # Seen in the wild: a 3xx with no Location header (transient edge
        # weirdness). Raise something diagnosable instead of NoMethodError -
        # the retry/keep-last-good layers above handle it.
        raise "HTTP #{response.code} redirect without Location from #{url}" if location.nil?

        location = URI.join(url, location).to_s unless location.start_with?("http")
        return get_following_redirects(location, { "User-Agent" => USER_AGENT }, limit - 1)
      end
      response
    end

    def cache_path(key)
      File.join(@cache_dir, key).tap { |p| FileUtils.mkdir_p(File.dirname(p)) }
    end

    def write_atomically(path, body)
      tmp = "#{path}.tmp"
      File.binwrite(tmp, body)
      File.rename(tmp, path) # atomic on POSIX; readers never see a torn file
    end

    def load_state
      return {} unless File.exist?(@state_path)

      JSON.parse(File.read(@state_path)).transform_values do |h|
        StateEntry.new(**h.transform_keys(&:to_sym))
      end
    rescue JSON::ParserError
      {} # corrupt state file is not fatal; we just refetch everything
    end

    def save_state
      FileUtils.mkdir_p(File.dirname(@state_path))
      File.write(@state_path, JSON.pretty_generate(@state.transform_values(&:to_h)))
    end

    def human_size(bytes)
      bytes > 1_000_000 ? "#{(bytes / 1_000_000.0).round(1)}MB" : "#{(bytes / 1000.0).round(1)}KB"
    end

    def format_age(iso)
      return "age unknown" unless iso

      hours = ((Time.now.utc - Time.parse(iso)) / 3600).round(1)
      "#{hours}h ago"
    end
  end
end
