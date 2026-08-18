# Mixin for APS REST calls. Include in any service that talks to the
# Autodesk Platform Services API.
#
# Usage:
#   class MyService
#     include ApsHttp
#     def initialize(token:) = @token = token
#   end
#
# All services follow the same pattern:
#   - Instantiated with token: keyword argument
#   - Token stored as @token
#   - HTTP calls pass @token explicitly to get/paginate

module ApsHttp
  # URL-safe query string builder — escapes both keys and values.
  def build_params(opts)
    opts.compact.map { |k, v| "#{CGI.escape(k.to_s)}=#{CGI.escape(v.to_s)}" }.join("&")
  end

  # Paginate through any ACC/APS endpoint that uses offset/limit pagination.
  #
  # @param path         [String]  full path, e.g. "/construction/issues/v1/projects/X/issues"
  # @param access_token [String]  bearer token
  # @param extra_params [Hash]    additional query params merged on every page
  # @param page_size    [Integer] records per page (max depends on endpoint)
  # @yield              [Array]   each page's raw result array (optional)
  # @return             [Array]   all records across all pages
  def paginate(path, access_token, extra_params: {}, page_size: 100)
    all    = []
    offset = 0

    loop do
      params = build_params(extra_params.merge(offset: offset, limit: page_size))
      page   = get("#{path}?#{params}", access_token)
      batch  = page["results"] || []

      yield batch if block_given?
      all.concat(batch)

      total = page.dig("pagination", "totalResults").to_i
      break if all.length >= total || batch.empty?

      offset += page_size
    end

    all
  end

  # Raw GET — raises StandardError on HTTP error responses.
  def get(path, access_token)
    url = "#{Aps::Base::BASE_URL}#{path}"
    response = RestClient::Request.execute(
      method:       :get,
      url:          url,
      headers:      { Authorization: "Bearer #{access_token}", Accept: "application/json" },
      timeout:      30,
      open_timeout: 10
    )
    JSON.parse(response.body)
  rescue RestClient::ExceptionWithResponse => e
    Rails.logger.error("APS HTTP Error [GET #{path}]: #{e.response}")

    # Connection-level failures (timeouts, DNS failures, connection refused)
    # get caught by this rescue but never had an HTTP response at all — prior
    # to this fix, e.response.code below crashed with a confusing
    # NoMethodError instead of surfacing the real failure. This branch is the
    # ONLY change; every case branch below is unchanged, so behavior for
    # actual HTTP error responses (401/403/404/429/5xx) is identical to
    # before for every existing caller, including aps-viewer-api.
    if e.response.nil?
      raise ApsErrors::ConnectionError, "Could not connect to Autodesk API (#{e.class}: #{e.message})"
    end

    case e.response.code
    when 401 then raise ApsErrors::Unauthorized, "Autodesk token invalid or expired"
    when 403 then raise ApsErrors::Forbidden,    "Access denied to this resource"
    when 404 then raise ApsErrors::NotFound,     "Resource not found"
    when 429
      retry_after = e.response.headers[:retry_after]&.to_i
      raise ApsErrors::RateLimited.new("Autodesk API rate limit exceeded", retry_after: retry_after)
    else          raise ApsErrors::ServerError,  "Autodesk API error (#{e.response.code})"
    end
  end
end
