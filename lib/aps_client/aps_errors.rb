# frozen_string_literal: true

module ApsErrors
  class Base            < StandardError; end
  # 401
  class Unauthorized    < Base; end
  # 403
  class Forbidden       < Base; end
  # 404
  class NotFound        < Base; end
  # 5xx
  class ServerError     < Base; end
  # connection-level failure, no HTTP response at all (timeout, DNS, refused)
  class ConnectionError < Base; end

  # A 4xx from the Autodesk authentication or user info endpoints (bad code,
  # bad client credentials, rejected token). error_code is the OAuth "error"
  # value from the response body when there is one, e.g. "invalid_grant".
  class AuthRejected < Base
    attr_reader :status, :error_code

    def initialize(message, status: nil, error_code: nil)
      @status     = status
      @error_code = error_code
      super(message)
    end
  end

  # 429
  class RateLimited < Base
    attr_reader :retry_after

    def initialize(message, retry_after: nil)
      @retry_after = retry_after
      super(message)
    end
  end
end
