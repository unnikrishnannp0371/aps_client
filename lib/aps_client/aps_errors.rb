module ApsErrors
  class Base            < StandardError; end
  class Unauthorized    < Base; end  # 401
  class Forbidden       < Base; end  # 403
  class NotFound        < Base; end  # 404
  class ServerError     < Base; end  # 5xx
  class ConnectionError < Base; end  # connection-level failure, no HTTP response at all (timeout, DNS, refused)

  class RateLimited < Base  # 429
    attr_reader :retry_after

    def initialize(message, retry_after: nil)
      @retry_after = retry_after
      super(message)
    end
  end
end
