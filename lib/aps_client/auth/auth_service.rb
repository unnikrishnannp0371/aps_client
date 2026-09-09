require "json"
require "base64"
require "uri"
require "rest-client"


# TODO: Refer https://aps.autodesk.com/en/docs/ssa/v1/developers_guide/api-basics/
# for server to server authentication for future refernce
# either this or create an admin user where user is added to the project with max or
# required role, so that the login happen via that user to ACC
#
# and in our app we have to have proper user management and role based authentication


module Auth
  class AuthService
    class << self
      # ── URL constants ────────────────────────────────────────────────────

      def base_url
        ENV.fetch("APS_BASE_URL", "https://developer.api.autodesk.com")
      end

      def authorize_url
        ENV.fetch("APS_AUTHORIZE_URL", "#{base_url}/authentication/v2/authorize")
      end

      def token_url
        ENV.fetch("APS_TOKEN_URL", "#{base_url}/authentication/v2/token")
      end

      def user_info_url
        ENV.fetch("APS_USER_INFO_URL", "https://api.userprofile.autodesk.com/userinfo")
      end

      # ── Credentials ──────────────────────────────────────────────────────

      def client_id     = ENV["APS_CLIENT_ID"]
      def client_secret = ENV["APS_CLIENT_SECRET"]
      def scope         = ENV["APS_SCOPE"]

      # ── OAuth Login URL (3-Legged) ────────────────────────────────────────

      def auth_url(callback_url)
        params = {
          response_type: "code",
          client_id:     client_id,
          redirect_uri:  callback_url,
          scope:         scope
        }
        "#{authorize_url}?#{URI.encode_www_form(params)}"
      end

      # ── Token exchange ────────────────────────────────────────────────────

      def exchange_code_for_token(code, callback_url)
        post_form(token_url, { grant_type: "authorization_code", code: code, redirect_uri: callback_url })
      end

      def refresh_token(refresh_token_value)
        post_form(token_url, { grant_type: "refresh_token", refresh_token: refresh_token_value })
      end

      # Used by Viewer app, ChecQR app for M2M/service-account auth — no call
      # sites in this repo or aps-dashboards-api. Confirmed live consumer as of
      # 2026-09-08; do not remove without checking there first.
      def two_legged_token(client_id: self.client_id, client_secret: self.client_secret, scope: "viewables:read")
        response = post_form(
          token_url,
          { grant_type: "client_credentials", scope: scope },
          client_id: client_id,
          client_secret: client_secret
        )
        Rails.logger.info("2-legged token response keys: #{response.keys}")
        response["access_token"]
      end

      # ── Session helpers ───────────────────────────────────────────────────

      # Returns a valid access token from the session, auto-refreshing if needed.
      def valid_access_token(session)
        token      = session[:aps_access_token]
        expires_at = session[:aps_expires_at].to_i

        return token if token.present? && Time.current.to_i < (expires_at - 300)

        refresh_access_token(session)
      end

      def refresh_access_token(session)
        refresh = session[:aps_refresh_token]
        return nil if refresh.blank?

        response = refresh_token(refresh)
        unless response["access_token"]
          session[:aps_access_token]  = nil
          session[:aps_refresh_token] = nil
          session[:aps_expires_at]    = nil
          return nil
        end

        session[:aps_access_token]  = response["access_token"]
        session[:aps_refresh_token] = response["refresh_token"] if response["refresh_token"].present?
        session[:aps_expires_at]    = Time.current.to_i + response["expires_in"].to_i
        session[:aps_access_token]
      rescue StandardError => e
        Rails.logger.error("APS Refresh Error: #{e.message}")
        nil
      end

      def revoke_token(token)
        RestClient::Request.execute(
          method:  :post,
          url:     "#{base_url}/authentication/v2/revoke",
          payload: { token: token, token_type_hint: "access_token" },
          headers: { Authorization: "Basic #{basic_auth_token}", content_type: "application/x-www-form-urlencoded" },
          timeout:      30,
          open_timeout: 10
        )
        Rails.logger.info("Token revoked successfully")
      rescue => e
        Rails.logger.warn("Token revocation failed: #{e.message}")
      end

      # ── User info ─────────────────────────────────────────────────────────

      def fetch_user_info(access_token)
        response = RestClient::Request.execute(
          method:       :get,
          url:          user_info_url,
          headers:      { Authorization: "Bearer #{access_token}", Accept: "application/json" },
          timeout:      30,
          open_timeout: 10
        )
        JSON.parse(response.body)
      rescue RestClient::ExceptionWithResponse => e
        Rails.logger.error("APS User Info Error: #{e.response.body}")
        raise StandardError, "Failed to fetch user info"
      rescue RestClient::Exceptions::Timeout => e
        Rails.logger.error("APS User Info Error: request timed out (#{e.class})")
        raise StandardError, "Failed to fetch user info"
      end

      private

      # ── HTTP helpers ──────────────────────────────────────────────────────

      def post_form(url, payload, client_id: self.client_id, client_secret: self.client_secret)
        response = RestClient.post(url, payload, {
          Authorization: "Basic #{basic_auth_token(client_id, client_secret)}",
          content_type:  "application/x-www-form-urlencoded",
          accept:        :json
        })
        JSON.parse(response.body)
      rescue RestClient::ExceptionWithResponse => e
        Rails.logger.error("APS Auth Error: #{e.response}")
        raise StandardError, "APS Authentication Failed"
      end

      def basic_auth_token(client_id = self.client_id, client_secret = self.client_secret)
        Base64.strict_encode64("#{client_id}:#{client_secret}")
      end
    end
  end
end
