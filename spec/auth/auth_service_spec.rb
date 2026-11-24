# frozen_string_literal: true

RSpec.describe Auth::AuthService do
  let(:token_url)     { 'https://developer.api.autodesk.com/authentication/v2/token' }
  let(:userinfo_url)  { 'https://api.userprofile.autodesk.com/userinfo' }
  let(:callback_url)  { 'http://localhost:3003/api/auth/autodesk/callback' }
  let(:basic_header)  { "Basic #{Base64.strict_encode64('cid:csecret')}" }

  around do |example|
    keys  = %w[APS_CLIENT_ID APS_CLIENT_SECRET APS_SCOPE APS_BASE_URL APS_TOKEN_URL APS_USER_INFO_URL]
    saved = keys.to_h { |k| [k, ENV[k]] }
    keys.each { |k| ENV.delete(k) }
    ENV['APS_CLIENT_ID']     = 'cid'
    ENV['APS_CLIENT_SECRET'] = 'csecret'
    ENV['APS_SCOPE']         = 'openid user-profile:read'
    example.run
  ensure
    saved.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
  end

  # ── Existing behaviour. These must pass on 0.1.7 AND 0.2.0, because the
  # ── Viewer and ChecQR apps depend on it.
  describe 'existing behaviour (must not change)' do
    it 'builds the authorize URL without state exactly as before' do
      expect(described_class.auth_url(callback_url)).to eq(
        'https://developer.api.autodesk.com/authentication/v2/authorize' \
        '?response_type=code&client_id=cid' \
        '&redirect_uri=http%3A%2F%2Flocalhost%3A3003%2Fapi%2Fauth%2Fautodesk%2Fcallback' \
        '&scope=openid+user-profile%3Aread'
      )
    end

    it 'exchanges a code and returns the parsed token response' do
      stub = stub_request(:post, token_url)
             .with(headers: { 'Authorization' => basic_header },
                   body: { 'grant_type' => 'authorization_code', 'code' => 'abc', 'redirect_uri' => callback_url })
             .to_return(status: 200, body: { access_token: 'at', id_token: 'it', expires_in: 3599 }.to_json)

      result = described_class.exchange_code_for_token('abc', callback_url)

      expect(stub).to have_been_requested
      expect(result['access_token']).to eq('at')
      expect(result['expires_in']).to eq(3599)
    end

    it "raises StandardError 'APS Authentication Failed' when the token call is rejected" do
      stub_request(:post, token_url).to_return(status: 400, body: { error: 'invalid_grant' }.to_json)

      expect { described_class.exchange_code_for_token('bad', callback_url) }
        .to raise_error(StandardError, 'APS Authentication Failed')
    end

    it 'returns the parsed user info' do
      stub_request(:get, userinfo_url)
        .with(headers: { 'Authorization' => 'Bearer at' })
        .to_return(status: 200, body: { sub: '3T62', email: 'a@b.c', email_verified: true }.to_json)

      expect(described_class.fetch_user_info('at')).to include('sub' => '3T62', 'email_verified' => true)
    end

    it "raises StandardError 'Failed to fetch user info' on a rejected user info call" do
      stub_request(:get, userinfo_url).to_return(status: 401, body: '{}')

      expect { described_class.fetch_user_info('at') }
        .to raise_error(StandardError, 'Failed to fetch user info')
    end

    it 'two_legged_token returns the access token string with the viewables:read default scope' do
      stub = stub_request(:post, token_url)
             .with(headers: { 'Authorization' => basic_header },
                   body: { 'grant_type' => 'client_credentials', 'scope' => 'viewables:read' })
             .to_return(status: 200, body: { access_token: 'at2', expires_in: 3599 }.to_json)

      expect(described_class.two_legged_token).to eq('at2')
      expect(stub).to have_been_requested
    end
  end

  # ── New in 0.2.0
  describe 'hardening (0.2.0)' do
    describe '.auth_url with state' do
      it 'appends state as the last parameter' do
        url = described_class.auth_url(callback_url, state: 'xyz')
        expect(url).to end_with('&state=xyz')
        expect(url).to start_with(described_class.auth_url(callback_url))
      end

      it 'treats a nil state the same as no state' do
        expect(described_class.auth_url(callback_url, state: nil)).to eq(described_class.auth_url(callback_url))
      end
    end

    describe 'token call errors' do
      it 'raises AuthRejected with status and OAuth error code on a 400' do
        stub_request(:post, token_url)
          .to_return(status: 400, body: { error: 'invalid_grant', error_description: 'x' }.to_json)

        expect { described_class.exchange_code_for_token('bad', callback_url) }
          .to raise_error(ApsErrors::AuthRejected, 'APS Authentication Failed') { |e|
            expect(e.status).to eq(400)
            expect(e.error_code).to eq('invalid_grant')
          }
      end

      it 'tolerates a non-JSON error body' do
        stub_request(:post, token_url).to_return(status: 400, body: '<html>nope</html>')

        expect { described_class.exchange_code_for_token('bad', callback_url) }
          .to raise_error(ApsErrors::AuthRejected) { |e| expect(e.error_code).to be_nil }
      end

      it 'raises RateLimited with retry_after on a 429' do
        stub_request(:post, token_url).to_return(status: 429, headers: { 'Retry-After' => '7' }, body: '{}')

        expect { described_class.exchange_code_for_token('c', callback_url) }
          .to raise_error(ApsErrors::RateLimited) { |e| expect(e.retry_after).to eq(7) }
      end

      it 'raises ServerError on a 5xx' do
        stub_request(:post, token_url).to_return(status: 503, body: '{}')

        expect { described_class.exchange_code_for_token('c', callback_url) }
          .to raise_error(ApsErrors::ServerError, 'APS Authentication Failed')
      end

      it 'raises ConnectionError on a timeout' do
        stub_request(:post, token_url).to_timeout

        expect { described_class.exchange_code_for_token('c', callback_url) }
          .to raise_error(ApsErrors::ConnectionError, 'APS Authentication Failed')
      end

      it 'raises ConnectionError when the host cannot be reached' do
        stub_request(:post, token_url).to_raise(SocketError.new('getaddrinfo failed'))

        expect { described_class.exchange_code_for_token('c', callback_url) }
          .to raise_error(ApsErrors::ConnectionError)
      end

      it 'keeps the original error as the cause' do
        stub_request(:post, token_url).to_return(status: 400, body: '{}')

        expect { described_class.exchange_code_for_token('c', callback_url) }
          .to raise_error(ApsErrors::AuthRejected) { |e| expect(e.cause).to be_a(RestClient::ExceptionWithResponse) }
      end
    end

    describe '.fetch_user_info errors' do
      it 'raises AuthRejected on a 401' do
        stub_request(:get, userinfo_url).to_return(status: 401, body: '{}')

        expect { described_class.fetch_user_info('at') }
          .to raise_error(ApsErrors::AuthRejected, 'Failed to fetch user info') { |e| expect(e.status).to eq(401) }
      end

      it 'raises ConnectionError on a timeout instead of crashing on a nil response' do
        stub_request(:get, userinfo_url).to_timeout

        expect { described_class.fetch_user_info('at') }
          .to raise_error(ApsErrors::ConnectionError, 'Failed to fetch user info')
      end

      it 'raises ServerError on a 5xx' do
        stub_request(:get, userinfo_url).to_return(status: 500, body: 'oops')

        expect { described_class.fetch_user_info('at') }.to raise_error(ApsErrors::ServerError)
      end
    end

    describe '.two_legged_token_response' do
      it 'returns the access token and expires_in for the requested scope' do
        stub = stub_request(:post, token_url)
               .with(body: { 'grant_type' => 'client_credentials', 'scope' => 'account:read account:write' })
               .to_return(status: 200, body: { access_token: 'at3', expires_in: 3599 }.to_json)

        expect(described_class.two_legged_token_response(scope: 'account:read account:write'))
          .to eq(access_token: 'at3', expires_in: 3599)
        expect(stub).to have_been_requested
      end

      it 'requires a scope' do
        expect { described_class.two_legged_token_response }.to raise_error(ArgumentError)
      end

      it 'raises typed errors like the other token calls' do
        stub_request(:post, token_url).to_return(status: 401, body: { error: 'invalid_client' }.to_json)

        expect { described_class.two_legged_token_response(scope: 'x') }
          .to raise_error(ApsErrors::AuthRejected) { |e| expect(e.error_code).to eq('invalid_client') }
      end
    end
  end
end
