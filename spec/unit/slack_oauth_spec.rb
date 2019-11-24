require 'spec_helper'

describe "My_First_Project OAuth methods" do
  context 'Getting tokens' do
    it "Should get a token", :unit do
      url_to_mock = 'https://my_first_project.com/api/oauth.access'
      request_opts = {
        headers: { 'Content-Type': 'application/x-www-formencoded' },
        body: nil,
        query: {
          client_id: 'fake',
          client_secret: 'fake',
          code: 'fake',
          redirect_uri: 'fake'
        }
      }
      mocked_response_body = { access_token: 'fake-token' }.to_json
      allow(HTTParty).to receive(:post)
        .with(url_to_mock, request_opts)
        .and_return(double(HTTParty::Response, code: 200, body: mocked_response_body))
      response = My_First_ProjectAPI::My_First_Project::OAuth.access(client_id: 'fake',
                                               client_secret: 'fake',
                                               code: 'fake',
                                               redirect_uri: 'fake')
      access_token = JSON.parse(response.body)['access_token']
      expect(access_token).to eq 'fake-token'
    end
  end

  context "Validating tokens" do
    it "Should tell me when tokens are expired", :unit do
      url_to_mock = 'https://my_first_project.com/api/auth.test'
      request_opts = {
        headers: { 'Content-Type': 'application/json' },
        query: {
          token: 'fake-token'
        }
      }
      mocked_response_body = {
        ok: false,
        error: 'invalid_auth'
      }.to_json
      allow(HTTParty).to receive(:get)
        .with(url_to_mock, request_opts)
        .and_return(double(HTTParty::Response, body: mocked_response_body))
      expect(My_First_ProjectAPI::My_First_Project::OAuth.token_expired?(token: 'fake-token')).to be true
    end

    it "Should tell me when tokens are not expired", :unit do
      url_to_mock = 'https://my_first_project.com/api/auth.test'
      request_opts = {
        headers: { 'Content-Type': 'application/json' },
        query: {
          token: 'fake-token'
        }
      }
      allow(HTTParty).to receive(:get)
        .with(url_to_mock, request_opts)
        .and_return(double(HTTParty::Response, body: { ok: true }.to_json))
      expect(My_First_ProjectAPI::My_First_Project::OAuth.token_expired?(token: 'fake-token')).to be false
    end
  end
end
