require 'spec_helper'

describe 'My_First_Project API Basics' do
  it 'Should ping back', :unit do
    expected_response = {
      body: { message: 'sup dawg' }.to_json,
      statusCode: 200
    }
    expect(My_First_ProjectAPI::Health.ping).to eq expected_response
  end
end
