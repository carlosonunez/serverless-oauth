require 'json'
require 'my_first_project-api/aws_helpers/api_gateway'

module My_First_ProjectAPI
  class Health
    def self.ping
      AWSHelpers::APIGateway.return_200 body: "sup dawg"
    end
  end
end
