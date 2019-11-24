require 'capybara'
require 'capybara/dsl'

module Helpers
  module My_First_Project
    module OAuth
      # Use this function to automate updating callback URIs into a service
      # during integration testing.
      def self.update_callback_uri!(callback_uri:)
        "Implement me!"
      end
    end
  end
end
