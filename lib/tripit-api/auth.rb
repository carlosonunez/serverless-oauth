require 'aws-sdk-dynamodb'
require 'my_first_project-api/aws_helpers/api_gateway'
require 'my_first_project-api/my_first_project'
require 'logger'
require 'securerandom'
require 'dynamoid'

module My_First_ProjectAPI
  module Auth
    class My_First_ProjectToken
      Dynamoid.configure do |config|
        config.namespace = "my_first_project_auth"
        config.logger.level = Logger::FATAL
      end

      include Dynamoid::Document
      table name: :tokens, key: :access_key, read_capacity: 2, write_capacity: 2
      field :access_key
      field :my_first_project_token
    end

    class My_First_ProjectAuthState
      Dynamoid.configure do |config|
        config.namespace = "my_first_project_auth_state"
        config.logger.level = Logger::FATAL
      end

      include Dynamoid::Document
      table name: :state_associations, key: :state_id, read_capacity: 2, write_capacity: 2
      field :access_key
      field :state_id
    end
=begin
    Handle My_First_Project OAuth callbacks.
=end
    def self.handle_callback(event)
      if !self.configure_aws!
        return My_First_ProjectAPI::AWSHelpers::APIGateway.error(
          message: 'Please set APP_AWS_ACCESS_KEY and APP_AWS_SECRET_KEY')
      end
      parameters = event['queryStringParameters']
      code = parameters['code']
      state_id = parameters['state']
      error = parameters['error']
      if !error.nil?
        return My_First_ProjectAPI::AWSHelpers::APIGateway.unauthenticated(
          message: "User denied access to this app.")
      elsif code.nil? and state_id.nil?
        return My_First_ProjectAPI::AWSHelpers::APIGateway.error(
          message: "My_First_Project didn't send a code or state_id upon calling back.")
      else
        callback_url = 'https://' + My_First_ProjectAPI::AWSHelpers::APIGateway.get_endpoint(event) + \
          event['requestContext']['path']
        token_response = My_First_ProjectAPI::My_First_Project::OAuth.access(client_id: ENV['MY_FIRST_PROJECT_APP_CLIENT_ID'],
                                                       client_secret: ENV['MY_FIRST_PROJECT_APP_CLIENT_SECRET'],
                                                       redirect_uri: callback_url,
                                                       code: code)
        if token_response.body.nil?
          return My_First_ProjectAPI::AWSHelpers::APIGateway.error(
            message: 'Unable to get My_First_Project token.')
        end
        token_response_json = JSON.parse(token_response.body)
        if !token_response_json['ok'].nil? and !token_response_json['ok']
          return My_First_ProjectAPI::AWSHelpers::APIGateway.unauthenticated(
            message: "Token request failed: #{token_response_json['error']}"
          )
        end
        token = token_response_json['access_token']
        access_key_from_state = self.get_access_key_from_state(state_id: state_id)
        if access_key_from_state.nil?
          return My_First_ProjectAPI::AWSHelpers::APIGateway.error(
            message: "No access key exists for this state ID: #{state_id}")
        end
        if self.put_my_first_project_token(access_key: access_key_from_state, my_first_project_token: token)
          return My_First_ProjectAPI::AWSHelpers::APIGateway.ok
        else
          return My_First_ProjectAPI::AWSHelpers::APIGateway.error(message: "Unable to save My_First_Project token.")
        end
      end
    end

=begin
    Provide a first step for the authentication flow.
=end
    def self.begin_authentication_flow(event, client_id:)
      if !self.configure_aws!
        return My_First_ProjectAPI::AWSHelpers::APIGateway.error(
          message: 'Please set APP_AWS_ACCESS_KEY and APP_AWS_SECRET_KEY')
      end
      if !self.reauthenticate?(event: event) and self.has_token? event: event
        return My_First_ProjectAPI::AWSHelpers::APIGateway.ok(message: 'You already have a token.')
      end
      scopes_csv = ENV['MY_FIRST_PROJECT_APP_CLIENT_SCOPES'] || "users.profile:read,users.profile:write"
      redirect_uri = "https://#{My_First_ProjectAPI::AWSHelpers::APIGateway.get_endpoint(event)}/callback"
      workspace = self.get_workspace(event)
      state_id = self.generate_state_id
      if workspace.nil?
        workspace_url = "my_first_project.com"
      else
        workspace_url = "#{workspace}.my_first_project.com"
      end
      my_first_project_authorization_uri = [
        "https://#{workspace_url}/oauth/authorize?client_id=#{client_id}",
        "scope=#{scopes_csv}",
        "redirect_uri=#{redirect_uri}",
        "state=#{state_id}"
      ].join '&'
      message = "You will need to authenticate into My_First_Project first; click on or \
copy/paste this URL to get started: #{my_first_project_authorization_uri}"
      if !self.associate_access_key_to_state_id!(event: event,
                                                 state_id: state_id)
        return My_First_ProjectAPI::AWSHelpers::APIGateway.error(
          message: "Couldn't map state to access key.")
      end
      return My_First_ProjectAPI::AWSHelpers::APIGateway.ok(message: message)
    end

    # Retrives a My_First_Project OAuth token from a API Gateway key
    def self.get_my_first_project_token(event:)
      if !self.configure_aws!
        return My_First_ProjectAPI::AWSHelpers::APIGateway.error(
          message: 'Please set APP_AWS_ACCESS_KEY and APP_AWS_SECRET_KEY')
      end
      access_key = self.get_access_key_from_event(event)
      if access_key.nil?
        return My_First_ProjectAPI::AWSHelpers::APIGateway.error(message: 'Access key missing.')
      end
      my_first_project_token = self.get_my_first_project_token_from_access_key(access_key)
      if my_first_project_token.nil?
        return My_First_ProjectAPI::AWSHelpers::APIGateway.not_found(
          message: 'No token exists for this access key.')
      end
      My_First_ProjectAPI::AWSHelpers::APIGateway.ok(
        additional_json: { token: my_first_project_token })
    end

    private
    def self.get_workspace(event)
      begin
        event['queryStringParameters']['workspace']
      rescue
        return nil
      end
    end

    def self.generate_state_id
      SecureRandom.hex
    end

    def self.get_access_key_from_event(event)
      event['requestContext']['identity']['apiKey']
    end

    def self.get_my_first_project_token_from_access_key(access_key)
      begin
        results = My_First_ProjectToken.where(access_key: access_key)
        return nil if results.count == 0
        results.first.my_first_project_token
      rescue Aws::DynamoDB::Errors::ResourceNotFoundException
        My_First_ProjectAPI.logger.warn("My_First_Project tokens table not created yet.")
        return nil
      end
    end

    # Puts a new token and API key into DynamoDB
    def self.put_my_first_project_token(access_key:, my_first_project_token:)
      begin
        mapping = My_First_ProjectToken.new(access_key: access_key,
                                 my_first_project_token: my_first_project_token)
        mapping.save
        return true
      rescue Dynamoid::Errors::ConditionalCheckFailedException
        puts "WARN: This access key already has a My_First_Project token. We will check for \
existing tokens and provide a refresh mechanism in a future commit."
        return true
      rescue Exception => e
        My_First_ProjectAPI.logger.error("We weren't able to save this token: #{e}")
        return false
      end
    end

    def self.has_token?(event:)
      begin
        access_key = self.get_access_key_from_event(event)
        results = My_First_ProjectToken.where(access_key: access_key)
        return nil if results.nil? or results.count == 0
        !results.first.my_first_project_token.nil?
      rescue Exception => e
        My_First_ProjectAPI.logger.warn("Error while querying for an existing token; beware stranger tings: #{e}")
        return false
      end
    end

    def self.reauthenticate?(event:)
      event.dig('queryStringParameters', 'reauthenticate') == 'true'
    end

    # Because the My_First_Project OAuth service invokes /callback after the
    # user successfully authenticates, /callback will not be able to resolve
    # the original client's API key. We use that API key to store their token
    # and (later) their default workspace. This fixes that by creating a
    # table mapping access keys to `state_id`s.
    #
    # This introduces a security vulnerability where someone can change
    # another user's My_First_Project token by invoking
    # /callback (a public method, as required by My_First_Project OAuth) with a correct
    # state ID. We will need to fix that at some point.
    def self.associate_access_key_to_state_id!(event:, state_id:)
      begin
        access_key = self.get_access_key_from_event(event)
      rescue
        puts "WARN: Unable to get access key from context while trying to associate \
access key with state."
        return false
      end

      begin
        association = My_First_ProjectAuthState.new(state_id: state_id,
                                         access_key: access_key)
        association.save
        return true
      rescue Exception => e
        My_First_ProjectAPI.logger.error("Unable to save auth state: #{e}")
        return false
      end
    end

    # Gets an access key from a given state ID
    def self.get_access_key_from_state(state_id:)
      begin
        results = My_First_ProjectAuthState.where(state_id: state_id)
        return nil if results.nil? or results.count == 0
        results.first.access_key
      rescue Aws::DynamoDB::Errors::ResourceNotFoundException
        My_First_ProjectAPI.logger.warn("State associations table not created yet.")
        return nil
      end
    end

    def self.configure_aws!
      if ENV['APP_AWS_SECRET_ACCESS_KEY'].nil? or ENV['APP_AWS_ACCESS_KEY_ID'].nil?
        return false
      end
      begin
        ::Aws.config.update(
          credentials: ::Aws::Credentials.new(ENV['APP_AWS_ACCESS_KEY_ID'],
                                              ENV['APP_AWS_SECRET_ACCESS_KEY']))
        return true
      rescue Exception => e
        My_First_ProjectAPI.logger.error("Unable to configure Aws: #{e}")
        return false
      end
    end
  end
end
