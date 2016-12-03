module Doorkeeper
  module JWT
    module Rails
      module Helpers
        extend ActiveSupport::Concern

        def doorkeeper_jwt_authorize!(*scopes)
          @_doorkeeper_scopes = scopes.presence || Doorkeeper.configuration.default_scopes

          unless valid_doorkeeper_jwt_token?
            doorkeeper_render_error
          end
        end

        def valid_doorkeeper_jwt_token?
          doorkeeper_jwt_token && doorkeeper_jwt_token.acceptable?(@_doorkeeper_scopes)
        end

        private

        def doorkeeper_jwt_token
          if token = Doorkeeper::OAuth::Token.from_request(request, *Doorkeeper.configuration.access_token_methods)
            parsed_jwt = Doorkeeper::JWT.validate(token, {})
            return nil if parsed_jwt.empty?
            @_doorkeeper_token ||= Doorkeeper::JWT.configuration.token_deserializer.call parsed_jwt.last, parsed_jwt.first, token
          end
        end
      end
    end
  end
end
