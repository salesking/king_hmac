require 'rack/request'
module KingHmac
  module Rack
    class Middleware

      # === Parameter
      # opts<Hash>::
      # === opts params:
      # keys<Hash{String=>String}>:: Must be an array of accesskey=> secret
      # respond to the [] method and return a secret for access key id
      # only<Array[String]>:: path's to protect
      def initialize(app, opts={})
        @app = app
        @opts = opts
        @plain_error = "HMAC Authentication failed. Get yourself a valid HMAC Key .. Dude .. or ask your admin to get you some credentials"
        @hmac_auth = KingHmac::Auth.new(@opts['keys'])
      end

      def call(env)
        path = env['PATH_INFO']
        do_hmac_check = @opts['only'].detect{|i| path.include?(i) }
        if do_hmac_check
          unless hmac_authenticated?(::Rack::Request.new(env))
            headers = {'Content-Type' => "text/plain",
                      'Content-Length' => "#{@plain_error.length}",
                      'WWW-Authenticate' => 'AuthHMAC'
                      }
            [401, headers, [@plain_error]]
          else #valid credentials
            @app.call(env)
          end
        else # unprotected
          @app.call(env)
        end
      end

      def hmac_authenticated?(request)
        @hmac_auth.authenticated?(request)
      end


    end
  end
end