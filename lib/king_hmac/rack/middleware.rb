require 'rack/request'
module KingHmac
  module Rack
    class Middleware

      # === Parameter
      # app<Object>:: Another Rack app, just a class responding to .call
      # opts<Hash>:: {'keys'=>{'my_access_key'=>'my_secret'}, 'only'=>['a path', 'backend', 'api'] }
      # === opts params:
      # keys<Hash{String=>String}>:: Multiple sets of accesskey=> secret
      # respond to the [] method and return a secret for access key id
      # only<Array[String]>:: path's to protect ['admin', 'backend', 'api']
      def initialize(app, opts={})
        @app = app
        @opts = opts
        @error = "HMAC Authentication failed. Get yourself a valid HMAC Key .. Dude .. or ask your admin to get you some credentials"
        @hmac_auth = KingHmac::Auth.new(@opts['keys'])
      end

      def call(env)
        path = env['PATH_INFO'] || '' #root path / does not have path info
        do_hmac_check = @opts['only'].detect{|i| path.include?(i) }
        if do_hmac_check
          unless hmac_authenticated?(::Rack::Request.new(env))
            headers = {'Content-Type' => "text/plain",
                      'Content-Length' => "#{@error.length}",
                      'WWW-Authenticate' => 'AuthHMAC'
                      }
            [401, headers, [@error]]
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