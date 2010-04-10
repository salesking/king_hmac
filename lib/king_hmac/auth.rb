module KingHmac
  # This module provides a HMAC Authentication method for HTTP requests. It should work with
  # net/http request classes and CGIRequest classes and hence Rails.
  #
  # It is loosely based on the Amazon Web Services Authentication mechanism but
  # generalized to be useful to any application that requires HMAC based authentication.
  # As a result of the generalization, it won't work with AWS because it doesn't support
  # the Amazon extension headers.
  #
  # === References
  # Cryptographic Hash functions:: http://en.wikipedia.org/wiki/Cryptographic_hash_function
  # SHA-1 Hash function::          http://en.wikipedia.org/wiki/SHA-1
  # HMAC algorithm::               http://en.wikipedia.org/wiki/HMAC
  # RFC 2104::                     http://tools.ietf.org/html/rfc2104
  #
  class Auth
   
    include KingHmac::Headers
   

    @@default_signature_class = KingHmac::CanonicalString

    # Create an KingHmac::Auth instance using the given credential store
    #
    # Credential Store:
    # * Credential store must respond to the [] method and return a secret for access key id
    # 
    # Options:
    # Override default options
    # *  <tt>:service_id</tt> - Service ID used in the AUTHORIZATION header string. Default is KingHmac::Auth.
    # *  <tt>:signature_method</tt> - Proc object that takes request and produces the signature string
    #                                 used for authentication. Default is CanonicalString.
    # Examples:
    #   my_hmac = KingHmac::Auth.new('access_id1' => 'secret1', 'access_id2' => 'secret2')
    #
    #   cred_store = { 'access_id1' => 'secret1', 'access_id2' => 'secret2' }
    #   options = { :service_id => 'MyApp', :signature_method => lambda { |r| MyRequestString.new(r) } }
    #   my_hmac = KingHmac::Auth.new(cred_store, options)
    #   
    def initialize(credential_store, options = nil)
      @credential_store = credential_store

      # Defaults
      @service_id = self.class.name
      @signature_class = @@default_signature_class

      unless options.nil?
        @service_id = options[:service_id] if options.key?(:service_id)
        @signature_class = options[:signature] if options.key?(:signature) && options[:signature].is_a?(Class)
      end
      
      @signature_method = lambda { |r| @signature_class.send(:new, r) }
    end

    # Generates canonical signing string for given request
    #
    # Supports same options as KingHmac::Auth.initialize for overriding service_id and
    # signature method.
    # 
    def self.canonical_string(request, options = nil)
      self.new(nil, options).canonical_string(request)
    end

    # Generates signature string for a given secret
    #
    # Supports same options as KingHmac::Auth.initialize for overriding service_id and
    # signature method.
    # 
    def self.signature(request, secret, options = nil)
      self.new(nil, options).signature(request, secret)
    end

    # Signs a request using a given access key id and secret.
    #
    # Supports same options as KingHmac::Auth.initialize for overriding service_id and
    # signature method.
    # 
    def self.sign!(request, access_key_id, secret, options = nil)
      credentials = { access_key_id => secret }
      self.new(credentials, options).sign!(request, access_key_id)
    end
    
    # Authenticates a request using HMAC
    #
    # Supports same options as KingHmac::Auth.initialize for overriding service_id and
    # signature method.
    # 
    def self.authenticated?(request, access_key_id, secret, options)
      credentials = { access_key_id => secret }
      self.new(credentials, options).authenticated?(request)
    end
    
    # Signs a request using the access_key_id and the secret associated with that id
    # in the credential store.
    #
    # Signing a requests adds an Authorization header to the request in the format:
    #
    #  <service_id> <access_key_id>:<signature>
    #
    # where <signature> is the Base64 encoded HMAC-SHA1 of the CanonicalString and the secret.
    #
    def sign!(request, access_key_id)
      secret = @credential_store[access_key_id]
      raise ArgumentError, "No secret found for key id '#{access_key_id}'" if secret.nil?
      request['Authorization'] = authorization(request, access_key_id, secret)
    end
    
    # Authenticates a request using HMAC
    #
    # Returns true if the request has an KingHmac::Auth Authorization header and
    # the access id and HMAC match an id and HMAC produced for the secret
    # in the credential store. Otherwise returns false.
    #
    def authenticated?(request)
      rx = Regexp.new("#{@service_id} ([^:]+):(.+)$")
      if md = rx.match(authorization_header(request))
        access_key_id = md[1]
        hmac = md[2]
        secret = @credential_store[access_key_id]
        !secret.nil? && hmac == signature(request, secret)
      else
        false
      end
    end

    def signature(request, secret)
      digest = OpenSSL::Digest::Digest.new('sha1')
      Base64.encode64(OpenSSL::HMAC.digest(digest, secret, canonical_string(request))).strip
    end

    def canonical_string(request)
      @signature_method.call(request)
    end
    
    def authorization_header(request)
      find_header(%w(Authorization HTTP_AUTHORIZATION), headers(request))
    end

    def authorization(request, access_key_id, secret)
      "#{@service_id} #{access_key_id}:#{signature(request, secret)}"      
    end
  end
end