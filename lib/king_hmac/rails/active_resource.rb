module ActiveResourceExtension  # :nodoc:
  module BaseHmac # :nodoc:
    def self.included(base)
      base.extend(ClassMethods)

      base.class_inheritable_accessor :hmac_access_id
      base.class_inheritable_accessor :hmac_secret
      base.class_inheritable_accessor :use_hmac
      base.class_inheritable_accessor :hmac_options
    end

    module ClassMethods
      # Call with an Active Resource class definition to sign
      # all HTTP requests sent by that class with the provided
      # credentials.
      #
      # Can be called with either a hash or two separate parameters
      # like so:
      #
      #   class MyResource < ActiveResource::Base
      #     with_auth_hmac("my_access_id", "my_secret")
      #   end
      #
      # or
      #
      #   class MyOtherResource < ActiveResource::Base
      #     with_auth_hmac("my_access_id" => "my_secret")
      #   end
      #
      #
      # This has only been tested with Rails 2.1 and since it is virtually a monkey
      # patch of the internals of ActiveResource it might not work with past or
      # future versions.
      #
      def with_auth_hmac(access_id, secret = nil, options = nil)
        if access_id.is_a?(Hash)
          self.hmac_access_id = access_id.keys.first
          self.hmac_secret = access_id[self.hmac_access_id]
        else
          self.hmac_access_id = access_id
          self.hmac_secret = secret
        end
        self.use_hmac = true
        self.hmac_options = options

        class << self
          alias_method_chain :connection, :hmac
        end
      end

      def connection_with_hmac(refresh = false) # :nodoc:
        c = connection_without_hmac(refresh)
        c.hmac_access_id = self.hmac_access_id
        c.hmac_secret = self.hmac_secret
        c.use_hmac = self.use_hmac
        c.hmac_options = self.hmac_options
        c
      end
    end

    module InstanceMethods # :nodoc:
    end
  end

  module Connection # :nodoc:
    def self.included(base)
      base.send :alias_method_chain, :request, :hmac
      base.class_eval do
        attr_accessor :hmac_secret, :hmac_access_id, :use_hmac, :hmac_options
      end
    end

    def request_with_hmac(method, path, *arguments)
      if use_hmac && hmac_access_id && hmac_secret
        arguments.last['Date'] = Time.now.httpdate if arguments.last['Date'].nil?
        temp = "Net::HTTP::#{method.to_s.capitalize}".constantize.new(path, arguments.last)
        AuthHMAC.sign!(temp, hmac_access_id, hmac_secret, hmac_options)
        arguments.last['Authorization'] = temp['Authorization']
      end

      request_without_hmac(method, path, *arguments)
    end
  end

  unless defined?(ActiveResource)
    begin
      require 'rubygems'
      gem 'activeresource'
      require 'activeresource'
    rescue
      nil
    end
  end

  if defined?(ActiveResource)
    ActiveResource::Base.send(:include, BaseHmac)
    ActiveResource::Connection.send(:include, Connection)
  end
end