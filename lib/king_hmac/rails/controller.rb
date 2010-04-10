# Integration with Rails
#
class Rails # :nodoc:
  module ControllerFilter # :nodoc:
    module ClassMethods
      # Call within a Rails Controller to initialize HMAC authentication for the controller.
      #
      # * +credentials+ must be a hash that indexes secrets by their access key id.
      # * +options+ supports the following arguments:
      #   * +failure_message+: The text to use when authentication fails.
      #   * +only+: A list off actions to protect.
      #   * +except+: A list of actions to not protect.
      #   * +hmac+: Options for HMAC creation. See AuthHMAC#initialize for options.
      #
      def with_auth_hmac(credentials, options = {})
        unless credentials.nil?
          self.credentials = credentials
          self.authhmac_failure_message = (options.delete(:failure_message) or "HMAC Authentication failed")
          self.authhmac = AuthHMAC.new(self.credentials, options.delete(:hmac))
          before_filter(:hmac_login_required, options)
        else
          $stderr.puts("with_auth_hmac called with nil credentials - authentication will be skipped")
        end
      end
    end

    module InstanceMethods # :nodoc:
      def hmac_login_required
        unless hmac_authenticated?
          response.headers['WWW-Authenticate'] = 'AuthHMAC'
          render :text => self.class.authhmac_failure_message, :status => :unauthorized
        end
      end

      def hmac_authenticated?
        self.class.authhmac.nil? ? true : self.class.authhmac.authenticated?(request)
      end
    end

    unless defined?(ActionController)
      begin
        require 'rubygems'
        gem 'actionpack'
        gem 'activesupport'
        require 'action_controller'
        require 'active_support'
      rescue
        nil
      end
    end

    if defined?(ActionController::Base)
      ActionController::Base.class_eval do
        class_inheritable_accessor :authhmac
        class_inheritable_accessor :credentials
        class_inheritable_accessor :authhmac_failure_message
      end

      ActionController::Base.send(:include, ControllerFilter::InstanceMethods)
      ActionController::Base.extend(ControllerFilter::ClassMethods)
    end
  end
end