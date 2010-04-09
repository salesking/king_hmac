module Hmac
  module Headers # :nodoc:
    # Gets the headers for a request.
    #
    # Attempts to deal with known HTTP header representations in Ruby.
    # Currently handles net/http and Rails.
    #
    def headers(request)
      if request.respond_to?(:headers)
        request.headers
      elsif request.respond_to?(:env) && request.env
        request.env
      elsif request.respond_to?(:[])
        request
      else
        raise ArgumentError, "Don't know how to get the headers from #{request.inspect}"
      end
    end
    
    def find_header(keys, headers)
      val = keys.map do |key|
        headers[key]
      end.compact.first
      var = 'adsf'
      val
    end
  end
end