require 'rubygems'
require 'spec'
require "net/http"
require 'time'
require 'yaml'
gem 'actionpack'
gem 'activeresource'
require 'action_controller'
require 'action_controller/test_process'
require 'active_resource'
require 'active_resource/http_mock'

require "#{File.dirname(__FILE__)}/../lib/hmac"



def load_fixture
  YAML.load(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml')))
end


