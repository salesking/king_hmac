require 'rubygems'
require 'rake'
require 'rake/rdoctask'
require 'spec/rake/spectask'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = "king_hmac"
    gem.summary = %Q{A Ruby Gem for authenticating HTTP requests using a HMAC}
    gem.description = %Q{A Ruby Gem for authenticating HTTP requests using a HMAC}
    gem.email = "gl@salesking.eu"
    gem.homepage = "http://github.com/salesking/king_hmac"
    gem.authors = ["Georg Leciejewski"]
    gem.add_development_dependency "rspec", ">= 0"
    # gem is a Gem::Specification... see http://www.rubygems.org/read/chapter/20 for additional settings
  end
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: gem install jeweler"
end

desc 'Default: run specs.'
task :default => :spec

spec_files = Rake::FileList["spec/**/*_spec.rb"]

desc "Run specs"
Spec::Rake::SpecTask.new do |t|
  t.spec_files = spec_files
  t.spec_opts = ["-c"]
end

desc "Generate code coverage"
Spec::Rake::SpecTask.new(:coverage) do |t|
  t.spec_files = spec_files
  t.rcov = true
  t.rcov_opts = ['--exclude', 'spec,/var/lib/gems']
end

desc 'Generate king_hmac documentation.'
Rake::RDocTask.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = 'king_hmac'
  rdoc.options << '--line-numbers' << '--inline-source'
  rdoc.rdoc_files.include('README')
  rdoc.rdoc_files.include('lib/**/*.rb')
end
