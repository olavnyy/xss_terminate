require 'rake'
require 'rake/testtask'
require 'rake/rdoctask'

desc 'Default: run unit tests.'
task :default => :test

desc 'Test the xss_terminate plugin.'
Rake::TestTask.new(:test) do |t|
  t.libs << 'lib'
  t.pattern = 'test/**/*_test.rb'
  t.verbose = true
end

desc 'Generate documentation for the xss_terminate plugin.'
Rake::RDocTask.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = 'xss_terminate'
  rdoc.options << '--line-numbers' << '--inline-source'
  rdoc.rdoc_files.include('README')
  rdoc.rdoc_files.include('lib/**/*.rb')
end

begin
  require 'jeweler'
  Jeweler::Tasks.new do |s|
    s.name = "xss_terminate"
    s.summary = "xss_terminate is a plugin in that makes stripping and sanitizing HTML stupid-simple."
    s.email = "look@recursion.org"
    s.homepage = "http://github.com/look/xss_terminate"
    s.description = "xss_terminate is a plugin in that makes stripping and sanitizing HTML stupid-simple. Install and forget. And forget about forgetting to h() your output, because you won‘t need to anymore."
    s.authors = ["Luke Francl"]
    s.files =  FileList["[A-Z]*", "{lib,test}/**/*", 'lib/jeweler/templates/.gitignore']
    s.add_dependency "html5", ">= 0.10.0"
  end
rescue LoadError
  puts "Jeweler, or one of its dependencies, is not available. Install it with: sudo gem install jeweler"
end