require 'rails_sanitize'
require 'xss_terminate'
ActiveRecord::Base.send(:include, XssTerminate)
ActiveRecord::Base.before_validation :sanitize_fields
