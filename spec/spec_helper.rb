# frozen_string_literal: true

require 'logger'
require 'webmock/rspec'

# The gem calls Rails.logger. Provide a minimal stand-in so the suite runs
# without loading Rails.
unless defined?(Rails)
  module Rails
    def self.logger = (@logger ||= Logger.new(File::NULL))
  end
end

require 'aps_client'

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = '.rspec_status'

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
