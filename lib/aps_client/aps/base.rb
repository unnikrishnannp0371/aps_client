# frozen_string_literal: true

module Aps
  class Base
    BASE_URL = ENV.fetch('APS_BASE_URL', 'https://developer.api.autodesk.com')
  end
end
