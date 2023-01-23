class ApplicationController < ActionController::API
  RSA_PRIVATE = OpenSSL::PKey::RSA.generate 2048
  RSA_PUBLIC = RSA_PRIVATE.public_key
end
