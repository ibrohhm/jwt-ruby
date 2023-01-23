class ApplicationController < ActionController::API
  RSA_PRIVATE = OpenSSL::PKey::RSA.generate 2048
  RSA_PUBLIC = RSA_PRIVATE.public_key

  def authorize
    begin
      auth = request.headers['Authorization']
      token = auth.split(' ').last
      decoded_token = JWT.decode(token, RSA_PUBLIC, true, { algorithm: 'RS256' })[0]

      @current_user = User.find decoded_token['resource_owner_id']
    rescue JWT::VerificationError
      render :json => { error: 'token not valid' }, :status => :unauthorized
    rescue JWT::ExpiredSignature
      render :json => { error: 'token already expired' }, :status => :unauthorized
    rescue StandardError => e
      render :json => { error: e.message }, :status => :unauthorized
    end
  end

  def not_found
    render :json => { error: 'User not found' }, :status => :unprocessable_entity
  end

  def render_error(error)
    render :json => { error: error.message }, :status => :internal_server_error
  end
end
