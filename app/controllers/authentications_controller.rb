class AuthenticationsController < ApplicationController
  def login
    @user = User.find_by(email: params[:email])
    if @user&.authenticate(params[:password])
      render :json => { username: @user.username, token: generate_token, exp: payload[:exp] }, :status => :ok
    else
      render :json => { error: 'You are not authorized to access this resource' }, :status => :unauthorized
    end
  end

  private

  def payload
    { resource_owner_id: @user.id, exp: Time.now.to_i + 3600 }
  end

  def generate_token
    JWT.encode payload, RSA_PRIVATE, 'RS256'
  end
end
