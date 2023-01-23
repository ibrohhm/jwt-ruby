class UsersController < ApplicationController
  before_action :authorize

  def index
    render :json => User.all.to_a, :status => :ok
  end

  def show
    return not_found if current_resource.nil?

    render :json => current_resource, :status => :ok
  end

  def create
    user = User.new
  
    begin
      user.assign_attributes(permitted_attribute)
      user.save!
    rescue StandardError => e
      return render_error(e)
    end

    render :json => user, :status => :created
  end

  def update
    return not_found if current_resource.nil?
    
    begin
      current_resource.assign_attributes(permitted_attribute)
      current_resource.save!
    rescue StandardError => e
      return render_error(e)
    end

    render :json => current_resource, :status => :ok
  end

  def destroy
    return not_found if current_resource.new_record?

    current_resource.delete
    render :json => { message: 'ok' }, :status => :ok
  end

  private

  def current_resource
    @current_resource ||= User.find_by(id: params[:id])
  end

  def permitted_attribute
    params.permit(:name, :username, :email, :password)
  end
end
