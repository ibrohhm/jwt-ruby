# JWT - RUBY

Implement JWT as token-based auth with ruby-on-rails

## Description

This repo will try to implement JWT as token-based auth to simulate CRUD users with auth token. First, user need to request endpoint `/login` to get access token then the *token* will be used as header params to request any endpoint

## Endpoints

1. `POST /auth/login` -> to retrieve token for specific user
2. `POST /users` -> to create a new user
3. `GET /users` -> to retrieve all users
4. `GET /users/:id` -> to retrieve specific user by id
5. `PATCH /users/:id` -> to update specific user by id
6. `DELETE /users/:id` -> to delete specific user by id

## Implementations

### Initiate Project
initiate project by running `rails new jwt-ruby --api`, rails will automatically generate api project with repo name *jwt-ruby* in your local

### Setup Gemfile and Migrate User

To implement JWT, it need `jwt` gem to encode and decode the token also `bcrypt` gem to secure the users password

Add `jwt` and `bcrypt` gem to gemfile

```
gem 'jwt'
gem 'bcrypt'
```
and then install the dependencies in your local by running `bundle install`

Generate user model by running
```
rails generate model user name:string username:string email:string password_digest:string
```
it will generate model user and migrate file. Attribute `password_digest` is required when using bcrypt (read: [How does has_secure_password work in my model class?](https://stackoverflow.com/questions/15514847/how-does-has-secure-password-work-in-my-model-class) and [has_secure_password](https://apidock.com/rails/v4.0.2/ActiveModel/SecurePassword/ClassMethods/has_secure_password))

then migrate the user model in your local by running
```
rake db:migrate
```

because all endpoint will required auth token, then need to initiate first user to bypass that. Add this line to *db/seeds.rb*

```
# initiate user to bypass auth
User.create(name: 'Admin', username: 'admin', email: 'admin@gmail.com', password: 'admin123')
puts 'the first user has been created'
```
then running `rake db:seed` to initiate the first user

### Auth Controller

Create auth controller to generate token, first generate the controller by running

```
rails generate controller authentications
```

generate private key and store it to constant variable in
*app/controllers/application_controller.rb*
```
RSA_PRIVATE = OpenSSL::PKey::RSA.generate 2048
RSA_PUBLIC = RSA_PRIVATE.public_key
```
RSA_PRIVATE will be used as secret to encode the token and RSA_PUBLIC will be used to decode the token. Detaling auth controller,
*app/controllers/authentications_controller.rb*

```
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
```
encode the token with payload `{ exp: Time.now.to_i + 3600 }` to set expiration time just one hour after token generated. To check the result of the generated token, set the login endpoint in the router,
*config/routes.rb*
```
post 'auth/login', to: 'authentications#login'
```

run the project by running `rails s` and try get token from endpoint
```
curl --location --request POST 'localhost:3000/auth/login' \
--header 'Content-Type: application/json' \
--data-raw '{
    "email": "admin@gmail.com", // email from db/seeds.rb
    "password": "admin123" // password from db/seeds.rb
}'
```

you'll get token detail with expiration time
```
{"username":"admin","token":"eyJhbGciOiJSUzI1NiJ9.eyJyZXNvdXJjZV9vd25lcl9pZCI6MSwiZXhwIjoxNjc0NDUxNzQ5fQ.rI4KjT8QnSf92dGtcju1zlyoY5HKGhOKdHde97zrGFBkrYOokwPZ2Zmebr7RN5735JmWN-nsw3I_LCe1SAXVp836A6own3B9ae_p7zIFh-rV4r7SJMzt_ucbKHXIuRmg_xnlbRzv1YgKtz5aJOEKUbaFPpMKmKECokRS-1m0hwWseW2YxkXqNC54zgGW0Tsi18W9MXRrwgtSWOz784l8vnDz3Dp3SMpBtU4cGxO31S_6J-P9ebOsBkuabiljQl6PEhBszPhPpWuWg0vseFW0h3GycAsIPcRSo9aEXfPWwsrqzN9Dc3C15WfsfsC9_xHXoyc6kxVuMXSEBvmnrGImUA","exp":1674451749}
```

### User Controller
Create user controller to simulate create, read, and update user using auth token

First, generate controller using
```
rails generate controller users
```

and add this line to application controller

*app/controllers/authentications_controller.rb*
```
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
```

method `authorize` will be used as auth validation each time user request the endpoint, method `not_found` and `render_error` will be used as render helper for main controller

Detailing the user controller, implement all method `index`, `show`, `create`, `update`, and `destroy`

*app/controllers/users_controller.rb*
```
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
```

set `before_action :authorize` to call method `authorize` in *app/controllers/application_controller.rb* to validate token each time request user endpoints. Then the last one is add endpoint user in router

*config/routes.rb*
```
resources :users
```

run the project `rails s` and try some endpoints

*endpoint index*
```
curl --location --request GET 'localhost:3000/users' \
--header 'Authorization: Token eyJhbGciOiJSUzI1NiJ9.eyJyZXNvdXJjZV9vd25lcl9pZCI6MSwiZXhwIjoxNjc0NDQzMDMwfQ.CtSR4XtuQcjqFQ4qMUAn_lb5of9eUrNiHPlGSbJuLhCC43XZRRY_ZcAWRfgJrZ7PTLIjgmtL8Lqk9fAqkgLyPrh9ifgAKBhtDXfkjXPFdT3GrRoX_9F96WfZqD29NY0-H6RCm6S3sYlRoJoWs-flRUZyf6dtz3lsNS1uHsjV1VTXOG7lrspKD9E8i7NHzVUNyDIyQEUHVqqxtHxHYMBTwRF_AQQERqYEOfMY0vYJj0GBSAZ5jLQhuIxfB3zHvjHdB5T6r13UYES5zoQLNOrxXPlfLzi_vsP8DuR2mnGvwmtIsUpwLeH_ywe5bMQKOVvBP1DysGb2lTzgOFccfezFgQ'
```

*endpoint show*
```
curl --location --request GET 'localhost:3000/users/1' \
--header 'Authorization: Token eyJhbGciOiJSUzI1NiJ9.eyJyZXNvdXJjZV9vd25lcl9pZCI6MSwiZXhwIjoxNjc0NDQzMDMwfQ.CtSR4XtuQcjqFQ4qMUAn_lb5of9eUrNiHPlGSbJuLhCC43XZRRY_ZcAWRfgJrZ7PTLIjgmtL8Lqk9fAqkgLyPrh9ifgAKBhtDXfkjXPFdT3GrRoX_9F96WfZqD29NY0-H6RCm6S3sYlRoJoWs-flRUZyf6dtz3lsNS1uHsjV1VTXOG7lrspKD9E8i7NHzVUNyDIyQEUHVqqxtHxHYMBTwRF_AQQERqYEOfMY0vYJj0GBSAZ5jLQhuIxfB3zHvjHdB5T6r13UYES5zoQLNOrxXPlfLzi_vsP8DuR2mnGvwmtIsUpwLeH_ywe5bMQKOVvBP1DysGb2lTzgOFccfezFgQ'
```

*endpoint create*
```
curl --location --request POST 'localhost:3000/users' \
--header 'Authorization: Token eyJhbGciOiJSUzI1NiJ9.eyJyZXNvdXJjZV9vd25lcl9pZCI6MSwiZXhwIjoxNjc0NDQzMDMwfQ.CtSR4XtuQcjqFQ4qMUAn_lb5of9eUrNiHPlGSbJuLhCC43XZRRY_ZcAWRfgJrZ7PTLIjgmtL8Lqk9fAqkgLyPrh9ifgAKBhtDXfkjXPFdT3GrRoX_9F96WfZqD29NY0-H6RCm6S3sYlRoJoWs-flRUZyf6dtz3lsNS1uHsjV1VTXOG7lrspKD9E8i7NHzVUNyDIyQEUHVqqxtHxHYMBTwRF_AQQERqYEOfMY0vYJj0GBSAZ5jLQhuIxfB3zHvjHdB5T6r13UYES5zoQLNOrxXPlfLzi_vsP8DuR2mnGvwmtIsUpwLeH_ywe5bMQKOVvBP1DysGb2lTzgOFccfezFgQ' \
--header 'Content-Type: application/json' \
--data-raw '{
    "name": "user",
    "username": "user",
    "email": "user@gmail.com",
    "password": "user123"
}'
```

*endpoint update*
```
curl --location --request PATCH 'localhost:3000/users/2' \
--header 'Authorization: Token eyJhbGciOiJSUzI1NiJ9.eyJyZXNvdXJjZV9vd25lcl9pZCI6MSwiZXhwIjoxNjc0NDQzMDMwfQ.CtSR4XtuQcjqFQ4qMUAn_lb5of9eUrNiHPlGSbJuLhCC43XZRRY_ZcAWRfgJrZ7PTLIjgmtL8Lqk9fAqkgLyPrh9ifgAKBhtDXfkjXPFdT3GrRoX_9F96WfZqD29NY0-H6RCm6S3sYlRoJoWs-flRUZyf6dtz3lsNS1uHsjV1VTXOG7lrspKD9E8i7NHzVUNyDIyQEUHVqqxtHxHYMBTwRF_AQQERqYEOfMY0vYJj0GBSAZ5jLQhuIxfB3zHvjHdB5T6r13UYES5zoQLNOrxXPlfLzi_vsP8DuR2mnGvwmtIsUpwLeH_ywe5bMQKOVvBP1DysGb2lTzgOFccfezFgQ' \
--header 'Content-Type: application/json' \
--data-raw '{
    "name": "user2"
}'
```

*endpoint delete*
```
curl --location --request DELETE 'localhost:3000/users/2' \
--header 'Authorization: Token eyJhbGciOiJSUzI1NiJ9.eyJyZXNvdXJjZV9vd25lcl9pZCI6MSwiZXhwIjoxNjc0NDQzMDMwfQ.CtSR4XtuQcjqFQ4qMUAn_lb5of9eUrNiHPlGSbJuLhCC43XZRRY_ZcAWRfgJrZ7PTLIjgmtL8Lqk9fAqkgLyPrh9ifgAKBhtDXfkjXPFdT3GrRoX_9F96WfZqD29NY0-H6RCm6S3sYlRoJoWs-flRUZyf6dtz3lsNS1uHsjV1VTXOG7lrspKD9E8i7NHzVUNyDIyQEUHVqqxtHxHYMBTwRF_AQQERqYEOfMY0vYJj0GBSAZ5jLQhuIxfB3zHvjHdB5T6r13UYES5zoQLNOrxXPlfLzi_vsP8DuR2mnGvwmtIsUpwLeH_ywe5bMQKOVvBP1DysGb2lTzgOFccfezFgQ'
```