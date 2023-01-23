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
