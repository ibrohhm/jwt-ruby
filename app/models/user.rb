class User < ApplicationRecord
  has_secure_password
  validates :name, presence: true
  validates :username, presence: true, uniqueness: true
  validates :email, :format => { :with => URI::MailTo::EMAIL_REGEXP }
  validates :password, length: { minimum: 6 }, if: -> { new_record? || password.present? }
end
