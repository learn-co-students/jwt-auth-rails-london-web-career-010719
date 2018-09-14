class UserSerializer < ActiveModel::Serializer
  attributes :username, :avatar, :bio
end
