class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
  after_destroy :untie_post_from_user


  has_many :posts

  def admin?
    role == "admin"
  end

  def can_update_or_destroy_post post
    id == post.user_id || admin?
  end

  def untie_post_from_user
    Post.where(user_id: id).update(user_id: nil)
  end
end
