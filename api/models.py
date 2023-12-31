from django.db import models

# Create your models here.
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser

from api.manager import UserManager


# Create your models here.


class User(AbstractUser):
    username = None
    email = models.EmailField(unique=True)
    gender = models.CharField(max_length=10, null=True)
    birthDate = models.DateField(default=timezone.now)
    age = models.IntegerField(default=18)
    phone_number = models.CharField(max_length=10, null=True)
    verification_status = models.CharField(max_length=20, default='pending')
    verification_slug = models.CharField(max_length=100, null=True)
    otp = models.CharField(max_length=6, null=True)
    otp_validity = models.BooleanField(default=False)
    phoneOTP = models.CharField(max_length=6, null=True)
    phoneOTP_validity = models.BooleanField(default=False)
    resetToken = models.CharField(max_length=50, default="none")

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    objects = UserManager()

# user support table


class user_support(models.Model):
    help_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey('User', on_delete=models.CASCADE)
    issue_message = models.TextField()
    image = models.ImageField(upload_to='user_support/images/')


# user address table


class userAddress(models.Model):
    address_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey('User', on_delete=models.CASCADE)
    country = models.CharField(max_length=30)
    state = models.CharField(max_length=30)
    city = models.CharField(max_length=30)
    street = models.CharField(max_length=30)
    zip_code = models.IntegerField()
    house_no = models.CharField(max_length=40)

# seller table


class seller(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=150,null=True)
    email = models.EmailField(null=False,unique=True)
    phone = models.IntegerField(null=True)
    # seller_address=models.TextField()
    password = models.CharField(max_length=128)
    # seller_image=models.ImageField(upload_to=)
    verification_status = models.CharField(
        max_length=20, default='pending')
    otp = models.CharField(max_length=6, null=True)
    otp_validity = models.BooleanField(default=False)
    seller_verification_slug = models.CharField(max_length=100,null=True)
    seller_status = models.CharField(max_length=20, default='active')
    resetToken = models.CharField(max_length=50, default="none")

        
    # USERNAME_FIELD = 'email'
    # REQUIRED_FIELDS = []
    # objects = SellerManager()

# seller address table


class sellerAddress(models.Model):
    address_id = models.AutoField(primary_key=True)
    seller_id = models.ForeignKey('seller', on_delete=models.CASCADE)
    country = models.CharField(max_length=30)
    state = models.CharField(max_length=30)
    city = models.CharField(max_length=30)
    street = models.CharField(max_length=30)
    zip_code = models.IntegerField()
    house_no = models.CharField(max_length=40)

# product table


class product(models.Model):
    CATEGORY_CHOICES = [("Electronics", "Electronics"), ("Smartphone", "Smartphone"), ("Laptop", "Laptop"), ("Tablet", "Tablet"), ("Computer", "Computer"), ("Stationary", "Stationary"), ("Fashion", "Fashion"), ("Furniture", "Furniture"), ("Health", "Health"), ("Beauty", "Beauty"), ("Kids", "Kids"), ("Books", "Books"), ("Sports", "Sports"), ("Automotive", "Automotive"), ("Groceries",
                                                                                                                                                                                                                                                                                                                                                                                     "Groceries"), ("Jewelry", "Jewelry"), ("Watches", "Watches"), ("Art and Crafts", "Art and Crafts"), ("Medicines", "Medicines"), ("Personal Care", "Personal Care"), ("Travel", "Travel"), ("Students", "Students"), ("Men's", "Men's"), ("women's", "women's"), ("Adult's", "Adult's"), ("Girl's", "Girl's"), ("Boy's", "Boy's"), ("Cycle", "Cycle"), ("Bike", "Bike"), ("Car", "Car")]
    product_id = models.AutoField(primary_key=True)
    product_name = models.CharField(max_length=150)
    seller_id = models.ForeignKey('seller', on_delete=models.CASCADE)
    product_image = models.ImageField(upload_to='product/images/')
    category = models.CharField(max_length=100, choices=CATEGORY_CHOICES)
    description = models.TextField()
    specifications_list = models.TextField()
    availability = models.BooleanField(default=True)

# product image table


# class productImages(models.Model):
#     image_id = models.AutoField(primary_key=True)
#     product_id = models.ForeignKey('product', on_delete=models.CASCADE, related_name='images')
#     product_image = models.ImageField(upload_to='product/images/')
#     image_name = models.TextField()

# cart table


class cart(models.Model):
    cart_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey('User', on_delete=models.CASCADE)
    product_id = models.ForeignKey('product', on_delete=models.CASCADE)
    quantity = models.IntegerField()

# wishlist table


class wishlist(models.Model):
    wishlist_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey('User', on_delete=models.CASCADE)
    product_id = models.ForeignKey('product', on_delete=models.CASCADE)

# product review table


class productReview(models.Model):
    review_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey('User', on_delete=models.CASCADE)
    product_id = models.ForeignKey('product', on_delete=models.CASCADE)
    review_msg = models.TextField()
    review_rating = models.IntegerField()
    review_img = models.ImageField(upload_to='product_review/images/')

# orders table


class orders(models.Model):
    order_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey('User', on_delete=models.CASCADE)
    product_id = models.ForeignKey('product', on_delete=models.CASCADE)
    quantity = models.IntegerField()
    order_status = models.CharField(max_length=20)
    order_date = models.DateTimeField(auto_now_add=True)

# product questions table


class productQuestions(models.Model):
    question_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey('User', on_delete=models.CASCADE)
    product_id = models.ForeignKey('product', on_delete=models.CASCADE)
    question_msg = models.TextField()
    answer = models.TextField()
    likes = models.IntegerField()
    dislikes = models.IntegerField()
    replyList = models.TextField()
