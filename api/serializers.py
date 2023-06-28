import re
from rest_framework import serializers
# from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth import authenticate
from api.models import *
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
# from django.contrib.auth.hashers import check_password
User=get_user_model()

class userRegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        if User.objects.filter(email=data.get('email')).exists():
            raise serializers.ValidationError("User with this email already exists.")
        if not len(data['password'])>7:
            raise serializers.ValidationError('Password length should be greater than or equal to 8')
        
        if not re.findall('\d', data['password']):
            raise serializers.ValidationError("The password must contain at least 1 digit, 0-9.")
        
        if not re.findall('[()[\]{}|\\`~!@#$%^&*_\-+=;:\'",<>./?]', data['password']):
            raise serializers.ValidationError("The password must contain at least 1 symbol")
        
        if not re.findall('[a-z]', data['password']):
            raise serializers.ValidationError("The password must contain at least 1 lowercase letter, a-z.")
        
        if not re.findall('[A-Z]', data['password']):
            raise serializers.ValidationError("The password must contain at least 1 uppercase letter, A-Z.")
        
        # if data['password']!=data['confirmPassword']:
        #     raise serializers.ValidationError('Password and confirm password not matched')
                    
        return data

    def create(self,validated_data):
        user=User.objects.create(email=validated_data['email'])
        user.set_password(validated_data['password'])
        user.save()
        return user



class UserSerializer(serializers.ModelSerializer):
    # email=serializers.EmailField()
    # password=serializers.CharField()
    # confirmPassword=serializers.CharField()
    class Meta:
        model = User
        fields=['email','password']

    # def validate(self, data):
    #     if not len(data['password'])>7:
    #         raise serializers.ValidationError('Password length should be greater than or equal to 8')
        
    #     if not re.findall('\d', data['password']):
    #         raise serializers.ValidationError("The password must contain at least 1 digit, 0-9.")
        
    #     if not re.findall('[()[\]{}|\\`~!@#$%^&*_\-+=;:\'",<>./?]', data['password']):
    #         raise serializers.ValidationError("The password must contain at least 1 symbol")
        
    #     if not re.findall('[a-z]', data['password']):
    #         raise serializers.ValidationError("The password must contain at least 1 lowercase letter, a-z.")
        
    #     if not re.findall('[A-Z]', data['password']):
    #         raise serializers.ValidationError("The password must contain at least 1 uppercase letter, A-Z.")
        
    #     if data['password']!=data['confirmPassword']:
    #         raise serializers.ValidationError('Password and confirm password not matched')
                    
    #     return data

    def create(self,validated_data):
        user=User.objects.create(email=validated_data['email'])
        user.set_password(validated_data['password'])
        user.save()
        return user
    
class verifyOTPSerializer(serializers.Serializer):
        email=serializers.EmailField()
        otp=serializers.CharField()

class forgotPasswordSerializer(serializers.Serializer):
        email=serializers.EmailField()

class resetPasswordSerializer(serializers.Serializer):
        email=serializers.EmailField()
        otp=serializers.CharField()
        resetToken=serializers.CharField()
        password=serializers.CharField()
        confirmPassword=serializers.CharField()

        def validate(self, data):
            if not len(data['password'])>7:
                raise serializers.ValidationError('Password length should be greater than or equal to 8')
            
            if not re.findall('\d', data['password']):
                raise serializers.ValidationError("The password must contain at least 1 digit, 0-9.")
            
            if not re.findall('[()[\]{}|\\`~!@#$%^&*_\-+=;:\'",<>./?]', data['password']):
                raise serializers.ValidationError("The password must contain at least 1 symbol")
            
            if not re.findall('[a-z]', data['password']):
                raise serializers.ValidationError("The password must contain at least 1 lowercase letter, a-z.")
            
            if not re.findall('[A-Z]', data['password']):
                raise serializers.ValidationError("The password must contain at least 1 uppercase letter, A-Z.")
            
            if data['password']!=data['confirmPassword']:
                raise serializers.ValidationError('Password and confirm password not matched')
                        
            return data
        
class userSupportSerializer(serializers.ModelSerializer):
    class Meta:
        model = user_support
        fields='__all__'
    # user_id=serializers.IntegerField()
    # issue_message=serializers.TextField()
    # image=serializers.ImageField()

class userAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = userAddress
        fields='__all__'
        # fields=['user_id','image','issue_message']


# class getUserAddressSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = userAddress
#         fields=['user_id']


class sellerSerializer(serializers.ModelSerializer):
    class Meta:
        model = seller
        # fields='__all__'
        fields=['email','password']

    def create(self,validated_data):
        seller_obj=seller.objects.create(email=validated_data['email'])
        seller_obj.password= make_password(validated_data['password'])
        seller_obj.save()
        return seller_obj
    
    # def validate(self, attrs):
    #     seller = authenticate(email=attrs['email'], password=attrs['password'])
    #     if seller is not None:
    #         if seller.is_active:
    #             data = super().validate(attrs)
    #             refresh = self.get_token(seller)
    #             refresh['seller_id'] = seller.pk
    #             data['refresh'] = str(refresh)
    #             data['access'] = str(refresh.access_token)
    #             return data
    #         else:
    #             raise serializers.ValidationError({'error': 'Account is not activated'})
    #     else:
    #         raise serializers.ValidationError({'error': 'Incorrect email or password'})

class SellerRegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    confirmPassword = serializers.CharField()

    def validate(self, data):
        if seller.objects.filter(email=data.get('email')).exists():
            raise serializers.ValidationError("Seller with this email already exists.")
        if not len(data['password'])>7:
            raise serializers.ValidationError('Password length should be greater than or equal to 8')
        
        if not re.findall('\d', data['password']):
            raise serializers.ValidationError("The password must contain at least 1 digit, 0-9.")
        
        if not re.findall('[()[\]{}|\\`~!@#$%^&*_\-+=;:\'",<>./?]', data['password']):
            raise serializers.ValidationError("The password must contain at least 1 symbol")
        
        if not re.findall('[a-z]', data['password']):
            raise serializers.ValidationError("The password must contain at least 1 lowercase letter, a-z.")
        
        if not re.findall('[A-Z]', data['password']):
            raise serializers.ValidationError("The password must contain at least 1 uppercase letter, A-Z.")
        
        if data['password']!=data['confirmPassword']:
            raise serializers.ValidationError('Password and confirm password not matched')
                    
        return data

    def create(self,validated_data):
        seller_obj=seller.objects.create(email=validated_data['email'])
        seller_obj.password= make_password(validated_data['password'])
        seller_obj.save()
        return seller_obj



class SellerLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        # Authenticate the seller
        try:
            seller_obj = seller.objects.get(email=email)
        except:
            raise serializers.ValidationError('Invalid email or password.')
        checkingPass =check_password(password,seller_obj.password)
        if not checkingPass:
            raise serializers.ValidationError('Invalid password.')
        if seller_obj.verification_status=="pending":
             raise serializers.ValidationError('Your Account is not verified')
        # Generate JWT token
        refresh = RefreshToken.for_user(seller_obj)
        tokens = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
        return tokens


class sellerAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = sellerAddress
        fields='__all__'

# class productImagesSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = productImages
#         fields='__all__'

class productSerializer(serializers.ModelSerializer):
    # images =  productImagesSerializer(many=True)
    # product_image = serializers.ListField(
    #     child=serializers.ImageField(allow_empty_file=False, use_url=False),
    #     write_only=True
    # )
    class Meta:
        model = product
        fields='__all__'


    # def create(self, validated_data):
    #     product_image = validated_data.pop("product_image")
    #     product_obj = product.objects.create(**validated_data)

    #     for image in product_image:
    #         productImages.objects.create(product=product_obj, image=image)
    #     # productImages.save()
    #     return product_obj


class cartSerializer(serializers.ModelSerializer):
    class Meta:
        model = cart
        fields='__all__'

class wishlistSerializer(serializers.ModelSerializer):
    class Meta:
        model = wishlist
        fields='__all__'

class productReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = productReview
        fields='__all__'

class ordersSerializer(serializers.ModelSerializer):
    class Meta:
        model = orders
        fields='__all__'

class productQuestionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = productQuestions
        fields='__all__'

# SELLER SERIALIZERs
class verifySellerOTPSerializer(serializers.Serializer):
        email=serializers.EmailField()
        otp=serializers.CharField()

class forgotSellerPasswordSerializer(serializers.Serializer):
        email=serializers.EmailField()

class resetSellerPasswordSerializer(serializers.Serializer):
        email=serializers.EmailField()
        otp=serializers.CharField()
        resetToken=serializers.CharField()
        password=serializers.CharField()
        confirmPassword=serializers.CharField()

        def validate(self, data):
            if not len(data['password'])>7:
                raise serializers.ValidationError('Password length should be greater than or equal to 8')
            
            if not re.findall('\d', data['password']):
                raise serializers.ValidationError("The password must contain at least 1 digit, 0-9.")
            
            if not re.findall('[()[\]{}|\\`~!@#$%^&*_\-+=;:\'",<>./?]', data['password']):
                raise serializers.ValidationError("The password must contain at least 1 symbol")
            
            if not re.findall('[a-z]', data['password']):
                raise serializers.ValidationError("The password must contain at least 1 lowercase letter, a-z.")
            
            if not re.findall('[A-Z]', data['password']):
                raise serializers.ValidationError("The password must contain at least 1 uppercase letter, A-Z.")
            
            if data['password']!=data['confirmPassword']:
                raise serializers.ValidationError('Password and confirm password not matched')
            
            return data