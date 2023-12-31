import json
import os
import random
import string
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.http.response import HttpResponse
from rest_framework import viewsets

# from django.contrib.auth.models import User
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from api.serializers import *
from api.task import sendEmailTask,sendSellerEmailTask,sendScheduleEmailTask,sendForgotEmailTask,sendSellerForgotEmailTask
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django_celery_beat.models import PeriodicTask,CrontabSchedule
from datetime import datetime
from django.contrib.auth.hashers import make_password

User=get_user_model()

# Create your views here.
@api_view(['POST'])
def login_api(request):
    try:
        data=request.data
        email=data.get('email')
        password=data.get('password')
        user = authenticate(username=email, password=password)
        if user:
            # token, _ = Token.objects.get_or_create(user=user)
            refresh = RefreshToken.for_user(user)
            return Response({
            # "token":str(token_obj),
            # "payload":serializer.data,
            "message":"Login Success",
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            },
            status=status.HTTP_302_FOUND)
            # return Response({
            #     'token':str(token)
            # },status=status.HTTP_200_OK)
        else:
            return Response({
                'message':'Invalid Credentials'
                },
                status=status.HTTP_404_NOT_FOUND
                )
    except Exception as e:
        # print(e)
        return Response({
            'message':str(e)
            },
            status=status.HTTP_400_BAD_REQUEST
            )

# Timer function to call invalidate password task after 5 min
def callInvalidateOTP(email):
    randomNum=random.randint(0,9999999999)
    hour=datetime.now().hour
    minutes=datetime.now().minute+10
    # what if someone using this function at **:59 minutes 
    if minutes>59:
        hour=hour+1
        minutes=minutes-59
        # print("TIME: ")
        # print(str(hour)+":"+str(minutes))
    schedule, created = CrontabSchedule.objects.get_or_create(
        hour=hour,
        minute=minutes,
        )
    task = PeriodicTask.objects.create(
        crontab=schedule,
        name='schedule_Invalidate_otp_task_'+str(randomNum),
        task="api.task.invalidateOTP", 
        kwargs=json.dumps({"email":email,"name":'schedule_Invalidate_otp_task_'+str(randomNum)}),
        )#[email]['schedule_Invalidate_otp_task_'+str(randomNum)]
    return HttpResponse('timer start of 10min to invalidate otp')

class RegisterUser(APIView):
    def post(self, request):
        # print(make_password("Sanket@123"))
        print("POST METHOD CALLED")
        serializer=userRegisterSerializer(data=request.data)
        print(serializer)
        if not serializer.is_valid():
            email = request.data.get('email')
            # print(email)
            try:
                    user=User.objects.get(email=request.data['email'])
                    # print(user)
                    if user.otp_validity == False and user.verification_status == "pending":
                        try:
                            email=user.email
                            # print(email)
                            sendEmailTask.delay(email)
                            # 
                            user.otp_validity=True
                            refresh = RefreshToken.for_user(user)
                            # print(refresh)
                            user.save()

                        except:
                            return Response(
                                {
                                    # "message":"Something went wrong",
                                    "error":serializer.errors
                                    },
                                    status=status.HTTP_400_BAD_REQUEST
                                    )
                        callInvalidateOTP(request.data['email'])
                        return Response({
                            # "payload":serializer.data['email'],
                            "message":"OTP send on "+serializer.data['email']+" Successfully.",
                            "refresh": str(refresh),
                            "access": str(refresh.access_token),
                            },
                            status=status.HTTP_302_FOUND
                            )
                       
                    return Response({
                    "error":serializer.errors
                    },
                    status=status.HTTP_403_FORBIDDEN
                    )
            except:
                return Response({
                    "error":serializer.errors
                    },
                    status=status.HTTP_403_FORBIDDEN
                    )        
        else:
            try:
                # print("ELSE")
                email=serializer.validated_data['email']
                # print(email)
                sendEmailTask.delay(email)
                # 
            except Exception as e:
                return Response(
                    {
                        "message":"Something went wrong\n"+str(e),
                        "error":serializer.errors
                        },
                        status=status.HTTP_400_BAD_REQUEST
                        )
            serializer.save()
            user=User.objects.get(email=serializer.data['email'])
            user.otp_validity=True
            # token_obj, _=Token.objects.get_or_create(user=user)
            refresh = RefreshToken.for_user(user)
            user.save()
            callInvalidateOTP(email)
            
            return Response({
                "message":"OTP send on "+serializer.data['email']+" Successfully.",
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                },
                status=status.HTTP_302_FOUND)   

class verifyOTP(APIView):
    def post(self,request):
        try:
            data=request.data
            serializer=verifyOTPSerializer(data=data)
            if not serializer.is_valid():
                return Response({"Message":"Invalid Input","error":serializer.errors})
            email=serializer.data['email']
            otp=serializer.data['otp']
            user=User.objects.filter(email=email)
            if not user.exists():
                return Response({
                    "message":"User not found"
                    },
                    status=status.HTTP_404_NOT_FOUND
                    )
            if user[0].otp != otp:
                return Response({
                    "message":"Invalid OTP"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                    )
            if user.first().verification_status == "verified":
                return Response({
                    "message":"Account already verified"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                    )
            user=user.first()
            user.otp_validity=False
            user.verification_status = "verified"
            user.save()
            return Response({
                "message":"Account verified Successfully"
                },
                status=status.HTTP_200_OK
                )
        except Exception as e:
            return Response({
                "ERROR":str(e)
                },
                status=status.HTTP_200_OK
                )   
            # if not bool(serializer.data):
        # return Response({"Message":"jkj Blank Input Not allowed"})
             

class forgotPassword(APIView):
    def post(self, request):
        serializer=forgotPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "message":"Invalid Input",
                "error":serializer.errors
                },
                status=status.HTTP_403_FORBIDDEN
                )
        email=serializer.data['email']
        user=User.objects.filter(email=email)
        if not user.exists():
            return Response({
                "message":"User not found"
                },
                status=status.HTTP_404_NOT_FOUND
                )
        try:    
            # send_otp_via_email(serializer.data['email'])
            sendForgotEmailTask.delay(email)
        except:
            return Response({
                "message":"Something went wrong",
                "error":serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
                )
        # serializer.save()
        resetToken=''.join(random.choices(string.ascii_lowercase +
                             string.digits, k=50))
        user=user.first()
        user.verification_status = "reset"
        user.otp_validity=True
        user.resetToken=str(resetToken)
        print(str(resetToken))
        user.save()
        user=User.objects.get(email=serializer.data['email'])
        email=user.email

        callInvalidateOTP(email)
        # token_obj, _=Token.objects.get_or_create(user=user)
        # refresh = RefreshToken.for_user(user)
        
        return Response({
            # "token":str(token_obj),
            "payload":serializer.data,
            "message":"OTP send on "+serializer.data['email']+" Successfully.",
            "resetToken":str(resetToken)
            # "refresh": str(refresh),
            # "access": str(refresh.access_token),
            },
            status=status.HTTP_302_FOUND)   

class resetPassword(APIView):
    def post(self,request):
        serializer=resetPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "error":serializer.errors
                },
                status=status.HTTP_403_FORBIDDEN
                )
        email=serializer.data['email']
        resetToken=serializer.data['resetToken']
        user=User.objects.filter(email=email)

        if not user.exists():
            return Response({
                "message":"User not found",
            },status=status.HTTP_404_NOT_FOUND
            )
        
        user=user.first() 

        if not user.resetToken==resetToken:
            return Response({
                "message":"Invalid Rest Token",
            },status=status.HTTP_404_NOT_FOUND
            )
        
        if serializer.data['otp']!=user.otp:
            return Response({
                "message":"Invalid OTP",
            },
            )
        
        # if not len(serializer.data['password'])>7:
        #     return Response({
        #         "message":"Password length should be greater than or equal to 8.",
        #     },
        #     )
        


        if user.email==email and user.resetToken==resetToken and user.verification_status=='reset':
            user.resetToken='none'
            user.otp_validity=False
            user.verification_status='verified'
            user.set_password(serializer.data['password'])
            user.save()
            return Response({
                    "message":"Password changed Successfully"
                    },
                    status=status.HTTP_202_ACCEPTED
                    )
            

class userSupportAPI(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    def get(self,request):
        queryset = user_support.objects.all()
        serializer = userSupportSerializer(queryset, many=True)
        return Response(serializer.data)

    def post(self,request):
        serializer = userSupportSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data saved","payload":serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request):
        help_id=request.data['help_id']
        instance = self.get_object(help_id)
        serializer = userSupportSerializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        help_id=request.data['help_id']
        instance = self.get_object(help_id)
        serializer = userSupportSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        help_id=request.data['help_id']
        instance = self.get_object(help_id)
        delete_image_file(str(instance.image.path))
        instance.delete()
        return Response({"message":"data deleted"},status=status.HTTP_200_OK)
    
    def get_object(self, help_id):
        try:
            return user_support.objects.get(help_id=help_id)
        except user_support.DoesNotExist:
            raise status.HTTP_404_NOT_FOUND            

class userAddressAPI(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    def get(self,request):

        try:
            queryset = userAddress.objects.filter(user_id=request.data['user_id'])
            serializer = userAddressSerializer(queryset, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({"message":str(e)})

    def post(self,request):
        serializer = userAddressSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data saved","payload":serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request):
        address_id=request.data['address_id']
        instance = self.get_object(address_id)
        serializer = userAddressSerializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        address_id=request.data['address_id']
        instance = self.get_object(address_id)
        serializer = userAddressSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        address_id=request.data['address_id']
        instance = self.get_object(address_id)
        instance.delete()
        return Response({"message":"data deleted"},status=status.HTTP_200_OK)
    
    def get_object(self, address_id):
        try:
            return userAddress.objects.get(address_id=address_id)
        except userAddress.DoesNotExist:
            raise status.HTTP_404_NOT_FOUND
 
       
class sellerAPI(APIView):
    def get(self,request):
        queryset = seller.objects.all()
        serializer = sellerSerializer(queryset, many=True)
        return Response(serializer.data)

    def post(self,request):
        serializer = sellerSerializer(data=request.data)
        if serializer.is_valid():
            self.password = make_password(request.data['password'])
            serializer.save()
            return Response({"message":"data saved","payload":serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request):
        seller_id=request.data['seller_id']
        instance = self.get_object(seller_id)
        serializer = sellerSerializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        seller_id=request.data['seller_id']
        instance = self.get_object(seller_id)
        serializer = sellerSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        seller_id=request.data['seller_id']
        instance = self.get_object(seller_id)
        instance.delete()
        return Response({"message":"data deleted"},status=status.HTTP_200_OK)
    
    def get_object(self, seller_id):
        try:
            return seller.objects.get(seller_id=seller_id)
        except seller.DoesNotExist:
            raise status.HTTP_404_NOT_FOUND
        
class sellerAddressAPI(APIView):
    def get(self,request):
        queryset = sellerAddress.objects.all()
        serializer = sellerAddressSerializer(queryset, many=True)
        return Response(serializer.data)

    def post(self,request):
        serializer = sellerAddressSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data saved","payload":serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request):
        address_id=request.data['address_id']
        instance = self.get_object(address_id)
        serializer = sellerAddressSerializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        address_id=request.data['address_id']
        instance = self.get_object(address_id)
        serializer = sellerAddressSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        address_id=request.data['address_id']
        instance = self.get_object(address_id)
        instance.delete()
        return Response({"message":"data deleted"},status=status.HTTP_200_OK)
    
    def get_object(self, address_id):
        try:
            return sellerAddress.objects.get(address_id=address_id)
        except sellerAddress.DoesNotExist:
            raise status.HTTP_404_NOT_FOUND

# class ProductViewSet(viewsets.ModelViewSet):
#     queryset = product.objects.all()
#     serializer_class = productSerializer

class productAPI(APIView):
    def get(self,request):
        queryset = product.objects.all()
        serializer = productSerializer(queryset, many=True)
        return Response(serializer.data)

    def post(self,request):
        # authentication_classes=[JWTAuthentication]
        # permission_classes=[IsAuthenticated]
        # print(request.product_image)
        serializer = productSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data saved","payload":serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request):
        product_id=request.data['product_id']
        instance = self.get_object(product_id)
        serializer = productSerializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        product_id=request.data['product_id']
        instance = self.get_object(product_id)
        serializer = productSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        product_id=request.data['product_id']
        instance = self.get_object(product_id)
        instance.delete()
        return Response({"message":"data deleted"},status=status.HTTP_200_OK)
    
    def get_object(self, product_id):
        try:
            return product.objects.get(product_id=product_id)
        except product.DoesNotExist:
            raise status.HTTP_404_NOT_FOUND
        
# class productImagesAPI(APIView):
#     def get(self,request):
#         queryset = productImages.objects.all()
#         serializer = productImagesSerializer(queryset, many=True)
#         return Response(serializer.data)

#     def post(self,request):
#         serializer = productImagesSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response({"message":"data saved","payload":serializer.data}, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#     def put(self, request):
#         image_id=request.data['image_id']
#         instance = self.get_object(image_id)
#         serializer = productImagesSerializer(instance, data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response({"message":"data updated","payload":serializer.data},)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def patch(self, request):
#         image_id=request.data['image_id']
#         instance = self.get_object(image_id)
#         serializer = productImagesSerializer(instance, data=request.data, partial=True)
#         if serializer.is_valid():
#             serializer.save()
#             return Response({"message":"data updated","payload":serializer.data},)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def delete(self, request):
#         image_id=request.data['image_id']
#         instance = self.get_object(image_id)
#         delete_image_file(str(instance.image.path))
#         instance.delete()
#         return Response({"message":"data deleted"},status=status.HTTP_200_OK)
    
#     def get_object(self, image_id):
#         try:
#             return productImages.objects.get(image_id=image_id)
#         except productImages.DoesNotExist:
#             raise status.HTTP_404_NOT_FOUND
        
class cartAPI(APIView):
    def get(self,request):
        queryset = cart.objects.all()
        serializer = cartSerializer(queryset, many=True)
        return Response(serializer.data)

    def post(self,request):
        serializer = cartSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data saved","payload":serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request):
        cart_id=request.data['cart_id']
        instance = self.get_object(cart_id)
        serializer = cartSerializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        cart_id=request.data['cart_id']
        instance = self.get_object(cart_id)
        serializer = cartSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        cart_id=request.data['cart_id']
        instance = self.get_object(cart_id)
        instance.delete()
        return Response({"message":"data deleted"},status=status.HTTP_200_OK)
    
    def get_object(self, cart_id):
        try:
            return cart.objects.get(cart_id=cart_id)
        except cart.DoesNotExist:
            raise status.HTTP_404_NOT_FOUND

class wishlistAPI(APIView):
    def get(self,request):
        queryset = wishlist.objects.all()
        serializer = wishlistSerializer(queryset, many=True)
        return Response(serializer.data)

    def post(self,request):
        serializer = wishlistSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data saved","payload":serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request):
        wishlist_id=request.data['wishlist_id']
        instance = self.get_object(wishlist_id)
        serializer = wishlistSerializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        wishlist_id=request.data['wishlist_id']
        instance = self.get_object(wishlist_id)
        serializer = wishlistSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        wishlist_id=request.data['wishlist_id']
        instance = self.get_object(wishlist_id)
        instance.delete()
        return Response({"message":"data deleted"},status=status.HTTP_200_OK)
    
    def get_object(self, wishlist_id):
        try:
            return wishlist.objects.get(wishlist_id=wishlist_id)
        except wishlist.DoesNotExist:
            raise status.HTTP_404_NOT_FOUND

class productReviewAPI(APIView):
    def get(self,request):
        queryset = productReview.objects.all()
        serializer = productReviewSerializer(queryset, many=True)
        return Response(serializer.data)

    def post(self,request):
        serializer = productReviewSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data saved","payload":serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request):
        review_id=request.data['review_id']
        instance = self.get_object(review_id)
        serializer = productReviewSerializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        review_id=request.data['review_id']
        instance = self.get_object(review_id)
        serializer = productReviewSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        review_id=request.data['review_id']
        instance = self.get_object(review_id)
        delete_image_file(str(instance.image.path))
        instance.delete()
        return Response({"message":"data deleted"},status=status.HTTP_200_OK)
    
    def get_object(self, review_id):
        try:
            return productReview.objects.get(review_id=review_id)
        except productReview.DoesNotExist:
            raise status.HTTP_404_NOT_FOUND

class ordersAPI(APIView):
    def get(self,request):
        queryset = orders.objects.all()
        serializer = ordersSerializer(queryset, many=True)
        return Response(serializer.data)

    def post(self,request):
        serializer = ordersSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data saved","payload":serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request):
        order_id=request.data['order_id']
        instance = self.get_object(order_id)
        serializer = ordersSerializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        order_id=request.data['order_id']
        instance = self.get_object(order_id)
        serializer = ordersSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        order_id=request.data['order_id']
        instance = self.get_object(order_id)
        instance.delete()
        return Response({"message":"data deleted"},status=status.HTTP_200_OK)
    
    def get_object(self, order_id):
        try:
            return orders.objects.get(order_id=order_id)
        except orders.DoesNotExist:
            raise status.HTTP_404_NOT_FOUND

class productQuestionsAPI(APIView):
    def get(self,request):
        queryset = productQuestions.objects.all()
        serializer = productQuestionsSerializer(queryset, many=True)
        return Response(serializer.data)

    def post(self,request):
        serializer = productQuestionsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data saved","payload":serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request):
        question_id=request.data['question_id']
        instance = self.get_object(question_id)
        serializer = productQuestionsSerializer(instance, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        question_id=request.data['question_id']
        instance = self.get_object(question_id)
        serializer = productQuestionsSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"data updated","payload":serializer.data},)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        question_id=request.data['question_id']
        instance = self.get_object(question_id)
        instance.delete()
        return Response({"message":"data deleted"},status=status.HTTP_200_OK)
    
    def get_object(self, question_id):
        try:
            return productQuestions.objects.get(question_id=question_id)
        except productQuestions.DoesNotExist:
            raise status.HTTP_404_NOT_FOUND

def schedule_mail(request):
    # sendScheduleEmailTask()
    try:
        randomNum = random.randint(0, 99999)
        schedule, created = CrontabSchedule.objects.get_or_create(hour=21, minute=26)
        task = PeriodicTask.objects.create(
            crontab=schedule,
            name='schedule_mail_task_' + str(randomNum),
            task="api.task.sendScheduleEmailTask",
            args=json.dumps(['sanketugale2003@gmail.com'])
        )
    except Exception as e:
        print(e)
    return HttpResponse('send')
# Response({'message':"Success"})

# @api_view(['POST',"GET"])
class demoApi(APIView):
    # authentication_classes=[TokenAuthentication]
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    def get(self,request):
        return Response({
            "message":"GET request from demoApi"
            },
            status=status.HTTP_200_OK
            )
    def post(self,request):
        return Response({
            "message":"POST request from demoApi"
            },
            status=status.HTTP_200_OK
            )
    def put(self,request):
        return Response({
            "message":"PUT request from demoApi"
            },
            status=status.HTTP_200_OK
            )
    def delete(self,request):
        return Response({
            "message":"DELETE request from demoApi"
            },
            status=status.HTTP_200_OK
            )
    def patch(self,request):
        return Response({
            "message":"PATCH request from demoApi"
            },
            status=status.HTTP_200_OK
            )

def index(request):
    return render(request, "chat/index.html")

def room(request, room_name):
    return render(request, "chat/room.html", {"room_name": room_name})


def delete_image_file(file_path):
    try:
        os.remove(file_path)
        print(f"Image file '{file_path}' deleted successfully.")
    except OSError as e:
        print(f"Error deleting image file '{file_path}': {e}")

# Example usage
# image_file_path = "/path/to/image.jpg"
# delete_image_file(image_file_path)


# SELLER VIEWS

# @api_view(['POST'])
# def SellerLoginApi(request):
    
    # try:
    #     data=request.data
    #     email=data.get('email')
    #     password=data.get('password')
    #     # if password is None and email is None:
    #     #     return Response({"message":serializers.errors})
    #     seller =authenticate(username=email, password=password)
    #     if seller:
    #         # token, _ = Token.objects.get_or_create(user=user)
    #         refresh = RefreshToken.for_user(seller)
    #         return Response({
    #         # "token":str(token_obj),
    #         # "payload":serializer.data,
    #         "message":"Login Success",
    #         "refresh": str(refresh),
    #         "access": str(refresh.access_token),
    #         },
    #         status=status.HTTP_302_FOUND)
    #         # return Response({
    #         #     'token':str(token)
    #         # },status=status.HTTP_200_OK)
    #     else:
    #         return Response({
    #             'message':'Invalid Credentials'
    #             },
    #             status=status.HTTP_404_NOT_FOUND
    #             )
    # except Exception as e:
    #     print(e)
    #     return Response({
    #         'message':str(e)
    #         },
    #         status=status.HTTP_400_BAD_REQUEST
    #         )

# Timer function to call invalidate password task after 5 min
def callSellerInvalidateOTP(email):
    randomNum=random.randint(0,99999999)
    hour=datetime.now().hour
    minutes=datetime.now().minute+10
    # what if someone using this function at **:59 minutes 
    if minutes>59:
        hour=hour+1
        minutes=minutes-59
        print("TIME: ")
        print(str(hour)+":"+str(minutes))
    schedule, created = CrontabSchedule.objects.get_or_create(
        hour=hour,
        minute=minutes,
        )
    task = PeriodicTask.objects.create(
        crontab=schedule,
        name='schedule_Invalidate_seller_otp_task_'+str(randomNum),
        task="api.task.invalidateSellerOTP", 
        kwargs=json.dumps({"email":email,"name":'schedule_Invalidate_seller_otp_task_'+str(randomNum)}),
        )#[email]['schedule_Invalidate_otp_task_'+str(randomNum)]
    return HttpResponse('timer start of 10min to invalidate otp')



class SellerLoginView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = SellerLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data)


class RegisterSeller(APIView):
    def post(self, request):
        serializer=SellerRegisterSerializer(data=request.data)
        if not serializer.is_valid():
            email = request.data.get('email')
            try:
                    # if seller.objects.all(email=email).exists():
                    seller_obj=seller.objects.get(email=request.data['email'])
                    # print(seller_obj)
                    if seller_obj.otp_validity == False and seller_obj.verification_status == "pending":
                        try:
                            email=seller_obj.email
                            # print(email)
                            sendSellerEmailTask.delay(email)
                            seller_obj.otp_validity=True
                            # seller_obj.password= make_password(request.data['password'])
                            refresh = RefreshToken.for_user(seller_obj)
                            # print(refresh)
                            seller_obj.save()
                            # print(seller.objects.update(seller=seller_obj))

                        except:
                            return Response(
                                {
                                    "message":"Something went wrong",
                                    "error":serializer.errors
                                    },
                                    status=status.HTTP_400_BAD_REQUEST
                                    )
                        # print(request.data['email']+"::::::::::::::::::::::::::::::::")
                        callSellerInvalidateOTP(request.data['email'])
                        # callInvalidateOTP(request.data['email'],'seller')
                        return Response({
                            # "payload":serializer.data['email'],
                            "message":"OTP send on "+serializer.data['email']+" Successfully.",
                            "refresh": str(refresh),
                            "access": str(refresh.access_token),
                            },
                            status=status.HTTP_302_FOUND
                            )
                       
                    return Response({
                    "error":serializer.errors
                    },
                    status=status.HTTP_403_FORBIDDEN
                    )                       
        # print(email)
        # callInvalidateOTP(email)
            except:
                return Response({
                    "error":serializer.errors
                    },
                    status=status.HTTP_403_FORBIDDEN
                    )        
        else:
            try:
                email=serializer.validated_data['email']
                sendSellerEmailTask.delay(email)
            except:
                return Response(
                    {
                        "message":"Something went wrong",
                        "error":serializer.errors
                        },
                        status=status.HTTP_400_BAD_REQUEST
                        )
            serializer.save()
            seller_obj=seller.objects.get(email=serializer.data['email'])
            seller_obj.otp_validity=True
            # token_obj, _=Token.objects.get_or_create(user=user)
            refresh = RefreshToken.for_user(seller_obj)
            seller_obj.save()
            callSellerInvalidateOTP(email)
            
            return Response({
                # "token":str(token_obj),
                # "payload":serializer.data{},
                "message":"OTP send on "+serializer.data['email']+" Successfully.",
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                },
                status=status.HTTP_302_FOUND)   
                # return Response({'error': 'Data with this email already exists.'}, status=400)



class verifySellerOTP(APIView):
    def post(self,request):
        try:
            data=request.data
            serializer=verifySellerOTPSerializer(data=data)
            if serializer.is_valid():
                email=serializer.data['email']
                otp=serializer.data['otp']
                seller_obj=seller.objects.filter(email=email)
                if not seller_obj.exists():
                    return Response({
                        "message":"Seller not found"
                        },
                        status=status.HTTP_404_NOT_FOUND
                        )
                if seller_obj.first().otp_validity == False:
                    return Response({
                        "message":"Your old otp is no more valid"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                        )
                if seller_obj[0].otp != otp:
                    return Response({
                        "message":"Invalid OTP"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                        )
                if seller_obj.first().verification_status == "verified":
                    return Response({
                        "message":"Account already verified"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                        )
                seller_obj=seller_obj.first()
                seller_obj.otp_validity=False
                seller_obj.verification_status = "verified"
                seller_obj.save()
                return Response({
                    "message":"Account verified Successfully"
                    },
                    status=status.HTTP_200_OK
                    )
            else:
                return Response(serializer.errors)
        except Exception as e:
            return Response({
                "ERROR":str(e)
                },
                status=status.HTTP_200_OK
                )    

class forgotSellerPassword(APIView):
    def post(self, request):
        serializer=forgotSellerPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "message":"Invalid Input",
                "error":serializer.errors
                },
                status=status.HTTP_403_FORBIDDEN
                )
        email=serializer.data['email']
        seller_obj=seller.objects.filter(email=email)
        if not seller_obj.exists():
            return Response({
                "message":"Seller not found"
                },
                status=status.HTTP_404_NOT_FOUND
                )
        try:    
            # send_otp_via_email(serializer.data['email'])
            sendSellerForgotEmailTask.delay(email)
        except:
            return Response({
                "message":"Something went wrong",
                "error":serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
                )
        # serializer.save()
        resetToken=''.join(random.choices(string.ascii_lowercase +
                             string.digits, k=50))
        seller_obj=seller_obj.first()
        seller_obj.verification_status = "reset"
        seller_obj.otp_validity=True
        seller_obj.resetToken=str(resetToken)
        # print(str(resetToken))
        seller_obj.save()
        seller_obj=seller.objects.get(email=serializer.data['email'])
        email=seller_obj.email
        callSellerInvalidateOTP(email)
        # invalidateSellerOTP(email)
        # token_obj, _=Token.objects.get_or_create(user=user)
        # refresh = RefreshToken.for_user(user)
        
        return Response({
            # "token":str(token_obj),
            "payload":serializer.data,
            "message":"OTP send on "+serializer.data['email']+" Successfully.",
            "resetToken":str(resetToken)
            # "refresh": str(refresh),
            # "access": str(refresh.access_token),
            },
            status=status.HTTP_302_FOUND)   

class resetSellerPassword(APIView):
    def post(self,request):
        serializer=resetSellerPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "message":"Invalid Input",
                "error":serializer.errors
                },
                status=status.HTTP_403_FORBIDDEN
                )
        email=serializer.data['email']
        resetToken=serializer.data['resetToken']
        seller_obj=seller.objects.filter(email=email)

        if not seller_obj.exists():
            return Response({
                "message":"Seller not found",
            },status=status.HTTP_404_NOT_FOUND
            )
        
        seller_obj=seller_obj.first() 

        if not seller_obj.resetToken==resetToken:
            return Response({
                "message":"Invalid Rest Token",
            },status=status.HTTP_404_NOT_FOUND
            )
        print(seller_obj.otp)
        if serializer.data['otp']!=seller_obj.otp:
            return Response({
                "message":"Invalid OTP",
            },
            )
        
        # if not len(serializer.data['password'])>7:
        #     return Response({
        #         "message":"Password length should be greater than or equal to 8.",
        #     },
        #     )

        if seller_obj.email==email and seller_obj.resetToken==resetToken and seller_obj.verification_status=='reset':
            seller_obj.resetToken='none'
            seller_obj.otp_validity=False
            seller_obj.verification_status='verified'
            seller_obj.password=make_password(serializer.data['password'])
            # seller.password=make_password(serializer.data['password'])
            seller_obj.save()
            return Response({
                    "message":"Password changed Successfully"
                    },
                    status=status.HTTP_202_ACCEPTED
                    )