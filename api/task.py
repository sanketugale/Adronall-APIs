from celery import shared_task
from django.core.mail import send_mail
# from rest_framework.response import Response
from django.core.mail import send_mail
import random
from .models import User, seller
from django.template import loader
from django_celery_beat.models import PeriodicTask
# Task for sending email to verify register user account
@shared_task(bind=True)
def sendEmailTask(self, email):
    print("SEND EMAIL CALLED..........")
    subject="AdronAll User Account verification."
    otp=random.randint(100000,999999)
    print("OTP GENERATED"+str(otp))
    html_message = loader.render_to_string('registrationEmail.html',{'otp':otp})
    send_mail(subject,"", 'sanketbhikajiugale@outlook.com', [email], fail_silently=False,html_message=html_message)
    user_obj=User.objects.get(email=email)
    user_obj.otp=otp
    user_obj.save()
    return "DONE"

# Task for sending email for resetting password
@shared_task(bind=True)
def sendForgotEmailTask(self, email):
    subject="AdronAll Reset Password."
    otp=random.randint(100000,999999)
    html_message = loader.render_to_string('forgotPasswordEmail.html',{'otp':otp})
    send_mail(subject,"", 'sanketbhikajiugale@outlook.com', [email], fail_silently=False,html_message=html_message)
    user_obj=User.objects.get(email=email)
    user_obj.otp=otp
    user_obj.save()
    return "DONE"

@shared_task(bind=True)
def sendScheduleEmailTask(self,email):
    # print(args)
    # print("sendScheduleEmailTask called")
    subject="AdronAll Account verification OTP."
    otp=random.randint(100000,999999)
    html_message = loader.render_to_string('forgotPasswordEmail.html',{'otp':otp})
    send_mail(subject,"", 'sanketbhikajiugale@outlook.com', [email], fail_silently=False,html_message=html_message)
    return "DONE"

# to set otp invalid after 5 minutes of sending to user
@shared_task(bind=True)
def invalidateOTP(self,email,name):
    print(email)
    print(name)
    user_obj=User.objects.get(email=email)
    user_obj.otp_validity=False
    user_obj.save()
    periodic_task = PeriodicTask.objects.get(name=name)
    periodic_task.enabled = False
    periodic_task.save()
    return "SET otp Invalid"


# SELLER TASKS

@shared_task(bind=True)
def sendSellerEmailTask(self, email):
    # print("sendSellerEmailTask sendSellerEmailTask sendSellerEmailTask")
    subject="AdronAll Seller Account verification."
    otp=random.randint(100000,999999)
    html_message = loader.render_to_string('registrationEmail.html',{'otp':otp})
    send_mail(subject,"", 'sanketbhikajiugale@outlook.com', [email], fail_silently=False,html_message=html_message)
    seller_obj=seller.objects.get(email=email)
    seller_obj.otp=otp
    seller_obj.save()
    # seller.objects.update(seller=seller_obj)
    return "DONE"

# Task for sending email for resetting password
@shared_task(bind=True)
def sendSellerForgotEmailTask(self, email):
    subject="AdronAll Reset Password."
    otp=random.randint(100000,999999)
    html_message = loader.render_to_string('forgotPasswordEmail.html',{'otp':otp})
    send_mail(subject,"", 'sanketbhikajiugale@outlook.com', [email], fail_silently=False,html_message=html_message)
    seller_obj=seller.objects.get(email=email)
    seller_obj.otp=otp
    seller_obj.save()
    return "DONE"

@shared_task(bind=True)
def invalidateSellerOTP(self,email,name):
    seller_obj=seller.objects.get(email=email)
    seller_obj.otp_validity=False
    seller_obj.save()
    periodic_task = PeriodicTask.objects.get(name=name)
    periodic_task.enabled = False
    periodic_task.save()
    return "SET otp Invalid"