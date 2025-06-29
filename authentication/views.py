import pyotp
from rest_framework.views import APIView
from appFunctions import timediff
from roles.models import user_roles
from django.shortcuts import get_object_or_404
from authentication.models import CustomUser
from rest_framework.response import Response
from authentication.serializers import UserSerializer, LoginSerializer, RegisterSerializer
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from appFunctions import timediff
import jwt
# from auditlogs.models import auditTrail
from django.contrib.auth.hashers import check_password
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


class Login(APIView):
    '''
    A class to login a user

    post: User login
    '''
    permission_classes = [AllowAny]  # allow without jwt

    @swagger_auto_schema(
        request_body=LoginSerializer,
        responses={201: UserSerializer()}
    )
    def post(self, request, format=None):

        secret_key = pyotp.random_base32()
        totp = pyotp.TOTP(secret_key)
        otp = totp.now()

        email = request.data['email']
        password = request.data['password']

        if email is not None and password is not None:

            authenticated_user = authenticate(
                request, username=email, password=password)

            if authenticated_user is not None:
                # serialize user and generate jwt tokens
                # serializer = UserSerializer(authenticated_user)
                # refreshToken = RefreshToken.for_user(authenticated_user)
                # accessToken = str(refreshToken.access_token)

                try:
                    user = CustomUser.objects.get(username=email)
                    user.otp = otp
                    user.otp_expiry = timezone.now()

                    user.save()

                    context = {
                        "user": user.first_name,
                        "code": otp
                    }

                    template_name = 'otp_email.html'
                    convert_to_html_content = render_to_string(
                        template_name=template_name,
                        context=context
                    )
                    plain_message = strip_tags(convert_to_html_content)

                    send_mail("SolarU Login Code", message=plain_message,
                              from_email=settings.EMAIL_HOST, recipient_list=[email], html_message=convert_to_html_content, fail_silently=False)

                except Exception as e:
                    return Response({
                        "responseCode": "111",
                        "responseMessage": "Email could not be sent",
                    })

                return Response({
                    "responseCode": "000",
                    "responseMessage": "Verification email sent successfully",
                    # "data": {"user": serializer.data,
                    #             "accessToken": accessToken,
                    #             "refreshToken": str(refreshToken)
                    #             }
                })
            else:
                return Response({
                    "responseCode": "111",
                    "responseMessage": "Invalid email or password",
                })
        else:

            return Response({
                "responseCode": "111",
                "responseMessage": "Phone number and password should be provided",
            })


class Register(APIView):
    '''
    A class to register a user

    post: Register user

    '''
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=RegisterSerializer,
        responses={201: UserSerializer()}
    )
    def post(self, request, format=None):
        userRole = get_object_or_404(user_roles, id=request.data['role'])
        print(userRole)
        # return Response("hello")

        # create a new user
        try:
            CustomUser.objects.create_user(
                username=request.data['email'],
                email=request.data['email'],
                first_name=request.data['first_name'],
                last_name=request.data['last_name'],
                phone_number=request.data['phone_number'],
                role=userRole,
                password=request.data['password']
            )
            return Response({
                "responseCode": "000",
                "responseMessage": "User registration successful",
            })
        except Exception as e:
            return Response({
                "responseCode": "111",
                "responseMessage": "An error occured "
            })

        # authenticate user
        # authenticated_user = authenticate(
        #     request, username=request.data['email'], password=request.data['password'])

        # # serialize user and generate jwt tokens
        # serializer = UserSerializer(authenticated_user)
        # refreshToken = RefreshToken.for_user(authenticated_user)
        # accessToken = str(refreshToken.access_token)

        # return Response({
        #     "responseCode": "000",
        #     "responseMessage": "User registered successfully",
        #     "data": {"user": serializer.data,
        #              "accessToken": accessToken,
        #              "refreshToken": str(refreshToken)
        #              }
        # })


class GenerateOTP(APIView):
    '''
    A class to generate OTP

    post: Generate OTP
    '''
    @swagger_auto_schema(
        security=[{'Bearer': []}],
        responses={200: 'Token generated successfully'}
    )
    def post(self, request, format=None):

        secret_key = pyotp.random_base32()
        totp = pyotp.TOTP(secret_key)
        otp = totp.now()

        try:
            user = CustomUser.objects.get(username=request.user.email)
            user.otp = otp
            user.otp_expiry = timezone.now()

            user.save()

            context = {
                "user": user.first_name,
                "code": otp
            }

            template_name = 'otp_email.html'
            convert_to_html_content = render_to_string(
                template_name=template_name,
                context=context
            )
            plain_message = strip_tags(convert_to_html_content)

            send_mail("SolarU Login Code", message=plain_message,
                      from_email=settings.EMAIL_HOST, recipient_list=[request.user.email], html_message=convert_to_html_content, fail_silently=False)

            return Response({
                "responseCode": "000",
                "responseMessage": "Token generated successfully",
            })
        except Exception as e:
            return Response({
                "responseCode": "111",
                "responseMessage": e,
            })


class VerifyOTP(APIView):
    '''
    A class to verify OTP

    post:Verify OTP
    '''

    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['token', 'email'],
            properties={
                'token': openapi.Schema(type=openapi.TYPE_STRING),
                'email': openapi.Schema(type=openapi.FORMAT_EMAIL)
            },
        ),
        # security=[{'Bearer': []}],
        responses={201: UserSerializer()}
    )
    def post(self, request, format=None):
        try:

            user = CustomUser.objects.get(username=request.data['email'])
        except Exception as e:
            return Response({
                "responseCode": "111",
                "responseMessage": "Could not get  user"
            })

        refreshToken = RefreshToken.for_user(user)
        accessToken = str(refreshToken.access_token)

        otp_datetime = user.otp_expiry

        serializer = UserSerializer(user)

        if timediff.is_more_than_20_minutes(otp_datetime):
            user.otp_expiry = ''
            user.save()

            return Response({
                "responseCode": "111",
                "responseMessage": "Token has expired",
            })
        else:
            if user.otp == request.data['token']:
                try:
                    user.otp = ''
                    user.otp_expiry = ''
                    user.save()
                except Exception as e:
                    print("here", e)
                # return Response({
                #     "responseCode": "000",
                #     "responseMessage": "Token verified successfully",
                #     "data": serializer.data
                # })
                return Response({
                    "responseCode": "000",
                    "responseMessage": "Token verified successfully",
                    "data": {"user": serializer.data,
                             "accessToken": accessToken,
                             "refreshToken": str(refreshToken)
                             }
                })
            else:
                return Response({
                    "responseCode": "111",
                    "responseMessage": "Token is invalid",
                })


class ForgotPassword(APIView):
    '''
    A class to request a url to change password

    post: forgot password
    '''

    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
        responses={201: 'Email sent successfully'}
    )
    def post(self, request, format=None):
        user = get_object_or_404(CustomUser, email=request.data['email'])

        if user is not None:

            refreshToken = RefreshToken.for_user(user)
            accessToken = str(refreshToken.access_token)

            context = {
                "user": user.first_name,
                "accessToken": accessToken
            }

            template_name = 'password_reset_email.html'
            convert_to_html_content = render_to_string(
                template_name=template_name,
                context=context
            )
            plain_message = strip_tags(convert_to_html_content)

            send_mail("Forgot Password", message=plain_message,
                      from_email=settings.EMAIL_HOST, recipient_list=[user.email], html_message=convert_to_html_content, fail_silently=False)

            user.password_reset_link_expiry = timezone.now()
            user.save()

            return Response({
                "responseCode": "000",
                "responseMessage": "Email sent successfully"
            })

        else:
            return Response({
                "responseCode": "111",
                "responseMessage": "User could not be found"
            })


class verifyResetPasswordLink(APIView):
    '''
    A class to verify the password reset link

    post: verify reset password link
    '''

    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['token'],
            properties={
                'token': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
        responses={201: 'Link hasn\'t expired'}
    )
    def post(self, request, format=None):
        token = request.data['token']

        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            theUser = payload.get('user_id')

            user = CustomUser.objects.get(id=theUser)

            reset_link_time = user.password_reset_link_expiry

            if timediff.is_more_than_20_minutes(reset_link_time):
                user.password_reset_link_expiry = ''
                user.save()
                return Response({
                    "responseCode": "111",
                    "responseMessage": "Link has expired",
                })

            else:
                return Response({
                    "responseCode": "000",
                    "responseMessage": "Link hasn't expired",
                })
        except Exception as e:
            return Response({
                "responseCode": "111",
                "responseMessage": str(e)
            })


class ResetPassword(APIView):
    '''
    A class to reset password

    post: reset password
    '''

    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['password'],
            properties={
                'password': openapi.Schema(type=openapi.TYPE_STRING)
            },
        ),
        responses={201: 'Password reset successful'}
    )
    def post(self, request, format=None):
        # token = request.data['token']
        password = request.data['password']

        try:
            # payload = jwt.decode(token, options={"verify_signature": False})
            theUser = request.user.email

            user = get_object_or_404(CustomUser, email=theUser)
            user.set_password(password)
            user.save()

            return Response({
                "responseCode": "000",
                "responseMessage": "password reset successfull"
            })

        except Exception as e:

            return Response({
                "responseCode": "111",
                "responseMessage": str(e)
            })


class ChangePassword(APIView):
    '''
    post: change user password
    '''

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email', 'new_password', 'old_password'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL),
                'new_password': openapi.Schema(type=openapi.TYPE_STRING),
                'old_password': openapi.Schema(type=openapi.TYPE_STRING)
            },
        ),
        responses={201: 'Password changed successful'}
    )
    def post(self, request, format=None):
        email = request.data.get('email')
        new_password = request.data.get('new_password')
        old_password = request.data.get('old_password')

        if not email or not new_password:
            return Response({
                "responseCode": "111",
                "responseMessage": "email and password must be provided"
            })

        user = get_object_or_404(CustomUser, email=email)
        print(user)
        if not check_password(old_password, user.password):
            return Response({
                "responseCode": "111",
                "responseMessage": "Passwords do not match"
            })

        user.set_password(new_password)
        user.save()

        return Response({
            "responseCode": "000",
            "responseMessage": "password change successful"
        })
