from django.shortcuts import render
from django.http import Http404
from django.shortcuts import get_object_or_404, render
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from authentication.models import CustomUser
from authentication.serializers import UserSerializer, RegisterSerializer
from rest_framework.response import Response
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from roles.models import user_roles

# Create your views here.


class UsersList(APIView):
    '''
    A class to add and retrieve users

    get: Get all users

    post: Add User Note: Pass a role ID (eg. 1) for role
    '''
    # permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        responses={200: UserSerializer()}
    )
    def get(self, request, format=None):
        allusers = CustomUser.objects.all()
        serializer = UserSerializer(allusers, many=True)
        return Response({
            "responseCode": "000",
            "responseMessage": "All user found",
            "data": serializer.data
        })

    @swagger_auto_schema(
        request_body=RegisterSerializer,
        responses={201: UserSerializer()}
    )
    def post(self, request, format=None):
        try:
            userRole = get_object_or_404(user_roles, id=request.data['role'])
            # create a new user
            new_user = CustomUser.objects.create_user(
                username=request.data['email'],
                email=request.data['email'],
                first_name=request.data['first_name'],
                last_name=request.data['last_name'],
                phone_number=request.data['phone_number'],
                role=userRole,
                password=request.data['password']
            )

            context = {
                "user": new_user.first_name,
            }

            template_name = 'welcome_email.html'
            convert_to_html_content = render_to_string(
                template_name=template_name,
                context=context
            )
            plain_message = strip_tags(convert_to_html_content)

            try:
                send_mail("Solar-U New Account", message=plain_message,
                          from_email=settings.EMAIL_HOST, recipient_list=[request.data['email']], html_message=convert_to_html_content, fail_silently=False)

            except Exception as e:
                return Response({
                    "responseCode": "111",
                    "responseMessage": "Failed to send email"
                })
            serializer = UserSerializer(new_user)

            # newlog = auditTrail()
            # newlog.user = request.user
            # newlog.action = "Add user"
            # newlog.status = True

            # newlog.save()

            return Response({
                "responseCode": "000",
                "responseMessage": "User created successfully",
                "data": serializer.data
            })
        except Exception as e:
            print(e)

            # newlog = auditTrail()
            # newlog.user = request.user
            # newlog.action = "Add user"
            # newlog.save()

            return Response({
                "responseCode": "111",
                "responseMessage": "An error occured"
            })


class UsersDetails(APIView):
    '''
    Retrive, update or delete a single user

    get: Get the details of a user
    put: Update the details of a user
    delete: Delete a user
    '''
    # permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return CustomUser.objects.get(id=pk)
        except CustomUser.DoesNotExist:
            raise Http404

    @swagger_auto_schema(
        responses={200: UserSerializer()}
    )
    def get(self, request, pk, format=None):
        user = self.get_object(pk)
        serializer = UserSerializer(user)
        return Response({
            "responseCode": "000",
            "responseMessage": "user found",
            "data": serializer.data
        })

    @swagger_auto_schema(
        responses={200: UserSerializer()}
    )
    def put(self, request, pk, format=None):
        user = self.get_object(pk)
        userRole = get_object_or_404(user_roles, id=request.data['role'])

        try:
            user.first_name = request.data['first_name']
            user.last_name = request.data['last_name']
            user.phone_number = request.data['phone_number']
            user.role = userRole
            user.save()

            user = self.get_object(pk)
            serializer = UserSerializer(user)

            # newlog = auditTrail()
            # newlog.user = request.user
            # newlog.action = "Edit user"
            # newlog.status = True
            # newlog.save()

            return Response({
                "responseCode": "000",
                "responseMessage": "user updated successfully",
                "data": serializer.data
            })
        except Exception as e:

            # newlog = auditTrail()
            # newlog.user = request.user
            # newlog.action = "Edit user"
            # newlog.save()

            return Response({
                "responseCode": "111",
                "responseMessage": "an error occured" + e
            })

    @swagger_auto_schema(
        responses={200: 'User deleted successfully'}
    )
    def delete(self, request, pk, format=None):
        user = self.get_object(pk)
        user.delete()

        # newlog = auditTrail()
        # newlog.user = request.user
        # newlog.action = "Delete user"
        # newlog.status = True
        # newlog.save()

        return Response({
            "responseCode": "000",
            "responseMessage": "user deleted successfully"
        })
