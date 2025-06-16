from rest_framework.views import APIView
from roles.models import user_roles
from roles.serializers import RoleSerializer, AddRoleSerializer
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from drf_yasg.utils import swagger_auto_schema
from django.http import Http404

# Create your views here.


class RolesList(APIView):
    '''
    List all roles, or create a new role
    
    get:get list of all roles
    post:add a new role
    '''
    #permission_classes = [IsAuthenticated]
    # get all roles

    @swagger_auto_schema(
        security=[{'Bearer': []}],
        responses={201: RoleSerializer()}
    )
    def get(self, request, format=None):
        allroles = user_roles.objects.all()
        serializer = RoleSerializer(allroles, many=True)
        return Response({
            "responseCode": "000",
            "responseMessage": "All user roles",
            "data": serializer.data
        })


    @swagger_auto_schema(
        request_body=AddRoleSerializer,
        responses={201: RoleSerializer()}
    )
    # add role
    def post(self, request, format=None):
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()

            return Response({
                "responseCode": "000",
                "responseMessage": "Role save successfully",
                "data": serializer.data
            })

        return Response({
            "responseCode": "111",
            "responseMessage": serializer.errors
        })


class RolesDetails(APIView):
    '''
    Retrive,update or delete a single role
    
    get: get details of one role
    put: update a role
    delete: delete a role
    '''
    #permission_classes = [IsAuthenticated]

    
    def get_object(self, pk):
        try:
            return user_roles.objects.get(id=pk)
        except user_roles.DoesNotExist:
            raise Http404

    # retrieve and return role
    @swagger_auto_schema(
        responses={200: RoleSerializer()}
    )
    def get(self, request, pk, format=None):
        role = self.get_object(pk)
        serializer = RoleSerializer(role)
        return Response({
            "responseCode": "000",
            "responseMessage": "role found",
            "data": serializer.data
        })

    # update role
    @swagger_auto_schema(
        request_body=RoleSerializer,
        responses={200: RoleSerializer()}
    )
    def put(self, request, pk, format=None):
        role = self.get_object(pk)
        serializer = RoleSerializer(role, data=request.data)
        if serializer.is_valid():
            serializer.save()
            role = self.get_object(pk)
            serializer = RoleSerializer(role)

            return Response({
                "responseCode": "000",
                "responseMessage": "role updated successfully",
                "data": serializer.data
            })
        
        return Response({
            "responseCode": "000",
            "responseMessage": serializer.errors
        })

    # delete role
    @swagger_auto_schema(
        responses={200: 'Role deleted successfully'}
    )
    def delete(self, request, pk, format=None):
        role = self.get_object(pk)
        role.delete()

        return Response({
            "responseCode": "000",
            "responseMessage": "role deleted successfully"
        })
