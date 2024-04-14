import json
from django.db.models import Q
from django.http import QueryDict
from django.shortcuts import render
from django.shortcuts import render
from django.core import exceptions
from rest_framework.viewsets import GenericViewSet, ViewSet,ModelViewSet
from rest_framework.views import APIView
from rest_framework import mixins
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import generics
from rest_framework.decorators import action, permission_classes

from authenticate.models import Users
from authenticate.serializers import UsersSerializer
from backend.custom_perm_classes import *
from backend.supabase_auth import SupabaseAuthBackend
from fileoperations.models import AccessLog, Objects, SharedFiles
from fileoperations.serializers import AccessLogSerializer, FileSerializer, SharedFileSerializer
from logic.models import *
from logic.serializers import *
from rest_framework.request import Request
import bcrypt
from logic.utils.utils import send_email,generate_confirmation_token,generate_strong_password
from time import sleep

class InviteUserView(ModelViewSet):
    authentication_classes = [SupabaseAuthBackend]
    permission_classes = [OrgadminRequired]
    serializer_class = InviteUserSerializer
    
    def invite_user(self, user, user_org,department,role,first_name,last_name, confirmation_token):
        try:
            serializer = UsersSerializer(data=user)
            if serializer.is_valid():
                instance = serializer.save()
                # Adding user to the organization
                data = UserInfo.objects.get(pk=instance.id)
                data.org = user_org
                data.dept = department
                data.role_priv = role
                data.name = first_name
                data.last_name = last_name
                data.save()

                #Creating Entry in identities Table
                identity = Identity(
                    provider_id=instance.id,
                    user_id = instance.id,
                    identity_data = {"sub":instance.id,"email":data.email,"email_verified":False,"phone_verified":False},
                    provider= "email",
                    email = data.email
                )
                identity.save()
                # Sending the mail
                email_response = send_email(user['email'], user['encrypted_password'], confirmation_token)
                print(email_response)
                return True
            return False
        except Exception as e:
            print(e)  # Log the error for debugging purposes
            return False

    def invite_driver(self, request):
        user_org = request.user.org
        # department_id = request.data.get('dept_id',None)
        # print("yooo",department_id)



        serializer = InviteUserSerializer(data=request.data)
        
        if serializer.is_valid():
            emails = serializer.validated_data.get('emails', [])
            try:
                first_name = request.data.get('first_name','')
                last_name = request.data.get('last_name','')


                department_id = request.data[ 'dept_id']
                department = Departments.objects.get(pk=department_id)  # Or filter by ID

                role_id = request.data['role_id']
                role = Role.objects.get(pk=role_id).role  # Or filter by ID

            except Departments.DoesNotExist:
                return Response({"msg":"Invalid Department Id"},status=status.HTTP_400_BAD_REQUEST)
            except Role.DoesNotExist:
                return Response({"msg":"Invalid Role Id"},status=status.HTTP_400_BAD_REQUEST)

            failed_invites = []
            for email in emails:
                confirmation_token = generate_confirmation_token()
                password = generate_strong_password()
                user = {
                    "email": email,
                    "encrypted_password": password,
                    "confirmation_token": confirmation_token,
                    "raw_app_meta_data": {"provider": "email", "providers": ["email"]},
                }

                if not self.invite_user(user, user_org,department,role,first_name,last_name, confirmation_token):
                    failed_invites.append(email)

            if failed_invites:
                return Response({"msg": "Some invites failed.", "failed_emails": failed_invites}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                return Response({"msg": "Invites sent successfully"}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def get_pending_invites(self,request):
        self.serializer_class = NUserGetInfoSerializer 
        user_org = request.user.org
        pending_users = Users.objects.filter(email_confirmed_at__isnull=True)
        self.queryset = UserInfo.objects.select_related('org').filter(org=user_org, id__in=pending_users.values('id'))
        return self.list(request)







        

 




# Organization ViewSet
class OrgView(mixins.ListModelMixin, mixins.CreateModelMixin, GenericViewSet):
    authentication_classes = [SupabaseAuthBackend]
    permission_classes = [SuperadminRequired]
    serializer_class = OrganizationSerializer

    # Access to all users
    def list_orgs(self, request, *args, **kwargs):
        print("perm", self.permission_classes)
        self.queryset = Organizations.objects.all()
        return self.list(request, *args, **kwargs)

    # Access to Super Admins only
    def create_orgs(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)

    def get_permissions(self):
        if self.action == "list_orgs":
            self.permission_classes = [AllowAny]
        return super().get_permissions()


# Department ViewSet
class DeptView(mixins.ListModelMixin, mixins.CreateModelMixin, mixins.DestroyModelMixin ,mixins.UpdateModelMixin, GenericViewSet):
    # Default Permission Class
    permission_classes = [OrgadminRequired]
    queryset = Departments.objects.all()
    authentication_classes = [SupabaseAuthBackend]
    serializer_class = DepartmentSerializer
    lookup_field = "id"

    # Access to all Authenticated Users.
    def list_depts(self, request, *args, **kwargs):
        org_id = request.user.org_id
        self.queryset = Departments.objects.filter(org=org_id)
        return self.list(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        org_id = request.user.org
        serializer.save(org=org_id)
        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    # Access to Organizational Admins only.
    def create_depts(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)
    
    def delete_depts(self, request, *args, **kwargs):
        user = request.user
        self.lookup_field = "id"
        self.queryset = Departments.objects.filter(org = user.org_id)
        return self.destroy(request,**kwargs)

    def update_depts(self,request,*args,**kwargs):
        return self.partial_update(request, *args, **kwargs)

    def get_permissions(self):
        if self.action == "list_depts":
            self.permission_classes = [IsAuthenticated]
        elif self.action == "create_depts":
            self.permission_classes = [OrgadminRequired]
        return super().get_permissions()


# User ViewSet for Org Admin
class AUserViewSet(
    mixins.ListModelMixin,
    mixins.UpdateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.DestroyModelMixin,
    GenericViewSet,
):
    # Default Permission required for this class
    permission_classes = [OrgadminRequired]

    queryset = UserInfo.objects.all()
    serializer_class = AUserGetInfoSerializer
    authentication_classes = [SupabaseAuthBackend]
    lookup_field = "id"

    def list_users(self, request, *args, **kwargs):
        org_id = request.user.org_id
        dept = kwargs.get("dept")
        if dept:
            try:
                dept_id = Departments.objects.get(name=dept)
                self.queryset = UserInfo.objects.filter(org=org_id, dept=dept_id)
            except Departments.DoesNotExist:
                return Response(
                    {"error": "department not found"}, status=status.HTTP_404_NOT_FOUND
                )
        else:
            self.queryset = (
                UserInfo.objects.filter(org=org_id)
                .exclude(id=request.user.id)
                .order_by("-role_priv")
            )
            # self.queryset = Users.objects.filter(org=org_id)
        return self.list(request, context={'request':request}, **kwargs)

    # Checking the Role's Existance
    def partial_update(self, request, *args, **kwargs):

        if "role_priv" in request.data:
            # serializer = RoleSerializer(data=request.data["role_priv"], partial=True)
            # kk = serializer.is_valid()

            role = request.data["role_priv"]
            try:
                Role.objects.get(role=role)
            except Role.DoesNotExist:
                return Response(
                    {"error": "this role does not exist"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            except exceptions.ValidationError:
                return Response(
                    {"error": "invalid value"}, status=status.HTTP_400_BAD_REQUEST
                )
            return super().partial_update(request, *args, **kwargs)
        else:
            return super().partial_update(request, *args, **kwargs)

    def elevate(self, request, *args, **kwargs):
        self.serializer_class = AUserSetInfoSerializer
        pk = kwargs.get("pk")
        resp = self.partial_update(request, *args, **kwargs)
        return resp

    # Get diffent files using the type param
    # type = owned or received or shared
    def get_user_info(self, request, **kwargs):
        # Queried user instance
        user = request.user
        user_org = user.org
        instance = self.get_object()

        try:
            n = int(request.GET.get("recs", "0"))
            file_type = request.GET.get("type")  
            logs = request.GET.get("logs","0")
        except ValueError:
            return Response(
                {"error": "invalid parameter"}, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as error:
            return Response({"error": str(error)})
        
        if(logs == "1"):
            self.serializer_class = AccessLogSerializer
            user_id = kwargs.get("id")
            self.queryset = AccessLog.objects.filter(org_id = user_org.id,user=user_id).order_by("-timestamp")
            self.queryset = self.queryset[:n] if n >= 1 else self.queryset
            return self.list(request)
        

        combined_data = {}
        if file_type == "owned":
            # Fetching files owned by user
            files_owned_by_user = Objects.objects.filter(owner=instance)
            owned_files_data = FileSerializer(files_owned_by_user, many=True).data
            combined_data["files"] = owned_files_data

        elif file_type == "received":
            # Fetching files shared with the user
            files_shared_with_user = Objects.objects.filter(
                sharedfiles__shared_with=instance
            )
            shared_files_data = FileSerializer(files_shared_with_user, many=True).data
            combined_data["files"] = shared_files_data

        elif file_type == "shared":
            # Fetching files shared by user
            files_shared_by_user = Objects.objects.filter(
                sharedfiles__file__owner=instance.id
            )
            shared_files_by_user_data = FileSerializer(
                files_shared_by_user, many=True
            ).data
            combined_data["files"] = shared_files_by_user_data

        # User profile data
        user_data = self.get_serializer(instance).data
        combined_data["user_info"] = user_data

        return Response(combined_data, status=status.HTTP_200_OK)

    def delete_user(self, request,**kwargs):
        user = request.user
        self.lookup_field = 'id'
        self.queryset = UserInfo.objects.filter(org = user.org_id)
        return self.destroy(request,**kwargs)
    
    def get_permissions(self):
        if self.action == "list_users":
            self.permission_classes = [OthersPerm]
        return super().get_permissions()



# User Viewset for  Normal users
class NUserViewSet(mixins.ListModelMixin, mixins.UpdateModelMixin, GenericViewSet):
    authentication_classes = [SupabaseAuthBackend]
    permission_classes = [IsAuthenticated]
    serializer_class = NUserGetInfoSerializer
    lookup_field = "id"

    def get_current_user_info(self, request):
        current_user = request.user
        serializer = self.get_serializer(current_user)
        print(serializer.data)
        return Response(serializer.data)

    def update_profile_data(self, request, **kwargs):
        # self.serializer_class = NUserSetInfoSerializer
        # Retrieve the object based on the request user's ID
        user_id = request.user.id
        try:
            user_info = UserInfo.objects.get(id=user_id)
        except UserInfo.DoesNotExist:
            return Response({"error": "Profile not found for this user"}, status=404)

        # Check permissions if needed
        self.check_object_permissions(request, user_info)

        # Update the user_info object with the request data
        serializer = self.get_serializer(user_info, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data)        


# Roles Viewset
class RolesViewset(
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    GenericViewSet,
):
    authentication_classes = [SupabaseAuthBackend]
    queryset = Role.objects.all()
    permission_classes = [SuperadminRequired]
    serializer_class = RoleSerializer
    lookup_field = "id"

    def list_roles(self, request):
        return self.list(request)

    def create_roles(self, request):
        return self.create(request)

    def update_roles(self, request):
        return self.update(request)

    def delete_roles(self, request, *args, **kwargs):
        kwargs.get("pk")
        return self.destroy(request, *args, **kwargs)

    def get_permissions(self):
        if self.action == "list_roles":
            self.permission_classes = [OrgadminRequired]
        return super().get_permissions()
