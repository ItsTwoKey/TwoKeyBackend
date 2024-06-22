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
from rest_framework.status import HTTP_204_NO_CONTENT, HTTP_404_NOT_FOUND

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from firebase_admin import auth, firestore
from backend.firebase_admin_init import db
from backend.custom_perm_classes import SuperadminRequired
from .serializers import OrganizationSerializer
from rest_framework.decorators import api_view, permission_classes,authentication_classes
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework.response import Response
import json

from backend.firebase_auth import FirebaseAuthBackend
from authenticate.models import Identity, Users
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


def invite_user_to_firestore(user_data, user_org, department, role, first_name, last_name, confirmation_token):
    try:
        # Assuming UsersSerializer validates the data and has `is_valid` method.
        serializer = UsersSerializer(data=user_data)
        if serializer.is_valid():
            user_doc_ref = db.collection('users').document()
            user_data['id'] = user_doc_ref.id  # Assign the Firestore document ID to the user data.
            user_doc_ref.set(user_data)

            # Adding user to the organization
            user_info_ref = db.collection('user_info').document(user_doc_ref.id)
            user_info_ref.set({
                'org': user_org,
                'dept': department,
                'role_priv': role,
                'first_name': first_name,
                'last_name': last_name
            })

            # Creating Entry in identities Collection
            identity_ref = db.collection('identities').document(user_doc_ref.id)
            identity_ref.set({
                'provider_id': user_doc_ref.id,
                'user_id': user_doc_ref.id,
                'identity_data': {
                    'sub': user_doc_ref.id,
                    'email': user_data['email'],
                    'email_verified': False,
                    'phone_verified': False
                },
                'provider': 'email',
                'email': user_data['email']
            })

            # Sending the email
            email_response = send_email(user_data['email'], user_data['encrypted_password'], confirmation_token)
            print(email_response)
            return True
        return False
    except Exception as e:
        print(e)  # Log the error for debugging purposes
        return False

@api_view(['POST'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([OrgadminRequired])
@csrf_exempt
def invite_driver(request):
    user_org = request.user.org

    serializer = InviteUserSerializer(data=request.data)
    
    if serializer.is_valid():
        emails = serializer.validated_data.get('emails', [])
        try:
            first_name = request.data.get('first_name', '')
            last_name = request.data.get('last_name', '')

            department_id = request.data['dept_id']
            department = db.collection('departments').document(department_id).get().to_dict()

            role_id = request.data['role_id']
            role = db.collection('roles').document(role_id).get().to_dict().get('role')

        except Exception as e:
            return Response({"msg": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        failed_invites = []
        for email in emails:
            confirmation_token = generate_confirmation_token()
            password = generate_strong_password()
            user_data = {
                "email": email,
                "encrypted_password": password,
                "confirmation_token": confirmation_token,
                "raw_app_meta_data": {"provider": "email", "providers": ["email"]}
            }

            if not invite_user_to_firestore(user_data, user_org, department, role, first_name, last_name, confirmation_token):
                failed_invites.append(email)

        if failed_invites:
            return Response({"msg": "Some invites failed.", "failed_emails": failed_invites}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({"msg": "Invites sent successfully"}, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([OrgadminRequired])
@csrf_exempt
def get_pending_invites(request):
    user_org = request.user.org
    pending_users_query = db.collection('users').where('email_confirmed_at', '==', None).stream()
    pending_users = [user.to_dict() for user in pending_users_query]

    pending_user_info_query = db.collection('user_info').where('org', '==', user_org).where('id', 'in', [user['id'] for user in pending_users]).stream()
    pending_user_info = [user_info.to_dict() for user_info in pending_user_info_query]

    return Response(pending_user_info)

    
# Organization ViewSet
class OrgView(mixins.ListModelMixin, mixins.CreateModelMixin, GenericViewSet):
    authentication_classes = [FirebaseAuthBackend]
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


@api_view(['GET'])
@permission_classes([AllowAny])
@csrf_exempt  # Assuming you are not using session authentication
def list_orgs(request):
    try:
        orgs_ref = db.collection('organizations')
        orgs = orgs_ref.stream()

        response_data = []
        for org in orgs:
            org_data = org.to_dict()
            org_data['id'] = org.id
            response_data.append(org_data)

        return JsonResponse(response_data, safe=False, status=200)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@api_view(['POST'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([IsAuthenticated])
@csrf_exempt  # Assuming you are not using session authentication
def create_orgs(request):
    try:
        data = json.loads(request.body)
        org_ref = db.collection('organizations').document()
        org_ref.set(data)

        # Get the new document's ID
        data['id'] = org_ref.id

        return JsonResponse(data, status=201)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

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


@api_view(['GET'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([IsAuthenticated])
@csrf_exempt
def list_depts(request):
    try:
        org_id = request.user.org
        depts_ref = db.collection('departments').where('org', '==', org_id)
        depts = depts_ref.stream()

        response_data = []
        for dept in depts:
            dept_data = dept.to_dict()
            dept_data['id'] = dept.id
            response_data.append(dept_data)

        return JsonResponse(response_data, safe=False, status=200)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@api_view(['POST'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([OrgadminRequired])
@csrf_exempt
def create_dept(request):
    try:
        data = json.loads(request.body)
        org_id = request.user.org
        data['org'] = org_id
        name = data.get('name')
        metadata = data.get('metadata')

        dept_ref = db.collection('departments').document()
        dept_ref.set({'name': name, 'metadata': metadata, 'org': org_id})

        data['id'] = dept_ref.id

        return JsonResponse(data, status=201)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@api_view(['DELETE'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([OrgadminRequired])
@csrf_exempt
def delete_dept(request, id):
    try:
        user = request.user
        dept_ref = db.collection('departments').document(id)
        dept = dept_ref.get()

        if dept.exists and dept.to_dict().get('org') == user.org:
            dept_ref.delete()
            return JsonResponse({'message': 'Department deleted successfully'}, status=200)
        else:
            return JsonResponse({'error': 'Department not found or unauthorized'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@api_view(['PATCH'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([OrgadminRequired])
@csrf_exempt
def update_dept(request, id):
    try:
        data = json.loads(request.body)
        user = request.user
        dept_ref = db.collection('departments').document(id)
        dept = dept_ref.get()
        newName = data.get('name')
        metadata = data.get('metadata')

        if dept.exists and dept.to_dict().get('org') == user.org:
            dept_ref.update({'name': newName, 'metadata': metadata})
            updated_dept = dept_ref.get().to_dict()
            updated_dept['id'] = id
            return JsonResponse(updated_dept, status=200)
        else:
            return JsonResponse({'error': 'Department not found or unauthorized'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)



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
    authentication_classes= [FirebaseAuthBackend]

    # Define serializer class based on the action
    def get_serializer_class(self):
        if self.action == 'list_users':
            return AUserGetInfoSerializer
        if self.action == 'elevate':
            return AUserSetInfoSerializer
        return AUserGetInfoSerializer

    # List users based on organization and department
    def list_users(self, request, *args, **kwargs):
        org_id = request.user.org
        dept = kwargs.get("dept")
        users_ref = db.collection('users')
        if dept:
            dept_ref = db.collection('departments').where('name', '==', dept).get()
            if not dept_ref:
                return Response(
                    {"error": "department not found"}, status=status.HTTP_404_NOT_FOUND
                )
            dept_id = dept_ref[0].id
            query = users_ref.where('org', '==', org_id).where('dept', '==', dept_id)
        else:
            query = users_ref.where('org', '==', org_id).order_by('role_priv', direction=firestore.Query.DESCENDING)
        users = [doc.to_dict() for doc in query.stream() if doc.id != request.user.id]
        return Response(users, status=status.HTTP_200_OK)

    # Partial update to check role existence
    def partial_update(self, request, *args, **kwargs):
        if "role_priv" in request.data:
            role = request.data["role_priv"]
            role_ref = db.collection('roles').where('role', '==', role).get()
            if not role_ref:
                return Response(
                    {"error": "this role does not exist"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            return super().partial_update(request, *args, **kwargs)
        else:
            return super().partial_update(request, *args, **kwargs)

    # Elevate user
    def elevate(self, request, *args, **kwargs):
        self.serializer_class = AUserSetInfoSerializer
        return self.partial_update(request, *args, **kwargs)

    # Get user info and related files
    def get_user_info(self, request, **kwargs):
        user = request.user
        user_org = user.org
        instance = self.get_object()
        combined_data = {}

        try:
            n = int(request.GET.get("recs", "0"))
            file_type = request.GET.get("type")
            logs = request.GET.get("logs", "0")
        except ValueError:
            return Response(
                {"error": "invalid parameter"}, status=status.HTTP_400_BAD_REQUEST
            )

        if logs == "1":
            self.serializer_class = AccessLogSerializer
            user_id = kwargs.get("id")
            query = db.collection('access_logs').where('org_id', '==', user_org.id).where('user', '==', user_id).order_by('timestamp', direction=firestore.Query.DESCENDING)
            logs = [doc.to_dict() for doc in query.stream()]
            logs = logs[:n] if n >= 1 else logs
            return Response(logs, status=status.HTTP_200_OK)

        files_ref = db.collection('files')

        if file_type == "owned":
            files_owned_by_user = files_ref.where('owner', '==', instance.id).get()
            owned_files_data = [doc.to_dict() for doc in files_owned_by_user]
            combined_data["files"] = owned_files_data

        elif file_type == "received":
            files_shared_with_user = files_ref.where('shared_with', 'array_contains', instance.id).get()
            shared_files_data = [doc.to_dict() for doc in files_shared_with_user]
            combined_data["files"] = shared_files_data

        elif file_type == "shared":
            files_shared_by_user = files_ref.where('owner', '==', instance.id).get()
            shared_files_by_user_data = [doc.to_dict() for doc in files_shared_by_user]
            combined_data["files"] = shared_files_by_user_data

        user_data = self.get_serializer(instance).data
        combined_data["user_info"] = user_data

        return Response(combined_data, status=status.HTTP_200_OK)

    # Delete user
    def delete_user(self, request, **kwargs):
        user = request.user
        self.lookup_field = 'id'
        user_id = kwargs.get('id')
        db.collection('users').document(user_id).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    # Set permissions based on action
    def get_permissions(self):
        if self.action == "list_users":
            self.permission_classes = [OthersPerm]
        return super().get_permissions()


@api_view(['GET'])
@permission_classes([OthersPerm])
@csrf_exempt
@authentication_classes([FirebaseAuthBackend])
def list_users(request, *args, **kwargs):
    org_id = request.user.org
    dept = kwargs.get("dept")
    users_ref = db.collection('users')
    if dept:
        dept_ref = db.collection('departments').where('name', '==', dept).get()
        if not dept_ref:
            return Response(
                {"error": "department not found"}, status=status.HTTP_404_NOT_FOUND
            )
        dept_id = dept_ref[0].id
        query = users_ref.where('org', '==', org_id).where('dept', '==', dept_id)
    else:
        query = users_ref.where('org', '==', org_id).order_by('role_priv', direction=firestore.Query.DESCENDING)
    users = [doc.to_dict() for doc in query.stream() if doc.id != request.user.id]
    print(users)
    return Response(users, status=status.HTTP_200_OK)

@api_view(['PATCH'])
@permission_classes([OrgadminRequired])
@csrf_exempt
@authentication_classes([FirebaseAuthBackend])
def partial_update(request, *args, **kwargs):
    if "role_priv" in request.data:
        role = request.data["role_priv"]
        role_ref = db.collection('roles').where('role', '==', role).get()
        if not role_ref:
            return Response(
                {"error": "this role does not exist"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user_id = kwargs.get('id')
        user_ref = db.collection('users').document(user_id)
        user_ref.update(request.data)
        return Response({"status": "role updated"}, status=status.HTTP_200_OK)
    else:
        return Response({"error": "role_priv not provided"}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PATCH'])
@permission_classes([OrgadminRequired])
@csrf_exempt
@authentication_classes([FirebaseAuthBackend])
def elevate(request, id):
    data = request.data
    user_ref = db.collection('users').document(id)
    user_ref.update(data)
    return Response({"status": "elevated"}, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([OrgadminRequired])
@csrf_exempt
@authentication_classes([FirebaseAuthBackend])
def get_user_info(request, **kwargs):
    user = request.user
    user_org = user.org
    user_id = kwargs.get('id')
    instance_ref = db.collection('users').document(user_id)
    instance = instance_ref.get().to_dict()

    try:
        n = int(request.GET.get("recs", "0"))
        file_type = request.GET.get("type")
        logs = request.GET.get("logs", "0")
    except ValueError:
        return Response(
            {"error": "invalid parameter"}, status=status.HTTP_400_BAD_REQUEST
        )

    combined_data = {}
    if logs == "1":
        user_id = kwargs.get("id")
        query = db.collection('access_logs').where('org_id', '==', user_org.id).where('user', '==', user_id).order_by('timestamp', direction=firestore.Query.DESCENDING)
        logs = [doc.to_dict() for doc in query.stream()]
        logs = logs[:n] if n >= 1 else logs
        return Response(logs, status=status.HTTP_200_OK)

    files_ref = db.collection('files')

    if file_type == "owned":
        files_owned_by_user = files_ref.where('owner', '==', user_id).get()
        owned_files_data = [doc.to_dict() for doc in files_owned_by_user]
        combined_data["files"] = owned_files_data

    elif file_type == "received":
        files_shared_with_user = files_ref.where('shared_with', 'array_contains', user_id).get()
        shared_files_data = [doc.to_dict() for doc in files_shared_with_user]
        combined_data["files"] = shared_files_data

    elif file_type == "shared":
        files_shared_by_user = files_ref.where('owner', '==', user_id).get()
        shared_files_by_user_data = [doc.to_dict() for doc in files_shared_by_user]
        combined_data["files"] = shared_files_by_user_data

    user_data = instance
    combined_data["user_info"] = user_data

    return Response(combined_data, status=status.HTTP_200_OK)

@api_view(['DELETE'])
@permission_classes([OrgadminRequired])
@authentication_classes([FirebaseAuthBackend])
@csrf_exempt
def delete_user(request, **kwargs):
    user = request.user
    user_id = kwargs.get('id')

    if not user_id:
        return JsonResponse({'error': 'User ID not provided'}, status=HTTP_404_NOT_FOUND)

    # Delete user from Firestore
    user_doc_ref = db.collection('users').document(user_id)
    if user_doc_ref.get().exists:
        user_doc_ref.delete()
    else:
        return JsonResponse({'error': 'User not found in Firestore'}, status=HTTP_404_NOT_FOUND)

    # Delete user from Firebase Authentication
    try:
        auth.delete_user(user_id)
    except auth.AuthError as e:
        return JsonResponse({'error': f'Failed to delete user from Firebase Auth: {e}'}, status=HTTP_404_NOT_FOUND)
    
    return JsonResponse({'message': 'User deleted successfully'}, status=HTTP_204_NO_CONTENT)



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

db = firestore.client()

@api_view(['GET'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([OrgadminRequired])
@csrf_exempt
def list_roles(request):
    roles_ref = db.collection('roles')
    roles = [doc.to_dict() for doc in roles_ref.stream()]
    return Response(roles, status=status.HTTP_200_OK)

@api_view(['POST'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([SuperadminRequired])
@csrf_exempt
def create_roles(request):
    data = request.data
    role_ref = db.collection('roles').document()
    role_ref.set(data)
    return Response({"id": role_ref.id}, status=status.HTTP_201_CREATED)

@api_view(['PUT', 'PATCH'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([SuperadminRequired])
@csrf_exempt
def update_roles(request, id):
    data = request.data
    role_ref = db.collection('roles').document(id)
    role_ref.update(data)
    return Response({"status": "updated"}, status=status.HTTP_200_OK)

@api_view(['DELETE'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([SuperadminRequired])
@csrf_exempt
def delete_roles(request, id):
    role_ref = db.collection('roles').document(id)
    role_ref.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)