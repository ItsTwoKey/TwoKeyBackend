import datetime
import uuid
from django.core.cache import cache
from django.core import exceptions
from django.contrib.gis.geos import Point
from django.contrib.gis.measure import Distance
from decouple import config
from django.db import connection, reset_queries
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.db.models import Prefetch
from django.views.decorators.csrf import csrf_exempt


from rest_framework.viewsets import GenericViewSet , ModelViewSet
from rest_framework.views import APIView
from rest_framework import mixins, generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, authentication_classes

from backend.firebase_auth import FirebaseAuthBackend
from backend.firebase_admin_init import db
from backend import settings
from backend.custom_perm_classes import SuperadminRequired, OrgadminRequired, OthersPerm
from backend.supabase_auth import SupabaseAuthBackend


from .models import *
from fileoperations.serializers import (
    AccessLogSerializer,
    AllowedLocationSerializer,
    FileSerializer,
    FileMetaSerializer,
    SharedFileSerializer,
    SharedFilesRecepient,
    AddDepartmentsSerializer,
    FolderSerializer,
    FolderInteractSerializer
)

from .utils.supa import create_signed
from django.views.decorators.cache import cache_page
from django.utils.decorators import method_decorator

from firebase_admin import firestore, storage


Cache_TTL = 60


class ExtraChecksMixin:
    # Check if the user creating or deleting a share is the owner of the file
    def check_file_ownership(self, request, file_id):
        try:
            file_object = Objects.objects.get(id=file_id)
            file_owner = file_object.owner
        except Exception:
            print(Exception)
            return False
        current_user = request.user
        if current_user == file_owner:
            return True
        return False
    def check_folder_ownership(self, request, folder_id):
        try:
            folder_object = Folder.objects.get(id=folder_id)
            folder_owner = folder_object.owner.id
        except Exception:
            return False
        current_user = request.user.id
        
        if current_user == folder_owner:
            return True
        return False


class FileListing(mixins.ListModelMixin, generics.GenericAPIView):
    serializer_class = FileSerializer
    authentication_classes = [SupabaseAuthBackend]
    permission_classes = [OthersPerm]
    queryset = Objects.objects.all()


    def dispatch(self, request, *args, **kwargs):
        response = super().dispatch(request, *args, **kwargs)
        print("Queries :", connection.queries)
        print("Queries count :", len(connection.queries))
        return response

    # List all files uploaded by all users from all departments.

    def get(self, request, *args, **kwargs):
        dept_choice = kwargs.get("dept")
        file_type = request.GET.get("type")
        user = request.user
        try:
            n = int(request.GET.get("recs", "0"))
        except ValueError:
            return Response(
                {"error": "invalid parameter"}, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as error:
            return Response({"error": str(error)})

        if file_type == "owned":
            return self.get_files_owned_by_user(request, user)
        elif file_type == "received":
            return self.get_files_shared_to_user(request, user)
        elif file_type == "shared":
            return self.get_files_shared_by_user(request, user)
        else:
            return self.get_all_files(request, dept_choice, n)
            
    
    def get_all_files(self, request, dept_choice, n, *args, **kwargs):
        if dept_choice:
            try:
                dept = Departments.objects.get(name=dept_choice)

            except (Departments.DoesNotExist, ValueError, exceptions.ValidationError):
                return Response(
                    {"error": "invalid request"}, status=status.HTTP_400_BAD_REQUEST
                )
            
            self.queryset = (
                Objects.objects.select_related("owner")
                .prefetch_related(Prefetch('file_info', queryset=File_Info.objects.prefetch_related('depts')))
                .filter(owner__org=request.user.org, bucket_id="TwoKey",file_info__depts=dept.id)
                .exclude(name=".emptyFolderPlaceholder")
                .order_by("-created_at")
            )


        else:
            # print(FileSerializer(Objects.objects.prefetch_related().exclude(name=".emptyFolderPlaceholder"),many=True).data)
            # k = FileMetaSerializer(File_Info.objects.prefetch_related("depts").all(),many=True).data
            # print(k)
            self.queryset = (
                Objects.objects.select_related("owner")
                .prefetch_related(Prefetch('file_info', queryset=File_Info.objects.prefetch_related('depts')))
                .filter(owner__org=request.user.org, bucket_id="TwoKey")
                .exclude(name=".emptyFolderPlaceholder")
                .order_by("-created_at")
            )
        self.queryset = self.queryset[:n] if n >= 1 else self.queryset
        
        return self.list(request, *args, **kwargs)
    
    def get_files_owned_by_user(self, request, user):
        self.queryset = Objects.objects.select_related("owner").prefetch_related(Prefetch('file_info', queryset=File_Info.objects.prefetch_related('depts'))).select_related("owner__dept").filter(bucket_id="TwoKey",owner=user)
        return self.list(request)
    
    def get_files_shared_by_user(self, request, user):
        # Fetching files shared by user
        self.queryset = Objects.objects.prefetch_related(Prefetch('file_info', queryset=File_Info.objects.prefetch_related('depts'))).filter(sharedfiles__file__owner=user.id)
        return self.list(request)
    
    def get_files_shared_to_user(self, request, user):
        # Fetching files shared with the user
        self.queryset = Objects.objects.prefetch_related(Prefetch('file_info', queryset=File_Info.objects.prefetch_related('depts'))).filter(sharedfiles__shared_with=user)
        return self.list(request)

@api_view(['GET'])
@permission_classes([OthersPerm])
@csrf_exempt
@authentication_classes([FirebaseAuthBackend])
def list_files(request, *args, **kwargs):
    file_type = request.GET.get("type")
    user = request.user
    dept_choice = user.dept
    print(dept_choice,file_type)
    try:
        n = int(request.GET.get("recs", "0"))
    except ValueError:
        return JsonResponse({"error": "invalid parameter"}, status=400)
    except Exception as error:
        return JsonResponse({"error": str(error)}, status=400)

    if file_type == "owned":
        return get_files_owned_by_user(request, user)
    elif file_type == "received":
        return get_files_shared_to_user(request, user)
    elif file_type == "shared":
        return get_files_shared_by_user(request, user)
    else:
        return get_all_files(request, dept_choice, n)

def get_all_files(request, dept_choice, n, *args, **kwargs):
    user = request.user
    org_id = user.org
    
    files_ref = db.collection('files').document('organisations').collection(org_id)
    
    if user.role_priv == 'org_admin':
        files_ref = files_ref
    elif dept_choice:
        dept_ref = db.collection('departments').document(dept_choice).get()
        if not dept_ref.exists:
            return JsonResponse({"error": "invalid request"}, status=400)
        dept_id = dept_ref.id
        files_ref = files_ref.where('department_ids', 'array_contains', dept_id)
    
    files = files_ref.stream()
    file_list = [{"id": file.id, **file.to_dict()} for file in files]

    return JsonResponse(file_list[:n] if n > 0 else file_list, safe=False)

def get_files_owned_by_user(request, user):
    user_id = user.id
    org_id = user.org
    files_ref = db.collection('files').document('organisations').collection(org_id).where('owner_id', '==', user_id)
    files = files_ref.stream()
    file_list = [{"id": file.id, **file.to_dict()} for file in files]

    return JsonResponse(file_list, safe=False)

def get_files_shared_by_user(request, user):
    user_id = user.id
    shared_ref = db.collection('shared_files','organisations', user.org).where('owner_id', '==', user_id)
    shared_files = shared_ref.stream()
    file_ids = [file.to_dict().get('file_id') for file in shared_files]
    
    files = []
    for file_id in file_ids:
        file = db.collection('files','organisations', user.org).document(file_id).get()
        is_valid = check_if_share_is_valid(file_id, user)
        if file.exists and is_valid:
            file_data = file.to_dict()
            file_data['id'] = file_id
            files.append(file_data)

    return JsonResponse(files, safe=False)

def get_files_shared_to_user(request, user):
    user_id = user.id
    shared_ref = db.collection('shared_files', 'organisations', user.org).where('shared_with', '==', user_id)
    shared_files = shared_ref.stream()
    file_ids = [file.to_dict().get('file_id') for file in shared_files]

    files = []
    for file_id in file_ids:
        file = db.collection('files','organisations', user.org).document(file_id).get()
        is_valid = check_if_share_is_valid(file_id, user)
        print('is share valid',is_valid)
        if file.exists and is_valid:
            file_data = file.to_dict()
            file_data['id'] = file_id
            files.append(file_data)

    return JsonResponse(files, safe=False)



@api_view(['POST'])
@permission_classes([OrgadminRequired])
@csrf_exempt
@authentication_classes([FirebaseAuthBackend])
def add_departments_to_file(request, file_id, *args, **kwargs):
    org_id = request.user.org
    file_ref = db.collection('files', 'organisations', org_id).document(file_id)
    file_doc = file_ref.get()
    department_ids = request.data.get('department_ids', [])
    metadata = request.data.get('metadata', {})

    for department_id in department_ids:
        department_ref = db.collection('departments').document(department_id)
        department_doc = department_ref.get()
        if not department_doc.exists:
            return Response({'detail': f'Department {department_id} not found'}, status=status.HTTP_404_NOT_FOUND)

    if not file_doc.exists:
        # Check if the request contains the 'new' property to create a new file
        if 'new' in request.data:
            # Assuming the request contains necessary file details like name, etc.
            file_name = request.data.get('name', '')
            download_url = request.data.get('downloadURL', '')
            new_file_data = {
                'name': file_name,
                'department_ids': department_ids,
                'download_url':download_url,
                'owner_id': request.user.id,
                'metadata': metadata,
                'created_at': firestore.SERVER_TIMESTAMP,
                'updated_at': firestore.SERVER_TIMESTAMP,
                'profile_pic': request.user.profilePictureUrl,
            }
            # Create a new file document
            file_ref.set(new_file_data)
            return Response({'detail': 'New file created successfully'}, status=status.HTTP_201_CREATED)
        else:
            return Response({'detail': 'File not found'}, status=status.HTTP_404_NOT_FOUND)

    if department_ids:
        # Get current departments associated with the file
        current_department_ids = set(file_doc.to_dict().get('department_ids', []))

        # Check if departments are already associated and add only unique departments
        unique_department_ids = set(department_ids) - current_department_ids

        # Update the file with new department IDs
        new_department_ids = current_department_ids | unique_department_ids
        file_ref.update({'department_ids': list(new_department_ids)})

        return Response({'detail': 'Departments added successfully'}, status=status.HTTP_200_OK)

    return Response({"errors":["DepartmentId not provided"]}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
@permission_classes([OthersPerm])
@authentication_classes([FirebaseAuthBackend])
def delete_file(request, file_id):
    org_id = request.user.org
    try:
        file_ref = db.collection('files','organisations',org_id).document(file_id)
        file_doc = file_ref.get()
        if not file_doc.exists:
            return Response({'detail': 'File not found'}, status=status.HTTP_404_NOT_FOUND)
        
        file_ref.delete()
        return Response({'detail': 'File deleted successfully'}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# class FolderViewSet(GenericViewSet,
# mixins.ListModelMixin,
# mixins.CreateModelMixin,
# mixins.DestroyModelMixin,
# ):
#     authentication_classes = [SupabaseAuthBackend]
#     permission_classes = [OthersPerm]
#     serializer_class = FolderSerializer
#     queryset = Folder.objects.all()

#     def list(self,request):
#         user_org = request.user.org.id
#         user_id = request.user.id
#         queryset = Folder.objects.filter(org=user_org,owner=user_id)
#         serializer = self.get_serializer(queryset,many=True)
#         return Response(serializer.data)
        
#     def create(self,request):
#         user = request.user
#         owner_org_id = user.org.id
#         owner_dept  = user.dept.id
#         request.data['org'] = owner_org_id
#         request.data['dept'] = owner_dept 
#         request.data['owner'] = user.id
#         serializer = self.get_serializer(data=request.data)
#         if(serializer.is_valid(raise_exception=True)):
#             serializer.save()
#             return Response(serializer.data)
#         else:
#             return Response({"error":"Invalid data"})
    
#     def destroy(self, request, pk=None):
#         user = request.user.id
#         try:
#             folder = Folder.objects.get(pk=pk,owner=user)
#         except Folder.DoesNotExist:
#             return Response({"error": "Folder does not exist"}, status=status.HTTP_404_NOT_FOUND)

#         self.perform_destroy(folder)
#         return Response({'msg':"folder deleted"},status=status.HTTP_204_NO_CONTENT)

#     # def partial_update(self, request, pk=None):
#     #     try:
#     #         folder = Folder.objects.get(pk=pk,owner=user)
#     #     except Folder.DoesNotExist:
#     #         return Response({"error": "Folder does not exist"}, status=status.HTTP_404_NOT_FOUND)
#     #     # request_data = request.data.copy()
#     #     request.data['org'] = owner_org_ids 
#     #     request.data['owner'] = user.id
#     #     request_data.pop('dept', None)      
#     #     print(request.data)
#     #     serializer = self.get_serializer(folder, data=request.data, partial=True)
#     #     if serializer.is_valid(raise_exception=True):
#     #         serializer.save()
#     #         return Response(serializer.data)
#     #     else:
#     #         return Response({"error": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)


class FolderViewSet(GenericViewSet, mixins.ListModelMixin, mixins.CreateModelMixin, mixins.DestroyModelMixin):
    authentication_classes = [FirebaseAuthBackend]
    permission_classes = [OthersPerm]
    serializer_class = FolderSerializer

    def list(self, request):
        user_org = request.user.org
        user_id = request.user.id
        folders_ref = db.collection('folders').where('org', '==', user_org).where('owner', '==', user_id)
        folders = [{**doc.to_dict(), 'id': doc.id} for doc in folders_ref.stream()]
        serializer = self.get_serializer(folders, many=True)
        return Response(serializer.data)

    def create(self, request):
        user = request.user
        owner_org_id = user.org
        owner_dept = user.dept
        request.data['org'] = owner_org_id
        request.data['dept'] = owner_dept 
        request.data['owner'] = user.id

        # Saving data to Firestore
        folders_ref = db.collection('folders')
        new_folder_ref = folders_ref.add({"dept": owner_dept, "org": owner_org_id, "owner": user.id, "name": request.data['name'], "metadata": request.data['metadata']})
        new_folder = new_folder_ref[1].get()
        
        # Adding the document ID to the response
        folder_data = {**new_folder.to_dict(), 'id': new_folder.id}
        
        if new_folder.exists:
            return Response(folder_data, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": "Invalid request"}, status=status.HTTP_400_BAD_REQUEST)


    def destroy(self, request, pk=None):
        user = request.user.id
        folder_ref = db.collection('folders').document(pk)
        folder = folder_ref.get()
        if not folder.exists or folder.to_dict().get('owner') != user:
            return Response({"error": "Folder does not exist"}, status=status.HTTP_404_NOT_FOUND)
        
        folder_ref.delete()
        return Response({'msg': "Folder deleted"}, status=status.HTTP_204_NO_CONTENT)

    def partial_update(self, request, pk=None):
        user = request.user
        folder_ref = db.collection('folders').document(pk)
        folder = folder_ref.get()
        if not folder.exists or folder.to_dict().get('owner') != user.id:
            return Response({"error": "Folder does not exist"}, status=status.HTTP_404_NOT_FOUND)
        
        request.data['org'] = user.org
        request.data['owner'] = user.id
        folder_ref.update(request.data)
        updated_folder = folder_ref.get().to_dict()
        serializer = self.get_serializer(data=updated_folder)
        if serializer.is_valid(raise_exception=True):
            return Response(serializer.data)
        else:
            return Response({"error": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)

class FolderInteractViewSet(GenericViewSet,mixins.ListModelMixin,ExtraChecksMixin):
    authentication_classes = [SupabaseAuthBackend]
    permission_classes = [OthersPerm]
    
    def add_file_to_folder(self,request,folder_id):

        try:
            file_id = request.data['file_id']
        except:
            return Response({"file_id":"field required"})
        serializer = FolderInteractSerializer(data={"file_id":file_id,"folder_id":folder_id})
        if(serializer.is_valid(raise_exception=True)):
            if(1==1):
                file_info_rec = File_Info.objects.get(file=file_id)
                file_info_rec.folder = Folder.objects.get(id=folder_id)
                file_info_rec.save()
                return Response("File added successfully",status=status.HTTP_200_OK)
            else:
                return Response({"error":"Invalid file or folder"})
        return Response({"error":"Data error"},status=status.HTTP_400_BAD_REQUEST)



    def list_files_in_current_folder(self,request,folder_id):
        try:
            folder_id = uuid.UUID(folder_id)
        except ValueError:
            return Response({"error": "Invalid folder_id"}, status=status.HTTP_400_BAD_REQUEST)
            
        if(self.check_folder_ownership(request,folder_id)):
            # files_in_folder = File_Info.objects.filter(folder_id=folder_id)

            files_in_folder = (
                Objects.objects.select_related("owner")
                .prefetch_related(Prefetch('file_info', queryset=File_Info.objects.prefetch_related('depts')))
                .filter(owner__org=request.user.org, bucket_id="TwoKey",file_info__folder_id=folder_id)
                .exclude(name=".emptyFolderPlaceholder")
                .order_by("-created_at")
            )

            serializer = FileSerializer(files_in_folder, many=True)

            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({"error":"You do not own this folder"},status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([OthersPerm])
@csrf_exempt
def add_file_to_folder(request, folder_id):
    user = request.user
    try:
        file_id = request.data['file_id']
    except KeyError:
        return Response({"file_id": "field required"}, status=status.HTTP_400_BAD_REQUEST)

    folder_ref = db.collection('folders').document(folder_id)
    file_ref = db.collection('files','organisations',user.org).document(file_id)

    folder_doc = folder_ref.get()
    file_doc = file_ref.get()

    if not folder_doc.exists:
        return Response({"error": "Invalid folder"}, status=status.HTTP_400_BAD_REQUEST)

    if not file_doc.exists:
        return Response({"error": "Invalid file"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        file_ref.update({'folder_id': folder_id})
        return Response("File added successfully", status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([OthersPerm])
@csrf_exempt
def list_files_in_current_folder(request, folder_id):
    user = request.user
    org_id = user.org

    folder_ref = db.collection('folders').document(folder_id)
    folder_doc = folder_ref.get()

    if not folder_doc.exists:
        return Response({"error": "You do not own this folder"}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        files_ref = db.collection('files','organisations',org_id).where('folder_id', '==', folder_id)
        files = files_ref.stream()
        file_list = [file.to_dict() for file in files]

        return Response(file_list, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

#  Below are the endpoints used at the Sender's side.
class ShareViewSetSender(
    ExtraChecksMixin,
    mixins.RetrieveModelMixin,
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.UpdateModelMixin,
    GenericViewSet,
):
    authentication_classes = [SupabaseAuthBackend]
    serializer_class = SharedFileSerializer
    permission_classes = [OthersPerm]
    queryset = SharedFiles.objects.select_related("file").select_related("file__owner").all()

    # def dispatch(self, request, *args, **kwargs):
    #     response = super().dispatch(request, *args, **kwargs)
    #     print("Queries :", connection.queries)
    #     print("Queries count :", len(connection.queries))
    #     return response

    # Delete a file share if the user is the owner of the file
    def destroy(self, request, *args, **kwargs):
        file_id = kwargs.get("file")
        if self.check_file_ownership(request, file_id):
            return super().destroy(request, *args, **kwargs)
        else:
            return Response(
                {"error": "You cannot delete this share"},
                status=status.HTTP_403_FORBIDDEN,
            )

    # Share a file (alias for create)
    # Create a file share for list of UUIDs.
    # - Share a list of files
    # - Assigns a presigned url to the share as in the expiration_time parameter.
    # - Security Features not yet added.
    def share_file(self, request):
        file_ids = request.data.get("file", [])
        shared_files = []
        shared_with = request.data["shared_with"]
        if type(file_ids) != list:
            return Response(
                {"error": "file should be a list"}, status=status.HTTP_400_BAD_REQUEST
            )
        if(len(shared_with)==0):
            return Response(
                {"error": " This field 'shared_with' required"}, status=status.HTTP_400_BAD_REQUEST
            )

        for file_id in file_ids:
            if self.check_file_ownership(request, file_id):
                request.data.pop("file")
                request.data["file"] = file_id
                for id in shared_with:
                    if(SharedFiles.objects.filter(file=file_id,shared_with__id=id)):
                        return Response({"error":f"File already shared with {id}"},status=status.HTTP_406_NOT_ACCEPTABLE)
                serializer = self.get_serializer(data=request.data)
                serializer.is_valid(raise_exception=True)
                self.perform_create(serializer)
                shared_files.append(file_id)
            else:
                return Response(
                    {"error": "You cannot share this file"},
                    status=status.HTTP_403_FORBIDDEN,
                )
        headers = self.get_success_headers(serializer.data)
        response_data = {
            "message": "Shares created SuccessFully!",
            "shared_files": shared_files,
        }
        return Response(response_data, status=status.HTTP_201_CREATED, headers=headers)

    # Get information about the shared file, including its name, id, and the list of users it's shared with
    # Returns Information about the Shared file given
    #  - file_name
    #  - file_id
    #  - Shared_with list
    def get_file_info(self, request, *args, **kwargs):
        user = request.user
        self.lookup_field = "file"
        file = kwargs.get("file")

        cache_key = f"file_info_{file}"

        cache_data = cache.get(cache_key)
        if(cache_data):
            return Response(cache_data)
        self.queryset = SharedFiles.objects.filter(shared_with__id=user.id)
        res = self.retrieve(request,*args,**kwargs)
        cache.set(cache_key,res.data,timeout=3600*24*2)
        return res

    # Delete All share of a file
    # User file ownership check added already
    def delete_share(self, request, *args, **kwargs):
        self.lookup_field = "file"
        pk = kwargs.get("file")
        return self.destroy(request)

    # Edit file access
    # - The Access log entry is not implemented
    def edit_access(self, request, **kwargs):
        file_id = kwargs.get("file")
        self.lookup_field = "file"
        user = request.user
        org_id = user.org
        user_role = user.role_priv
        if user_role == "org_admin":
            return self.partial_update(request, **kwargs)
        elif self.check_file_ownership(request, file_id):
            return self.partial_update(request, **kwargs)
        else:
            return Response(
                {"error": "You cannot modify this share"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

def check_file_ownership(request, file_id):
    # Replace this with your logic to check if the user owns the file
    user = request.user
  
    file_ref = db.collection('files','organisations',user.org).document(file_id).get()
   
    if file_ref.exists and file_ref.to_dict().get('owner_id') == user.id:
        return True
    return False

@api_view(['DELETE'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([OthersPerm])
@csrf_exempt
def destroy(request, file_id):
    if check_file_ownership(request, file_id):
        try:
            db.collection('shared_files').document(file_id).delete()
            return Response({"message": "File share deleted successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        return Response({"error": "You cannot delete this share"}, status=status.HTTP_403_FORBIDDEN)

@api_view(['POST'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([OthersPerm])
@csrf_exempt
def share_file(request):
    file_ids = request.data.get("file", [])
    shared_with = request.data.get("shared_with", [])
    # TODO implement created at field and cron job to delete expired shares
    expiration_time = request.data.get("expiration_time", 3600)
    security_check = request.data.get("security_check", {})
    user = request.user
    shared_files = []
    
    if not isinstance(file_ids, list):
        return Response({"error": "file should be a list"}, status=status.HTTP_400_BAD_REQUEST)
    
    if len(shared_with) == 0:
        return Response({"error": "This field 'shared_with' required"}, status=status.HTTP_400_BAD_REQUEST)
    
    for file_id in file_ids:
        is_owner = check_file_ownership(request, file_id)
       
        if is_owner:
            for user_id in shared_with:
                if db.collection('shared_files','organisations', user.org).where('file_id', '==', file_id).where('shared_with', '==', user_id).get():
                    return Response({"error": f"File already shared with {user_id}"}, status=status.HTTP_406_NOT_ACCEPTABLE)
                db.collection('shared_files', 'organisations', user.org).add({
                    'file_id': file_id,
                    'shared_with': user_id,
                    'owner_id': user.id,
                    'expiration_time': expiration_time,
                    'security_check': security_check,
                    'created_at': firestore.SERVER_TIMESTAMP,
                    'name': db.collection('files','organisations', user.org).document(file_id).get().to_dict().get('name'),
                })
                shared_files.append(file_id)
        else:
            return Response({"error": "You cannot share this file"}, status=status.HTTP_403_FORBIDDEN)
    
    response_data = {
        "message": "Shares created successfully!",
        "shared_files": shared_files,
    }
    return Response(response_data, status=status.HTTP_201_CREATED)

@api_view(['GET'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([OthersPerm])
@csrf_exempt
def get_file_info(request, file_id):
    user = request.user
    cache_key = f"file_info_{file_id}"
    cache_data = cache.get(cache_key)
    
    if cache_data:
        return Response(cache_data)
    
    # Query for shared_with
    # implement check for expiration time

    shared_with_files = db.collection('shared_files', 'organisations', user.org).where(
        'file_id', '==', file_id
    ).where(
        'shared_with', '==', user.id
    ).get()

    results = []
    for doc in shared_with_files:
        is_valid = check_if_share_is_valid(doc.id, user)
        if is_valid:
            result = doc.to_dict()
            result['id'] = doc.id
        results.append(result)

    # Query for owner_id
    owner_file_ref = db.collection('files','organisations', user.org).document(file_id).get()
    owner_files = []
    if owner_file_ref.exists and owner_file_ref.to_dict().get('owner_id') == user.id:
        owner_files.append(owner_file_ref.to_dict())

    # Combine results
    combined_files = results + owner_files

    if not combined_files:
        return Response({"error": "No shared file info found"}, status=status.HTTP_404_NOT_FOUND)

    shared_file = combined_files[0]
    cache.set(cache_key, shared_file, timeout=3600 * 24 * 2)
    return Response(shared_file, status=status.HTTP_200_OK)

@api_view(['DELETE'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([OthersPerm])
@csrf_exempt
def delete_share(request, file_id):
    return destroy(request, file_id)

@api_view(['PATCH'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([OthersPerm])
@csrf_exempt
def edit_access(request, file_id):
    if check_file_ownership(request, file_id):
        try:
            db.collection('shared_files').document(file_id).update(request.data)
            return Response({"message": "Access updated successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        return Response({"error": "You cannot modify this share"}, status=status.HTTP_401_UNAUTHORIZED)

# Below will be used at recepient's end
class ShareViewSetReceiver(
    ExtraChecksMixin,
    mixins.RetrieveModelMixin,
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.ListModelMixin,
    GenericViewSet,
):
    serializer_class = SharedFilesRecepient
    authentication_classes = [SupabaseAuthBackend]
    permission_classes = [OthersPerm]

    # def dispatch(self, request, *args, **kwargs):
    #     response = super().dispatch(request, *args, **kwargs)
    #     print("Queries :", connection.queries)
    #     print("Queries count :", len(connection.queries))
    #     return response

    def retrieve(self, request, *args, **kwargs):
        # user = request.user
        # file_id = kwargs.get("file")
        
        instance = self.get_object()
        print(instance.security_check)
        sec_obj = SecCheck.objects.get(shared=instance)
        if sec_obj.geo_enabled == None:
            return super().retrieve(request, *args, **kwargs)
        else:
            try:
                latitude = float(self.request.data.get("latitude", 0))
                longitude = float(self.request.data.get("longitude", 0))
                user_location = Point(latitude, longitude, srid=4326)
                required_location = sec_obj.geo_enabled.location_point
                distance_in_kms = user_location.distance(required_location) * 100

                if distance_in_kms <= 1:
                    return super().retrieve(request, *args, **kwargs)
                else:
                    return Response(
                        {"error": "Location Not Allowed!"},
                        status=status.HTTP_401_UNAUTHORIZED,
                    )
            except ValueError:
                return Response(
                    {"error": "wrong parameter value"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            except Exception as error:
                return Response(
                    {"error": str(error)}, status=status.HTTP_400_BAD_REQUEST
                )

    # Endpoint Serves recepient with the presigned url
    # - Adds an access log entry.
    def get_shared_file_url(self, request, *args, **kwargs):
        # Only files shared with the current user
        
        user = request.user
        user_role = user.role_priv
        user_org = user.org
        self.lookup_field = "file"
    

        if not self.check_file_ownership(request, kwargs.get("file")):
            if user_role == "org_admin":
                self.queryset = Objects.objects.select_related("owner").filter(
                    owner__org=user_org
                )
                objs = get_object_or_404(self.queryset, id=kwargs.get("file"))
                signed_url = create_signed(objs.name, 60)
                response = Response({"id": objs.id, "signed_url": signed_url})
            else:
                self.queryset = SharedFiles.objects.filter(
                    shared_with__id=request.user.id
                )
                response = self.retrieve(request, *args, **kwargs)

            
            if response.status_code == 200:
                
                file_id = kwargs.get("file")
                access_log_data = {
                    "user": user.id,
                    "username": user.username,
                    "user_email": user.email,
                    "profile_pic": user.profile_pic,
                    "file": uuid.UUID(file_id),
                    "file_name": Objects.objects.get(id=file_id).name,
                    "event": "file_access",
                    "org": user.org.id,
                }

                access_log_serializer = AccessLogSerializer(data=access_log_data)

                print(access_log_data)
                if access_log_serializer.is_valid():
                    print("HELLO")
                    access_log_serializer.save()
                    key1 = f"log_access_{file_id}"
                    key2 = f"log_all_{file_id}"
                    # Deleting and setting new access cache
                    cache.delete_many([key1,key2])

            
            return response
        else:
            self.queryset = Objects.objects.filter(owner=user)
            objs = get_object_or_404(self.queryset, id=kwargs.get("file"))
            signed_url = create_signed(objs.name, 60)
            return Response({"id": objs.id, "signed_url": signed_url})


# Utility function to create a signed URL
def create_signed(file_name, expiration_minutes=60):
    bucket = storage.bucket()
    blob = bucket.blob(file_name)
    url = blob.generate_signed_url(expiration=datetime.timedelta(minutes=expiration_minutes), method="GET")
    return url

@api_view(['GET'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([OthersPerm])
@csrf_exempt
def retrieve_file_info(request, file_id):
    user_org = request.user.org
    try:
        shared_ref = db.collection('shared_files','organisations', user_org).document(file_id)
        shared_doc = shared_ref.get()

        if not shared_doc.exists:
            return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)

        shared_data = shared_doc.to_dict()
        if 'geo_enabled' in shared_data:
            latitude = float(request.query_params.get("latitude", 0))
            longitude = float(request.query_params.get("longitude", 0))
            user_location = (latitude, longitude)
            required_location = (shared_data['geo_enabled']['latitude'], shared_data['geo_enabled']['longitude'])
            distance_in_kms = user_location.distance(required_location) * 100

            if distance_in_kms > 1:
                return Response({"error": "Location Not Allowed!"}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(shared_data, status=status.HTTP_200_OK)
    except ValueError:
        return Response({"error": "Wrong parameter value"}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def check_if_share_is_valid(file_id, user):
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    
    # Retrieve the document
    doc_list = db.collection('shared_files', 'organisations', user.org).where('file_id', '==', file_id).get()
    print(user.org, file_id)
    
    if not doc_list:
        return {"error": "File not found"}
    
    doc = doc_list[0]
    
    if not doc.exists:
        return {"error": "File not found"}
    
    data = doc.to_dict()
    created_at = data.get('created_at')
    expiry = data.get('expiration_time')
    
    if created_at and expiry:
        created_at_dt = created_at.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        expiry_dt = created_at_dt + datetime.timedelta(seconds=expiry)
        
        print(f"Created at: {created_at_dt}, Expiry at: {expiry_dt}")
        print(now > expiry_dt)
        if now > expiry_dt:
            # Delete the document if it has expired
            doc.reference.delete()
            return False
        else:
            # File is still valid
            return True
    
    # If created_at or expiry is not found in the document
    return {"error": "Invalid file data"}
    
    return {"error": "File metadata is missing or invalid"}

@api_view(['POST'])
@authentication_classes([FirebaseAuthBackend])
@permission_classes([OthersPerm])
@csrf_exempt
def get_shared_file_url(request, file_id):
    try:
        user = request.user
        user_role = user.role_priv
        user_org = user.org
        shared_doc = None  # Initialize shared_doc to avoid reference before assignment

        if not check_file_ownership(request, file_id):
            if user_role == "org_admin":
                file_ref = db.collection('files').document(f'organisations/{user_org}/{file_id}')
                file_doc = file_ref.get()
                if not file_doc.exists:
                    return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)

                file_name = f'files/{user_org}/{file_doc.to_dict()["name"]}'
                signed_url = create_signed(file_name)
                response_data = {"id": file_doc.id, "signed_url": signed_url}
            else:
                is_valid = check_if_share_is_valid(file_id, user)

                if not is_valid:
                    return Response(is_valid, status=status.HTTP_404_NOT_FOUND)
                
                shared_list = db.collection('shared_files','organisations',user.org).where('file_id', '==', file_id).where('shared_with', '==', user.id).get()
                shared_doc_snapshot = shared_list[0]
                shared_doc = shared_doc_snapshot.to_dict()
                print(shared_doc)
                if not shared_doc:
                    return Response({"error": "Shared file not found"}, status=status.HTTP_404_NOT_FOUND)
                file_name = f'files/{user_org}/{shared_doc["name"]}'
                signed_url = create_signed(file_name)
                response_data = {"id": shared_doc['file_id'], "signed_url": signed_url}

            # Log access event
            log_data = {
                "user": user.id,
                "username": user.username,
                "user_email": user.email,
                "profile_pic": user.profilePictureUrl,
                "file": file_id,
                "file_name": (shared_doc.get('name') if shared_doc else file_doc.to_dict().get('name')),
                "event": "file_access",
                "org": user_org,
            }
            db.collection(f'access_logs/organisations/{user_org}').add(log_data)

            return Response(response_data, status=status.HTTP_200_OK)
        else:
            file_ref = db.collection('files').document(f'organisations/{user_org}/{file_id}')
            file_doc = file_ref.get()
            if not file_doc.exists:
                return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)

            file_name = f'files/{user_org}/{file_doc.to_dict()["name"]}'
            signed_url = create_signed(file_name)
            return Response({"id": file_doc.id, "signed_url": signed_url})
    except Exception as e:
        print(e)
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoggingView(
    ExtraChecksMixin,
    mixins.RetrieveModelMixin,
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.ListModelMixin,
    GenericViewSet,
):
    serializer_class = AccessLogSerializer
    authentication_classes = [SupabaseAuthBackend]
    permission_classes = [OthersPerm]

    
    def dispatch(self, request, *args, **kwargs):
        response = super().dispatch(request, *args, **kwargs)
        print("Queries :", connection.queries)
        print("Queries count :", len(connection.queries))
        return response


    def event_log_handler(self, request, *args, **kwargs):
        # Only files shared with the current user
        user = request.user
        file_id = kwargs.get("file")
        allowed_events = ["screenshot", "download"]
        try:
            event = request.GET.get("event", "screenshot")
            if event not in allowed_events:
                raise ValueError
        except ValueError:
            return Response(
                {"error": "invalid parameter"}, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as error:
            return Response({"error": str(error)})

        return self.create_log(request, user, event, *args, **kwargs)

    def create_log(self, request, user, event, *args, **kwargs):
        try:
            file_id = kwargs.get("file")
            shared = SharedFiles.objects.get(
                shared_with__id=request.user.id, file=file_id
            )

            access_log_data = {
                "user": user.id,
                "username": user.username,
                "user_email": user.email,
                "profile_pic":user.profile_pic,
                "file": uuid.UUID(file_id),
                "file_name": Objects.objects.get(id=file_id).name,
                "event": event,
                "org": user.org.id,
            }
            access_log_serializer = AccessLogSerializer(data=access_log_data)
            if access_log_serializer.is_valid():
                access_log_serializer.save()
            return Response(
                {"message": f"event logged successfully"},
                status=status.HTTP_201_CREATED,
            )
        except exceptions.ValidationError:
            return Response(
                {"error": "wrong parameter value"}, status=status.HTTP_400_BAD_REQUEST
            )
        except SharedFiles.DoesNotExist:
            return Response(
                {"error": "invalid share"}, status=status.HTTP_400_BAD_REQUEST
            )
        except Objects.DoesNotExist:
            return Response(
                {"error": "file does not exist"}, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as error:
            return Response({"error": str(error)}, status=status.HTTP_400_BAD_REQUEST)

    # Fetch the screen shot attempts for Current user's files
    def get_logs(self, request, *args, **kwargs):
        user = request.user
        event = kwargs.get("event")
        file = kwargs.get("file")

        # Get URL all parameters
        try:
            n = int(request.GET.get("recs", "0"))
            all_logs = int(request.GET.get("global", "1"))
        except ValueError:
            return Response(
                {"error": "invalid parameter"}, status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as error:
            return Response({"error": str(error)})

        # List of events
        all_events = ["access", "download", "screen"]

        # User activity logging system
        if event in all_events:
            event_filter = self.event_selector(event)
            if file:
                return self.handle_event_by_file(request, event_filter, file, n)
            else:
                return self.handle_event_all(request, event_filter, n)

        # The DUES logging  system
        elif event == "dues":
            return self.handle_due_event_all(user, n)

        # If now event is specified logs for all events:
        else:
            if file:
                return self.handle_all_by_file(request, user, file, n)
            else:
                return self.handle_all(request, user, n, all_logs)

    def event_selector(self, event_name):
        event_filter = {"include": {"event": []}, "exclude": {"event": []}}

        if event_name == "access":
            event_filter["include"]["event"].append("file_access")
        elif event_name == "download":
            event_filter["include"]["event"].append("download")
        elif event_name == "screen":
            event_filter["include"]["event"].append("screenshot")

        return event_filter

    def handle_event_by_file(self, request, event_filter, file, n):
        user = request.user
        user_org = user.org

        try:
            # Cache
            cache_key = f"log_{event_filter}_{file}"

            # Check if the data is already in the cache
            cached_data = cache.get(cache_key)
            if cached_data:
                return Response(cached_data)

            # If not in the cache, fetch the data from the database
            self.queryset = (
                AccessLog.objects.select_related("org")
                .filter(
                    file=file, org=user_org, event__in=event_filter["include"]["event"]
                )
                .order_by("-timestamp")
            )
            self.lookup_field = "file"
            self.queryset = self.queryset[:n] if n >= 1 else self.queryset
            response = self.list(request)

            # Cache the response with the custom cache key
            cache.set(cache_key, response.data, timeout=3600*24)

            return response

        except (AccessLog.DoesNotExist, exceptions.ValidationError, ValueError):
            return Response(
                {"error": "invalid request"}, status=status.HTTP_400_BAD_REQUEST
            )

    def handle_event_all(self, request, event_filter, n):
        user = request.user
        try:
            self.queryset = AccessLog.objects.filter(
                org=user.org, event__in=event_filter["include"]["event"]
            ).order_by("-timestamp")
            self.lookup_field = "file"
            self.queryset = self.queryset[:n] if n >= 1 else self.queryset
            return self.list(request)
        except (AccessLog.DoesNotExist, exceptions.ValidationError, ValueError):
            return Response(
                {"error": "invalid request"}, status=status.HTTP_400_BAD_REQUEST
            )

    def handle_due_event_all(self, user, n):
        self.serializer_class = SharedFileSerializer
        try:
            self.queryset = (
                SharedFiles.objects.select_related("file__owner__org")
                .filter(file__owner__org=user.org, state="due")
                .order_by("-last_modified_at")
            )
            self.queryset = self.queryset[:n] if n >= 1 else self.queryset
            fields = ["file","file_name", "last_updated", "expiration_time", "shared_with"]
            serializer = self.get_serializer(
                self.queryset, many=True, context={"fields": fields}
            )
            return Response(serializer.data)
        except (SharedFiles.DoesNotExist, exceptions.ValidationError, ValueError):
            return Response(
                {"error": "invalid request"}, status=status.HTTP_400_BAD_REQUEST
            )

    def handle_all_by_file(self, request, user, file, n):
        # user_org = user.org
        try:
            cache_key = f"log_all_{file}"

            # Check if the data is already in the cache
            cached_data = cache.get(cache_key)
            if cached_data:
                return Response(cached_data)

            self.queryset = AccessLog.objects.filter(file=file)
            self.lookup_field = "file"
            self.queryset = self.queryset[:n] if n >= 1 else self.queryset

            response = self.list(request)
            cache.set(cache_key,response.data,timeout=3600*24)
            
            return response

        except (AccessLog.DoesNotExist, exceptions.ValidationError, ValueError):
            return Response(
                {"error": "invalid request"}, status=status.HTTP_400_BAD_REQUEST
            )

    def handle_all(self, request, user, n, all_logs):
        try:
            if all_logs == 0:
                self.queryset = AccessLog.objects.filter(user=user.id).order_by(
                    "-timestamp"
                )
            else:
                self.queryset = AccessLog.objects.filter(org=user.org).order_by(
                    "-timestamp"
                )
            self.lookup_field = "file"
            self.queryset = self.queryset[:n] if n >= 1 else self.queryset
            return self.list(request)
        except (AccessLog.DoesNotExist, exceptions.ValidationError, ValueError):
            return Response(
                {"error": "invalid request"}, status=status.HTTP_400_BAD_REQUEST
            )


# class SetDepartment(APIView):
#     def get(self,request):
#         for file_obj in Objects.objects.select_related("owner").all().exclude(name=".emptyFolderPlaceholder"):
#             temp = file_obj.metadata
#             temp.update({"department":file_obj.owner.dept.name})
#             file_obj.name = "test"
#             file_obj.save()
#             print(file_obj.id)
#             break
#         return Response("DONE!!")

class GeoLocationView(
    mixins.CreateModelMixin,
    mixins.ListModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    GenericViewSet,
):
    permission_classes = [OrgadminRequired]
    authentication_classes = [SupabaseAuthBackend]
    serializer_class = AllowedLocationSerializer
    queryset = AllowedLocations.objects.all()
    lookup_field = "id"

    def dispatch(self, request, *args, **kwargs):
        response = super().dispatch(request, *args, **kwargs)
        print("Queries :", connection.queries)
        print("Queries count :", len(connection.queries))
        return response

    def perform_create(self, serializer):
        try:
            current_user = self.request.user
            organization = current_user.org
            # Set the organization ID in the serializer before creating the entry.
            serializer.save(org=organization)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return super().perform_create(serializer)

    def create_location(self, request):
        print(request.data)
        return self.create(request)

    def get_locations(self, request):
        user_org = request.user.org
        self.queryset = AllowedLocations.objects.filter(org=user_org)
        return self.list(request)

    def update_location(self, request, **kwargs):
        user_org = request.user.org
        self.queryset = AllowedLocations.objects.filter(org=user_org)
        return self.update(request, **kwargs)

    def delete_location(self, request, **kwargs):
        user_org = request.user.org
        self.queryset = AllowedLocations.objects.filter(org=user_org)
        return self.destroy(request, **kwargs)

    def get_permissions(self):
        if self.action == "get_locations":
            self.permission_classes = [OthersPerm]
        return super().get_permissions()

