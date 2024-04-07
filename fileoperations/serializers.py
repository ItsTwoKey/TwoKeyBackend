from django.utils import timezone
from django.shortcuts import get_object_or_404
from rest_framework.fields import empty
from rest_framework.serializers import ModelSerializer
from rest_framework import serializers
from django.core.exceptions import ObjectDoesNotExist,ValidationError
from .utils.supa import supabase , create_signed
from logic.models import UserInfo
from decouple import config
from rest_framework_gis.serializers import GeoFeatureModelSerializer
from .models import AccessLog, AllowedLocations, Objects, SecCheck, SharedFiles, File_Info, Folder
from logic.serializers import DepartmentSerializer





class AddDepartmentsSerializer(serializers.Serializer):
    department_ids = serializers.ListField(child=serializers.UUIDField())
    class Meta:
        model = File_Info
        fields = ['department_ids']




class FileMetaSerializer(ModelSerializer):
    depts = DepartmentSerializer(many=True)

    class Meta:
        model = File_Info
        fields = ['depts']

class FileSerializer(ModelSerializer):
    metadata =serializers.JSONField
    profile_pic = serializers.SerializerMethodField()
    file_info = FileMetaSerializer(many=True, read_only=True)
        
    class Meta:
        model = Objects
        fields = ['id','name','metadata','file_info',"profile_pic"]
    def to_representation(self, instance):
        data = super().to_representation(instance)
        # print(instance.owner.email)
        data['owner_email'] = instance.owner.email
        data['metadata'].pop('eTag')
        data['metadata'].pop('cacheControl')
        data['metadata'].pop('contentLength')
        data['metadata'].pop('httpStatusCode')
        
        return data
    
    def get_profile_pic(self,instance):
        return instance.owner.profile_pic


class FolderSerializer(ModelSerializer):
    class Meta:
        model = Folder
        fields = "__all__"

class FolderInteractSerializer(serializers.Serializer):
    file_id = serializers.UUIDField()
    folder_id = serializers.UUIDField()

    class Meta:
        fields = ['file_id','folder_id']



class SecCheckSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecCheck
        fields = ['download_enabled','geo_enabled','unique_identifiers']



class SharedFileSerializer(serializers.ModelSerializer):
    BUCKET_NAME = config('BUCKET_NAME')

    shared_with = serializers.ListField(child=serializers.UUIDField(), write_only=True)
    file_name = serializers.CharField(source='file.name', read_only=True)
    owner = serializers.SerializerMethodField()
    last_updated = serializers.SerializerMethodField()
    security_check = SecCheckSerializer()

    class Meta:
        model = SharedFiles
        fields = ["file", "owner", "file_name", 'last_updated', 'shared_with', 'expiration_time', "security_check"]


    def create(self, validated_data):
        security_check = validated_data.pop('security_check')
        file_name = validated_data['file'].name
        expiration_time = validated_data['expiration_time']
        # Setting the state of the share to active or due 
        state = "active" if (int(expiration_time)>259200) else "due"
        validated_data["state"] = state
        signed_url = supabase.storage.from_(self.BUCKET_NAME).create_signed_url(file_name, expiration_time)['signedURL']
        validated_data['signed_url'] = signed_url

        created = super().create(validated_data)
        SecCheck(shared=created, **security_check).save()
        return created
    
    def update(self, instance, validated_data):
        file_name = instance.file.name
        if('expiration_time' in validated_data.keys()):
            expiration_time = validated_data['expiration_time']
            new_presigned_url = create_signed(file_name,expiration_time)
            validated_data['signed_url'] = new_presigned_url
            validated_data['last_modified_at'] = timezone.now()

            # Modify THis Later
        if('security_check' in validated_data.keys()):
            validated_data.pop("security_check")
        return super().update(instance, validated_data)

    def get_last_updated(self, obj):
        return obj.file.updated_at

    def get_owner(self, obj):
        return obj.file.owner.name +" "+ obj.file.owner.last_name

    # def get_user_ids(self, emails):
    #     return list(UserInfo.objects.filter(email__in=[email.lower() for email in emails]).values_list('id', flat=True))

    def get_user_representation(self, user):
        return {
            "user_id": str(user.id),
            "user_email": user.email,
            "profile_pic": user.profile_pic,
            "first_name": user.name,
            "last_name": user.last_name,
        }

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data.pop("security_check")
        print(data)

        serializer = SecCheckSerializer(SecCheck.objects.get(shared = instance))
        print(serializer.data)
        data["security_check"] = serializer.data

        users = instance.shared_with.all()
        data['shared_with'] = [self.get_user_representation(user) for user in users]

        # If Context Specified, output fields can be reduced.
        fields_to_include = self.context.get('fields')

        if fields_to_include:
            data = {key: value for key, value in data.items() if key in fields_to_include}
            data['shared_with'] = [self.get_user_representation(user) for user in users]

        return data
    
class SharedFilesRecepient(ModelSerializer):
    class Meta:
        model = SharedFiles
        fields = ['id','signed_url']





class AccessLogSerializer(serializers.ModelSerializer):

    profile_pic = serializers.CharField(required=False)

    class Meta:
        model = AccessLog
        exclude = ["timestamp", "id"]

    def get_file(self, instance):
        return instance.file_name  # Assuming file_name is a field in AccessLog
    
    def get_user(self, instance):
        return instance.user_email
    def get_username(self, instance):
        return instance.username

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['timestamp'] = instance.timestamp
        return data


   

class AllowedLocationSerializer(GeoFeatureModelSerializer):
    class Meta:
        model = AllowedLocations
        geo_field = 'location_point' 
        fields =['name','location_point','address_info']
    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['id'] = instance.id
        return data