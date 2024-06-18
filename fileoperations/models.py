from django.db import models
from authenticate.models import Users
from logic.models import UserInfo , Organizations, Departments
from django.utils import timezone
from uuid import uuid4
import django.contrib.gis.db.models as location_model

# Non Managed

class Buckets(models.Model):
    id = models.TextField(primary_key=True)
    name = models.TextField(unique=True)
    owner = models.UUIDField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)
    public = models.BooleanField(blank=True, null=True)
    avif_autodetection = models.BooleanField(blank=True, null=True)
    file_size_limit = models.BigIntegerField(blank=True, null=True)
    allowed_mime_types = models.TextField(blank=True, null=True)  # This field type is a guess.

    class Meta:
        managed = False
        db_table = 'storage"."buckets'



class Objects(models.Model):
    id = models.UUIDField(primary_key=True)
    bucket = models.ForeignKey(Buckets, models.DO_NOTHING, blank=True, null=True)
    name = models.TextField(blank=True, null=True)
    owner = models.ForeignKey(UserInfo,on_delete=models.SET_NULL,blank=True, null=True,db_column='owner')
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)
    last_accessed_at = models.DateTimeField(blank=True, null=True)
    metadata = models.JSONField(blank=True, null=True)
    path_tokens = models.TextField(blank=True, null=True)  # This field type is a guess.
    version = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'storage"."objects'
        unique_together = (('bucket', 'name'),)

class Folder(models.Model):
    id = models.CharField(primary_key=True)
    name = models.CharField(max_length=20)
    owner = models.CharField(null=False)
    org = models.CharField(null=False)
    dept = models.CharField(null=False)
    metadata = models.JSONField(blank=True, null=True)
    
    class Meta:
        db_table = "folder"
class File_Info(models.Model):
    id = models.UUIDField(primary_key=True,default=uuid4)
    file = models.ForeignKey(Objects,on_delete=models.CASCADE,related_name="file_info")
    org = models.ForeignKey(Organizations,on_delete=models.DO_NOTHING)
    depts = models.ManyToManyField(Departments)
    folder = models.ForeignKey('Folder', on_delete=models.SET_NULL, related_name='files', null=True, blank=True)


    class Meta:
        db_table = "file_info"



# managed

class SharedFiles(models.Model):
    id = models.UUIDField(primary_key=True,default=uuid4)
    file = models.ForeignKey(Objects, on_delete=models.CASCADE)
    # file_owner = models.ForeignKey(UserInfo, on_delete=models.CASCADE)
    shared_with = models.ManyToManyField(UserInfo, related_name='shared_files')
    expiration_time = models.BigIntegerField()
    last_modified_at = models.DateTimeField(default=timezone.now)
    signed_url = models.URLField(default="")
    # download_allowed = models.BooleanField(default=False)
    state = models.CharField(default="active")

    class Meta:
        managed = True
        db_table = 'shared_files'

class AllowedLocations(models.Model):
    id = models.UUIDField(primary_key=True,default=uuid4)
    org = models.ForeignKey(Organizations,on_delete=models.CASCADE)
    name = models.CharField(max_length=50)
    location_point = location_model.PointField()
    address_info = models.JSONField(default=dict)
    class Meta:
        db_table = 'allowed_locations'
class SecCheck(models.Model):
    id = models.UUIDField(primary_key=True,default=uuid4)
    shared = models.ForeignKey(SharedFiles,on_delete=models.CASCADE,null=True,related_name='security_check')
    download_enabled = models.BooleanField(default=False)
    geo_enabled = models.ForeignKey(AllowedLocations,on_delete=models.SET_NULL,null=True,default=None)
    unique_identifiers = models.BooleanField(default=False)

    class Meta:
        db_table = 'security_checks'



class AccessLog(models.Model):
    id = models.UUIDField(primary_key=True,default=uuid4)
    user = models.UUIDField()
    username = models.CharField(max_length=100,default="")
    user_email = models.EmailField(default="")
    profile_pic = models.CharField(default="https://cderhtrlfxroiyqqzytr.supabase.co/storage/v1/object/public/avatar/profilePicDummy.jpg")
    file = models.UUIDField()
    file_name = models.CharField(max_length=500,default="")
    event = models.CharField(default="")
    org = models.ForeignKey(Organizations,on_delete=models.CASCADE,default=None,null=True)
    timestamp = models.DateTimeField(default=timezone.now)
    
    class Meta:
        db_table = 'access_log'

