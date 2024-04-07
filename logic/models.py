from django.db import models

# Create your models here.
import uuid
from django.db import models

class Organizations(models.Model):
    id = models.UUIDField(primary_key=True,default=uuid.uuid4)
    name = models.CharField(blank=True, null=True,unique=True)

    class Meta:
        managed = True
        db_table = 'organizations'

class Departments(models.Model):
    id = models.UUIDField(primary_key=True,default=uuid.uuid4)
    name = models.CharField(blank=True, null=True)
    org = models.ForeignKey(Organizations,on_delete=models.CASCADE,default=None)
    metadata = models.JSONField(blank=True, null=True, default=dict)

    class Meta:
        managed = True
        db_table = 'departments'


class UserInfo(models.Model):
    # Personal Info
    id = models.UUIDField(primary_key=True)
    username = models.CharField(default='',null=True)
    name =models.CharField(default='')
    last_name = models.CharField(default='')
    email = models.EmailField(default=None)
    phone = models.BigIntegerField(default=None,null=True)
    profile_pic = models.URLField(default="https://cderhtrlfxroiyqqzytr.supabase.co/storage/v1/object/public/avatar/profilePicDummy.jpg",null=True)
    # Work Info
    org = models.ForeignKey(Organizations, on_delete=models.CASCADE,default=None)
    role_priv = models.CharField(max_length=20,default="employee")
    dept = models.ForeignKey(Departments, models.DO_NOTHING,default=None)
    manager = models.ForeignKey('self', on_delete=models.SET_NULL, blank=True, null=True)
    # Address Info
    country = models.CharField(max_length=30,default='',blank=True)
    state = models.CharField(max_length=30,default='',blank=True)
    city = models.CharField(max_length=30,default='',blank=True)
    postal_code = models.IntegerField(default='',null=True,blank=True)

    is_approved = models.BooleanField(default=False)
    is_authenticated = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)

    class Meta:
        managed = True
        db_table = 'user_info'


class Role(models.Model):
    id = models.UUIDField(primary_key=True,default=uuid.uuid4)
    role = models.CharField(max_length=20)

    class Meta:
        db_table = 'user_roles'
