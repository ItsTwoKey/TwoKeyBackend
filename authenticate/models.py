from django.db import models
from logic.models import *
from django.utils import timezone
from uuid import uuid4


class Users(models.Model):
    id = models.UUIDField(primary_key=True,default=uuid4)
    instance_id = models.UUIDField(blank=True, null=True,default='00000000-0000-0000-0000-000000000000')
    aud = models.CharField(max_length=255, blank=True, null=True,default='authenticated')
    role = models.CharField(max_length=255, blank=True, null=True,default='authenticated')
    email = models.CharField(unique=True, max_length=255, blank=True, null=True)
    encrypted_password = models.CharField(max_length=255, blank=True, null=True)
    email_confirmed_at = models.DateTimeField(blank=True, null=True)
    invited_at = models.DateTimeField(blank=True, null=True)
    confirmation_token = models.CharField(unique=True, max_length=255, blank=True, null=True)
    confirmation_sent_at = models.DateTimeField(blank=True, null=True,default=timezone.now)
    recovery_token = models.CharField(unique=True, max_length=255, blank=True,default='')
    recovery_sent_at = models.DateTimeField(blank=True, null=True)
    email_change_token_new = models.CharField(unique=True, max_length=255, blank=True, null=True,default='')
    email_change = models.CharField(max_length=255, blank=True, null=True,default='')
    email_change_sent_at = models.DateTimeField(blank=True, null=True)
    last_sign_in_at = models.DateTimeField(blank=True, null=True)
    raw_app_meta_data = models.JSONField(blank=True, null=True)
    raw_user_meta_data = models.JSONField(blank=True, null=True)
    is_super_admin = models.BooleanField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True,default=timezone.now)
    updated_at = models.DateTimeField(blank=True, null=True,default=timezone.now)
    phone = models.TextField(unique=True, blank=True, null=True)
    phone_confirmed_at = models.DateTimeField(blank=True, null=True)
    phone_change = models.TextField(blank=True, null=True,default="")
    phone_change_token = models.CharField(max_length=255, blank=True, null=True,default='')
    phone_change_sent_at = models.DateTimeField(blank=True, null=True)
    # confirmed_at = models.DateTimeField(blank=True, null=True)
    email_change_token_current = models.CharField(unique=True, max_length=255, blank=True, null=True,default='')
    email_change_confirm_status = models.SmallIntegerField(blank=True, null=True,default=0)
    banned_until = models.DateTimeField(blank=True, null=True)
    reauthentication_token = models.CharField(unique=True, max_length=255, blank=True, null=True,default='')
    reauthentication_sent_at = models.DateTimeField(blank=True, null=True)
    is_sso_user = models.BooleanField(db_comment='Auth: Set this column to true when the account comes from SSO. These accounts can have duplicate emails.',default=False)
    deleted_at = models.DateTimeField(blank=True, null=True)
    # org = models.ForeignKey(Organizations,on_delete=models.CASCADE,default=None,null=True)
    # is_approved = models.BooleanField(default=False)
    # is_authenticated = models.BooleanField(default=False)
    class Meta:
        managed = True
        db_table = 'auth\".\"users'
        
        db_table_comment = 'Auth: Stores user login data within a secure schema.'

class Identity(models.Model):
    provider_id = models.TextField(null=False)
    user = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='identities')
    identity_data = models.JSONField(null=False)
    provider = models.TextField(null=False)
    last_sign_in_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)
    email = models.EmailField(null=True)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    class Meta:
        managed = True
        db_table = 'auth\".\"identities'
        constraints = [
            models.UniqueConstraint(fields=['provider_id', 'provider'], name='identities_provider_id_provider_unique'),
        ]
    
