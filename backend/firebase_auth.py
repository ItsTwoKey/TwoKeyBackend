import json
from typing import Any
from django.contrib.auth.backends import BaseBackend
from django.http import HttpRequest
from firebase_admin import auth, firestore
from django.core.cache import cache
from .firebase_admin_init import db

from logic.models import UserInfo

class FirebaseAuthBackend(BaseBackend):
    def authenticate(self, request: HttpRequest, **kwargs: Any) -> Any:
        cache_key = None
        if request.method != 'POST':
            id_token = request.headers.get('Authorization')
            cache_key = f"authenticated_user:{id_token}"
        else:
            data = json.loads(request.body)
            id_token = data.get('idToken') 
            cache_key = f"authenticated_user:{id_token}"

        # Check if user is in cache
        cached_user = cache.get(cache_key)
        if cached_user:
            return cached_user, None

        if not id_token:
            return None  # No access token provided

        try:
            decoded_token = auth.verify_id_token(id_token=id_token)

            # Get the UID from the decoded token
            uid = decoded_token.get('uid')

            # Fetch user information from Firestore
            user_ref = db.collection('users').document(uid)
            user_data = user_ref.get().to_dict()

            if not user_data:
                return None

            # Create a Django user instance or fetch from the database if it exists
            user = UserInfo(**user_data)
            user.is_authenticated = True

            # Cache the user for future requests
            cache.set(cache_key, user, timeout=3600)

            return user, None

        except auth.InvalidIdTokenError:
            return None
        except auth.ExpiredIdTokenError:
            return None

    def get_user(self, user_id: str) -> Any:
        try:
            # Fetch user information from Firestore
            db = firestore.client()
            user_ref = db.collection('users').document(user_id)
            user_data = user_ref.get().to_dict()

            if not user_data:
                return None

            # Create a Django user instance
            user = UserInfo(id=user_id, **user_data)
            user.is_authenticated = True
            return user
        except Exception as e:
            return None
