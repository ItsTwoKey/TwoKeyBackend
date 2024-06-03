# views.py
import base64
import uuid
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from firebase_admin import auth, storage
from django.views.decorators.csrf import csrf_exempt
from backend.firebase_admin_init import db

@csrf_exempt
@api_view(['PUT'])
def update_profile(request):
    data = request.data
    id_token = data.get('idToken')
    update_data = data.get('profileData')
    profile_picture = data.get('profilePicture')

    if not id_token or not update_data:
        return Response({'error': 'Missing idToken or profileData'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Verify the ID token
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['user_id']

        # Upload the profile picture to Firebase Storage if provided
        if profile_picture:
            try:
                # Decode the base64 image
                image_data = base64.b64decode(profile_picture)
                # Create a unique filename
                filename = f"{uid}_{uuid.uuid4()}.jpg"
                # Upload the image to Firebase Storage
                bucket = storage.bucket()
                blob = bucket.blob(f"profile_pictures/{filename}")
                blob.upload_from_string(image_data, content_type='image/jpeg')
                # Get the public URL of the uploaded image
                image_url = blob.public_url
                update_data['profilePictureUrl'] = image_url
            except Exception as e:
                return Response({'error': f"Failed to upload profile picture: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Fetch user information from Firestore
        user_ref = db.collection('users').document(uid)
        user_ref.update(update_data)  # Update with the provided profile data

        return Response({"message": "Profile updated successfully"}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
