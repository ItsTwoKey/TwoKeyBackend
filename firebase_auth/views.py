# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
# from rest_framework_simplejwt.tokens import RefreshToken
from firebase_admin import auth, firestore
from backend.firebase_admin_init import db
import json

@csrf_exempt
def sign_up(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        organization = data.get('organization')
        full_name = data.get('fullName')
        email = data.get('email')
        uid=data.get('uid')

        print(data, organization, full_name, email, uid)
        
        if not organization or not full_name or not email or not uid:
            return JsonResponse({'error': 'Missing required fields'}, status=400)

        try:
            db.collection('users').document(uid).set({
                'org': organization,
                'name': full_name,
                'email': email,
                "role_priv": "employee",
                "username": "",
                "last_name": "",
                "dept": "",
                "profilePictureUrl": "",
            })

            return JsonResponse({'message': f'Verification email sent to {email}, proceed to login'})

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def login(request):
    if request.method == 'PUT':
        data = json.loads(request.body)
        email = data.get('email')
        is_active = data.get('is_active')
        metadata = data.get('metadata')

        try:
            user = auth.get_user_by_email(email)
            
            # Check if the user's email is verified
            if not user.email_verified:
                return JsonResponse({'error': 'Email not verified'}, status=401)
            else:
                try:
                    doc_ref = db.collection('users').document(user.uid)
                    doc_ref.update({'is_active': is_active, 'metadata': metadata, 'is_authenticated':True })  # Fix: Pass key-value pairs as a dictionary
                    doc = doc_ref.get()
                    user_dict = doc.to_dict()

                    user_dict = {
                    'uid': user.uid,
                    'email': user.email,
                    'username': user_dict['username'],
                    'email_verified': user.email_verified,
                    'phone_number': user.phone_number,
                    'photo_url': user.photo_url,
                    'disabled': user.disabled,
                    'name':user_dict['name'],
                    'last_name':user_dict['last_name'],
                    'dept':user_dict['dept'],
                    'profilePictureUrl':user_dict['profilePictureUrl'], 
                    'is_active': True,
                    'is_authenticated': True,
                    }

                    return JsonResponse({'user': user_dict, 'message': 'Logged In updated successfully'}, status=200)  # Fix: Wrap 'user' in a dictionary
                except Exception as e:
                    return JsonResponse({'error': str(e)}, status=500)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt
def find_user(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        id_token = data.get('idToken')

        if not id_token:
            return JsonResponse({'error': 'Missing ID token'}, status=400)

        try:
            # Verify the ID token
            decoded_token = auth.verify_id_token(id_token)
            uid = decoded_token['uid']

            # Fetch user information from Firestore
            user_ref = db.collection('users').document(uid)
            user_doc = user_ref.get()

            if not user_doc.exists:
                return JsonResponse({'error': 'User not found'}, status=404)

            user_data = user_doc.to_dict()

            return JsonResponse({'user': user_data}, status=200)

        except auth.InvalidIdTokenError:
            return JsonResponse({'error': 'Invalid ID token'}, status=401)
        except auth.ExpiredIdTokenError:
            return JsonResponse({'error': 'Expired ID token'}, status=401)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def logout(request):
    if request.method == 'PUT':
        data = json.loads(request.body)
        id_token = data.get('idToken')
        is_active = data.get('is_active')

        if not id_token:
            return JsonResponse({'error': 'Not authorised'}, status=400)
        
        try:
            # Verify the ID token
            decoded_token = auth.verify_id_token(id_token)
            uid = decoded_token['uid']  # Corrected the key name to 'uid'

            # Fetch user information from Firestore
            user_ref = db.collection('users').document(uid)
            user_ref.update({'is_active': is_active})  # Fix: Pass key-value pairs as a dictionary
            return JsonResponse({"message": "Logged out successfully"}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
        
    return JsonResponse({'error': 'Invalid request method'}, status=400)