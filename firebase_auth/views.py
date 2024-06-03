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
                'organization': organization,
                'fullName': full_name,
                'email': email
            })

            return JsonResponse({'message': f'Verification email sent to {email}, proceed to login'})

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def login(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')

        try:
            user = auth.get_user_by_email(email)
            
            # Check if the user's email is verified
            if not user.email_verified:
                return JsonResponse({'error': 'Email not verified'}, status=401)

            # Sign in the user with email and password
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)