import firebase_admin
from firebase_admin import credentials, auth, firestore

cred = credentials.Certificate("keys/firebase.json")

firebase_admin.initialize_app(cred, {
    'storageBucket': 'twokey-a14ec.appspot.com'
})

db = firestore.client()
