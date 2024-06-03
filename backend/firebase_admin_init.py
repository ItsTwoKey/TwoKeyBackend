import firebase_admin
from firebase_admin import credentials, auth, firestore

cred = credentials.Certificate("keys/firebase.json")
firebase_admin.initialize_app(cred)

db = firestore.client()
