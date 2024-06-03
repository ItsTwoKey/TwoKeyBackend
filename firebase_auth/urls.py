# urls.py
from django.urls import path
from .views import sign_up, login, find_user, logout

urlpatterns = [
    path('sign-up/', sign_up, name='sign_up'),
    path('login/', login, name='login'),
    path('getProfileInfo/', find_user, name='find_user'),
    path('logout/', logout, name='logout'),
]
