
import os
from pathlib import Path
from decouple import config 


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# only for windows
GDAL_LIBRARY_PATH = str(Path('D:/Nishanth/TwoKey/code/venv/Lib/site-packages/osgeo/gdal.dll'))
os.environ['GDAL_LIBRARY_PATH'] = GDAL_LIBRARY_PATH

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-*mk17tssjq67b+&mc-b7go@2(m=!yi0deb2@!r90fek-%q3wgq'

#ENVIRONMENT VARIABLES:
ALLOWED_HOSTS = []
ALLOWED_HOSTS.append(os.environ.get("ALLOWED_HOSTS"))
SUPA_CLI_URL= os.environ.get("SUPA_URL")
SUPA_SERVICE_ROLE_KEY= os.environ.get("SERVICE_ROLE_KEY")
SUPA_USER= os.environ.get("SUPA_USER")
SUPA_PASS= os.environ.get("SUPA_PASS")
SUPA_HOST= os.environ.get("SUPA_HOST")
SUPA_PORT= os.environ.get("SUPA_PORT")
supabase_secret = os.environ.get('JWT_SECRET')
BREVO_KEY = os.environ.get('BREVO_KEY')
DEPLOY_URL = os.environ.get('DEPLOY_URL')
DEBUG = True

APPEND_SLASH = False
# Application definition

INSTALLED_APPS = [
    'django.contrib.gis',
    'rest_framework',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'logic',
    'fileoperations',
    'authenticate',
    'corsheaders',
    'drf_spectacular',
    'rest_framework_gis',
    'rest_framework_simplejwt',
    ]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'backend.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

AUTHENTICATION_BACKENDS = [
    'backend.supabase_auth.SupabaseAuthBackend',
    'django.contrib.auth.backends.ModelBackend'
]


# HIDE_THIS
DATABASES = {
    'default': {
        #'ENGINE': 'django.db.backends.sqlite3',
        # 'ENGINE': 'django.db.backends.postgresql',
        "ENGINE":'django.contrib.gis.db.backends.postgis',
        'NAME': 'postgres',
        'USER': SUPA_USER,
        'PASSWORD': SUPA_PASS,
        'HOST': SUPA_HOST,
        'PORT': SUPA_PORT,
        'OPTIONS' : {
        'options': '-c search_path=auth'
},

    }
}

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': BASE_DIR / 'db.sqlite3',
#     }
# }


# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = '/static/'

STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'



# Custom Added Values
# Swagger UI
REST_FRAMEWORK = {
    # YOUR SETTINGS
     'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}
SPECTACULAR_SETTINGS = {
    'TITLE': 'TwoKey API',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    # OTHER SETTINGS
}


# CORS_ALLOWED_ORIGINS = [
#     "https://example.com",
#     "https://sub.example.com",
#     "http://localhost:8080",
#     "http://127.0.0.1:9000",
# ]
CORS_ALLOW_ALL_ORIGINS = True
# SILKY_PYTHON_PROFILER = True
# SILKY_PYTHON_PROFILER_BINARY = True


# REDIS_USER = config("REDIS_USER")
# REDIS_PASS = config("REDIS_PASS")
# CACHES = {
#     "default": {
#         "BACKEND": "django_redis.cache.RedisCache",
#         "LOCATION": f"redis://{REDIS_USER}:{REDIS_PASS}@redis-10763.c323.us-east-1-2.ec2.cloud.redislabs.com:10763",
#         "OPTIONS": {
#             "CLIENT_CLASS": "django_redis.client.DefaultClient",
#         }
#     }
# }