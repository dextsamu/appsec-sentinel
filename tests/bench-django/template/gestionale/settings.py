import os

SECRET_KEY = "__DJANGO_SECRET_KEY__"
DEBUG = os.environ.get("DEBUG", "1") == "1"
ALLOWED_HOSTS = ["*"]
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.contenttypes", "django.contrib.sessions", "rest_framework", "soci"]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]
ROOT_URLCONF = "gestionale.urls"
DATABASES = {"default": {"ENGINE": "django.db.backends.postgresql", "NAME": "soci", "USER": "soci", "PASSWORD": os.environ.get("DB_PASSWORD"), "HOST": "db"}}
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
