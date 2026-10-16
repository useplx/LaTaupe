import os
import sys

os.environ.setdefault("DJANGO_SETTINGS_MODULE", __name__)
DEBUG = True
SECRET_KEY = "vulhub"
ALLOWED_HOSTS = ["*"]
MIDDLEWARE = ["django.middleware.common.CommonMiddleware"]
ROOT_URLCONF = "vuln.urls"
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "cve",
        "USER": "root",
        "PASSWORD": "mysql",
        "HOST": "database",
        "PORT": "3306",
    }
}
INSTALLED_APPS = ["vuln"]

from django.core.management import execute_from_command_line

execute_from_command_line(sys.argv)
