from django.urls import path

from . import views

urlpatterns = [path("vuln/", views.vulnerable)]
