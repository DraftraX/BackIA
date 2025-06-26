# seguridad/urls.py
from django.urls import path
from .views import greynoise_lookup

urlpatterns = [
    path("greynoise/<str:ip>/", greynoise_lookup, name="greynoise_lookup"),
]
