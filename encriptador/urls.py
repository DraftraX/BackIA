from django.urls import path
from .views import encriptar_view, desencriptar_view

urlpatterns = [
    path('encriptar/', encriptar_view, name='encriptar-url'),
    path('desencriptar/', desencriptar_view, name='desencriptar-url'),
]
