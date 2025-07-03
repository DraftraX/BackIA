from django.urls import path
from .views import IniciarSnortAPIView, SnortLogAPIView

urlpatterns = [
    path("iniciar-snort/", IniciarSnortAPIView.as_view(), name="iniciar-snort"),
    path("logs-snort/", SnortLogAPIView.as_view(), name="logs-snort"),
]
