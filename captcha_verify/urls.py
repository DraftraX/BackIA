from django.urls import path
from .views import verify_captcha_view

urlpatterns = [
    path('verify/', verify_captcha_view),
]
