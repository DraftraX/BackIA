from django.urls import path
from .views import (
    greynoise_lookup,
    EncryptDocumentView,
    VerifySignatureView,
    DecryptDocumentView,
    get_public_key,
)

urlpatterns = [
    path("greynoise/<str:ip>/", greynoise_lookup),
    path("encrypt-document/", EncryptDocumentView.as_view()),
    path("verify-document/", VerifySignatureView.as_view()),
    path("decrypt-document/", DecryptDocumentView.as_view()),
    path("public-key/", get_public_key), 
]
