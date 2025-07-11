from django.contrib import admin
from django.urls import path, include
from custom_auth.views import CustomLoginView

from django.http import JsonResponse

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include("seguridad.urls")),
    path('api/deteccion/', include("deteccion.urls")),
    path('api/auth/', include('custom_auth.urls')),
    path('api/auth/login/', CustomLoginView.as_view(), name='login_view'),
    path('api/encriptador/', include('encriptador.urls')),
    path('api/captcha/', include('captcha_verify.urls')),

    # Ruta raíz (para evitar 404 en "/")
    path('', lambda request: JsonResponse({
        "status": "ok",
        "message": "Bienvenido al backend de NIDS"
    })),
]
