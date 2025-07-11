from django.contrib import admin
from django.urls import path, include
from custom_auth.views import CustomLoginView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include("seguridad.urls")),
    path('api/deteccion/', include("deteccion.urls")),
    path('api/auth/', include('custom_auth.urls')),
    path('api/auth/login/', CustomLoginView.as_view(), name='login_view'),
    path('api/encriptador/', include('encriptador.urls')),
]
