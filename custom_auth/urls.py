# custom_auth/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_view),
    path('login/', views.login_view),
    path('logout/', views.logout_view),
    path('profile/', views.profile_view),
    path('validate-session/', views.validate_session),
    path('enviar-codigo/', views.enviar_codigo_view),
    path('verificar-codigo/', views.verificar_codigo_view),
    path('usuarios/', views.listar_usuarios_view),
    path('detalle-usuario/<str:encrypted_id>/', views.detalle_usuario_view),
]
