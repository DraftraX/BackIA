# custom_auth/views.py
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
import uuid

from .models import CustomUser, VerificationCode
from .serializers import CustomTokenObtainPairSerializer, RegisterSerializer, UserSerializer
from rest_framework_simplejwt.views import TokenObtainPairView

#Encripter
from encriptador.utils import encrypt_url
from django.shortcuts import get_object_or_404

@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        refresh = RefreshToken.for_user(user)

        # ❌ No generamos session_token aquí
        return Response({
            'user': UserSerializer(user).data,
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(request, username=username, password=password)

    if user:
        
        if user.session_token:
            return Response(
                {'error': 'Ya tienes una sesión activa. Cierra sesión en el otro dispositivo antes de volver a iniciar.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        refresh = RefreshToken.for_user(user)
        session_token = str(uuid.uuid4())
        user.session_token = session_token
        user.last_login = timezone.now()
        user.save()

        encrypted_user_id = encrypt_url(str(user.id))

        return Response({
            'user': {
                **UserSerializer(user).data,
                'id_encriptado': encrypted_user_id
            },
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'session_token': session_token
        }, status=status.HTTP_200_OK)

    return Response({'error': 'Credenciales inválidas'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def detalle_usuario_view(request, encrypted_id):
    try:
        user_id = decrypt_url(encrypted_id)
        user = get_object_or_404(CustomUser, id=user_id)
        return Response(UserSerializer(user).data, status=200)
    except Exception:
        return Response({'error': 'ID inválido o modificado'}, status=400)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    user = request.user
    user.last_logout = timezone.now()
    user.update_session_time()
    user.session_token = None
    user.save()
    return Response({'detail': 'Sesión cerrada correctamente.'}, status=200)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def profile_view(request):
    return Response(UserSerializer(request.user).data, status=200)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def validate_session(request):
    client_token = request.headers.get('X-Session-Token')
    user = request.user
    if not client_token or user.session_token != client_token:
        return Response({'detail': 'Sesión inválida o iniciada en otro dispositivo.'}, status=403)
    return Response({'detail': 'Sesión válida'}, status=200)


@api_view(['POST'])
@permission_classes([AllowAny])
def enviar_codigo_view(request):
    email = request.data.get('email')
    code = request.data.get('code')

    if not email or not code:
        return Response({'error': 'Email o código faltante'}, status=400)

    VerificationCode.objects.create(email=email, code=code)

    try:
        send_mail(
            subject='Código de verificación',
            message=f'Tu código de verificación es: {code}',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        return Response({'message': 'Código enviado correctamente al correo'}, status=200)
    except Exception as e:
        print(f"[Error envío]: {e}")
        return Response({'error': 'No se pudo enviar el correo'}, status=500)


@api_view(['POST'])
@permission_classes([AllowAny])
def verificar_codigo_view(request):
    email = request.data.get('email')
    code = request.data.get('code')

    if not email or not code:
        return Response({'error': 'Email y código son requeridos'}, status=400)

    try:
        registro = VerificationCode.objects.filter(email=email, code=code).order_by('-created_at').first()
        if not registro:
            return Response({'error': 'Código incorrecto'}, status=404)
        if registro.is_expired():
            return Response({'error': 'Código expirado'}, status=410)
        return Response({'message': 'Código válido'}, status=200)
    except Exception as e:
        print(f"[Verificación error]: {e}")
        return Response({'error': 'Error interno al verificar'}, status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def listar_usuarios_view(request):
    usuarios = CustomUser.objects.all().order_by('-last_login')
    serializer = UserSerializer(usuarios, many=True)
    return Response(serializer.data, status=200)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def validate_session(request):
    client_token = request.headers.get('X-Session-Token')
    if not client_token or request.user.session_token != client_token:
        return Response({'detail': 'Sesión inválida o iniciada en otro dispositivo.'}, status=403)

    return Response({'detail': 'Sesión válida'}, status=200)

class CustomLoginView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
