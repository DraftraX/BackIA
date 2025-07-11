# encriptador/views.py
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny  # O usa IsAuthenticated si lo deseas
from rest_framework.response import Response
from rest_framework import status
from .utils import encrypt_url, decrypt_url

@api_view(['GET'])
@permission_classes([AllowAny])  # Puedes cambiar a IsAuthenticated para mayor seguridad
def encriptar_view(request):
    data = request.GET.get("data", "")
    if not data:
        return Response({"error": "Falta el parámetro 'data'"}, status=status.HTTP_400_BAD_REQUEST)

    encrypted = encrypt_url(data)
    return Response({"original": data, "encriptado": encrypted})


@api_view(['GET'])
@permission_classes([AllowAny])
def desencriptar_view(request):
    token = request.GET.get("token", "")
    if not token:
        return Response({"error": "Falta el parámetro 'token'"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        original = decrypt_url(token)
        return Response({"encriptado": token, "original": original})
    except Exception:
        return Response({"error": "Token inválido o modificado"}, status=status.HTTP_400_BAD_REQUEST)
