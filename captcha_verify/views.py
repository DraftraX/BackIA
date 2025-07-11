from django.shortcuts import render

# Create your views here.
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
import requests
from django.conf import settings

@api_view(['POST'])
def verify_captcha_view(request):
    token = request.data.get('captcha_token')
    if not token:
        return Response({'error': 'Token faltante'}, status=status.HTTP_400_BAD_REQUEST)

    response = requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        data={
            'secret': settings.RECAPTCHA_SECRET_KEY,
            'response': token
        }
    )
    result = response.json()

    if result.get('success'):
        return Response({'detail': 'Captcha válido'}, status=200)
    else:
        return Response({'error': 'Captcha inválido'}, status=403)