# encriptador/utils.py
from cryptography.fernet import Fernet
from django.conf import settings

fernet = Fernet(settings.FERNET_KEY)

def encrypt_url(data: str) -> str:
    return fernet.encrypt(data.encode()).decode()

def decrypt_url(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()
