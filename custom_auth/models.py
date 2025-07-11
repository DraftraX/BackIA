# custom_auth/models.py
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from datetime import timedelta
from django.utils.timezone import now

from django.db import models
from django.contrib.auth.models import AbstractUser
from datetime import timedelta

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    session_token = models.CharField(max_length=255, blank=True, null=True)
    last_logout = models.DateTimeField(blank=True, null=True)
    total_session_time = models.DurationField(default=timedelta())
    last_activity = models.DateTimeField(blank=True, null=True)

    # ✅ NUEVOS CAMPOS para controlar múltiples sesiones
    nueva_solicitud = models.BooleanField(default=False)   # intento nuevo pendiente
    permitir_nueva = models.BooleanField(default=False)    # esta sesión aprobó la nueva

    def __str__(self):
        return self.username

    def update_session_time(self):
        if self.last_login and self.last_logout:
            duration = self.last_logout - self.last_login
            self.total_session_time += duration
            self.save()

    def reset_solicitud(self):
        self.nueva_solicitud = False
        self.permitir_nueva = False
        self.save(update_fields=["nueva_solicitud", "permitir_nueva"])

class VerificationCode(models.Model):
    email = models.EmailField()
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + timedelta(minutes=10)