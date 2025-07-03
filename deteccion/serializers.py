# serializers.py
from rest_framework import serializers
from .models import SnortAlert

class SnortAlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = SnortAlert
        fields = "__all__"
