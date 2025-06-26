# views.py
import requests
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

@api_view(["GET"])
def greynoise_lookup(request, ip):
    try:
        headers = {"key": "YOUR_GREYNOISE_API_KEY"}
        response = requests.get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)

        if response.status_code == 404:
            return Response({"error": "Not Found"}, status=404)

        if response.status_code == 429:
            return Response({"error": "Too Many Requests"}, status=429)

        response.raise_for_status()
        return Response(response.json())
    except requests.exceptions.RequestException as e:
        return Response({"error": str(e)}, status=500)
