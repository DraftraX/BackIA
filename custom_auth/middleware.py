# custom_auth/middleware.py
from django.utils.timezone import now

class LastActivityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            request.user.last_activity = now()
            request.user.save(update_fields=["last_activity"])
        return self.get_response(request)
