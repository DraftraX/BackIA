from rest_framework_simplejwt.tokens import RefreshToken

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    refresh['session_token'] = user.session_token  # ⬅ Incluir aquí

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
