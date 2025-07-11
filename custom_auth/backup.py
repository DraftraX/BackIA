# @api_view(['POST'])
# @permission_classes([AllowAny])
# def login_view(request):
#     username = request.data.get('username')
#     password = request.data.get('password')
#     user = authenticate(request, username=username, password=password)

#     if user:
#         refresh = RefreshToken.for_user(user)

#         session_token = str(uuid.uuid4())
#         user.session_token = session_token
#         user.last_login = timezone.now()
#         user.save()

#         return Response({
#             'user': UserSerializer(user).data,
#             'refresh': str(refresh),
#             'access': str(refresh.access_token),
#             'session_token': session_token
#         }, status=status.HTTP_200_OK)

#     return Response({'error': 'Credenciales inválidas'}, status=status.HTTP_401_UNAUTHORIZED)
