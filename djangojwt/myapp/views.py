from django.shortcuts import render
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework import status,viewsets
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.exceptions import ValidationError,MethodNotAllowed
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import UserSerializer, UserRegisterSerializer, UserLoginSerializer

class UserRegisterViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserRegisterSerializer

    
    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="POST",detail="User creation is not allowed on this endpoint. Go to '/users/register/' endpoint")

    # Custom registration endpoint
    @action(methods=['post'], detail=False, url_path='register')
    def register(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            response = {
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                }
            }
            return Response(response, status=status.HTTP_201_CREATED)
        raise ValidationError(serializer.errors, code=status.HTTP_400_BAD_REQUEST)
     
class LoginView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer
    
    def post(self, request, *args, **kwargs):
        username = request.data.get("username")
        password = request.data.get("password")
        
        if not username and not password:
            raise ValidationError({"message": "Username and password are required."})
        
        user = authenticate(username=username, password=password)
        
        if user is None:
            raise ValidationError({"message": "Invalid credentials"})
        
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        user_serializer = UserLoginSerializer(user)
        
        return Response(
            {
                'access': access_token,
                'refresh': str(refresh),
                'user': user_serializer.data,
            },
            status=status.HTTP_200_OK
        )