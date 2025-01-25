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

from .serializers import UserSerializer, UserRegisterSerializer, UserLoginSerializer, UserLoginOTPSerializer

from django.core.mail import send_mail
from django.utils.crypto import get_random_string

otp_storage = {}

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

        if not username or not password:
            raise ValidationError({"message": "Username and password are required."})

        # Authenticate the user
        user = authenticate(username=username, password=password)
        if user is None:
            raise ValidationError({"message": "Invalid credentials"})

        # Generate opt
        otp = get_random_string(length=6, allowed_chars='1234567890')
        otp_storage[username] = otp

        # Send OTP to user's email
        send_mail(
            subject="Your OTP for Login",
            message=f"Your OTP is {otp}. It is valid for 5 minutes.",
            from_email="shakil.eub.cse@gmail.com",
            recipient_list=[user.email],
        )

        return Response({
            "message": "OTP sent to your registered email address."
            },
            status=status.HTTP_200_OK
        )


class VerifyOtpView(generics.GenericAPIView):
    serializer_class = UserLoginOTPSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Extract validated data
        username = serializer.validated_data.get('username')
        otp = serializer.validated_data.get('otp')

        # Check if OTP exists for the username and validate it
        if username not in otp_storage:
            raise ValidationError({"message": "OTP has not been sent or expired or username not valid."})
        
        # Validate OTP
        if otp_storage[username] != otp:
            raise ValidationError({"message": "Invalid OTP."})

        # Clean up OTP after verification
        del otp_storage[username]

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise ValidationError({"message": "User does not exist."})

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        user_serializer = UserSerializer(user)


        return Response(
            {
                'access': access_token,
                'refresh': str(refresh),
                'user': user_serializer.data,
            },
            status=status.HTTP_200_OK
        )
        
class DashboardView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        user_serializer = UserSerializer(user)
        return Response({
            'message': 'Welcome to the Dashboard',
            'user': user_serializer.data
        },status=status.HTTP_200_OK)
    