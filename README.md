# Django-JWT-API-Token-Authentication

## Context
- [Project Setup](#project-setup)
- [Configure JWT Token](#configure-jwt-token)
- [Create Serializer Class](#create-serializer-class)
- [Create View Methodology](#create-view-methodology)

### Project Setup
1. At first Create Environment:
    ```cmd
    python-m venv env
    ```
2. After Create envirionment activate the environment:
    ```cmd
    .\env\Scripts\activate
    ```
3. Install Dependencies:
    ```cmd
    pip install -r requirements.txt
    ```
4. Create a Djnago Project:
    ```cmd
    django-admin startproject djangojwt
    ```
5. Change current directory to `djangojwt` folder:
    ```cmd
    cd djangojwt
    ```
6. Create a Django App:
    ```cmd
    django-admin startapp myapp
    ```
7. Update `settings.py` to Add `rest_framework` and `app_name` to `INSTALLED_APPS`:
    ```python
    INSTALLED_APPS = [
    ......
    ......
    'rest_framework',
    'myapp',
    ]
    ```
⬆️ [Go to Context](#context)

## Configure JWT Token
- Install Required Libraries
    ```cmd
    pip install djangorestframework-simplejwt
    ```
- Update `settings.py` to Add `rest_framework_simplejwt` inside the `INSTALLED_APPS`:
  ```python
    INSTALLED_APPS = [
    ......
    ......
    'rest_framework',
    'rest_framework_simplejwt',
    ]
    ```

- Then, your django project must be configured to use the library. In `settings.py`, add `rest_framework_simplejwt.authentication.JWTAuthentication` to the list of authentication classes:
    ```python
    REST_FRAMEWORK = {
        'DEFAULT_AUTHENTICATION_CLASSES': (
            'rest_framework_simplejwt.authentication.JWTAuthentication',
        )
    }
    ```

⬆️ [Go to Context](#context)
### Final Setup
- After Implement the Model Migrate the database:
    ```cmd
    py manage.py makemigrations
    py manage.py migrate
    ```
- Create superuser
    ```cmd
    py manage.py createsuperuser
    ```
- Run the project
    ```cmd
    py manage.py runserver
    ```
⬆️ [Go to Context](#context)

## Create Serializer Class:
### UserSerializer
To configure the serializer create `serializers.py` file inside the `app`:
- First create `UserSerializer` to get or store the user data:
    ```python
    from rest_framework import serializers
    from django.contrib.auth.models import User

    class UserSerializer(serializers.ModelSerializer):
        class Meta:
            model = User
            fields = ['id','username','email','date_joined']
    ```
### UserRegisterSerializer:
- Create `UserRegisterSerializer` class for register the user information:
    ```python
    class UserRegisterSerializer(serializers.ModelSerializer):
        id = serializers.PrimaryKeyRelatedField(read_only=True)
        username = serializers.CharField()
        first_name = serializers.CharField()
        last_name = serializers.CharField()
        email = serializers.EmailField()
        password = serializers.CharField(write_only=True)
        confirm_password = serializers.CharField(write_only=True)
        
        class Meta:
            model = User
            fields = ['id','username','first_name','last_name','email','password','confirm_password']
            
    ```
- To validate the username create a function inside the `UserRegisterSerializer` class. This function check this user already exists or not.
    ```python
    from rest_framework.exceptions import ValidationError
    def validate_username(self, username):
        if User.objects.filter(username=username).exists():
            detail = {
                "detail": "User Already exist!"
            }
            raise ValidationError(detail=detail)
        return username
    ```
- To validate the password matching and also check email already exists or not.
    ```python
    def validate(self, instance):
        if instance['password'] != instance['confirm_password']:
            raise ValidationError({"message":"Both password must match"})
        if User.objects.filter(email=instance['email']).exists():
            raise ValidationError({"message":"Email already taken!"})
        return instance
    ```
- After validate the user then implement a functio name create to create the user.
    ```python
    def create(self, validated_data):
        password = validated_data.pop('password')
        confirm_password = validated_data.pop('confirm_password')
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        return user
    ```

### UserLoginSerializer:
- Create user login serializer
    ```python
    class UserLoginSerializer(serializers.ModelSerializer):
        username = serializers.CharField()
        password = serializers.CharField(write_only=True)
        
        class Meta:
            model = User
            fields = ['username', 'password']
    ```
⬆️ [Go to Context](#context)

## Create View Methodology
Create viewsets using diffent api view like: `ModelViewSet`, `GenericAPIView`, `APIView` method. Also import required libries:
### User Register View
- Here I create user registration method using `ModelViewSet` with the custom `@action` method for custom registration endpoint.
    ```python
    #Import the libries
    from django.contrib.auth.models import User
    from rest_framework import status,viewsets
    from rest_framework.exceptions import MethodNotAllowed
    from .serializers import UserRegisterSerializer
    ```
    ```python
    class UserRegisterViewSet(viewsets.ModelViewSet):
        queryset = User.objects.all()
        serializer_class = UserRegisterSerializer
    ```
- `ModelViewSet` provide default create method. But here i need to customize the registration  that's why apply `MethodNotAllowed`. For that include the create function under the `UserRegisterViewSet` class:
    ```python
    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="POST",detail="User creation is not allowed on this endpoint. Go to '/users/register/' endpoint")

    ```
- Now apply the custom registratio function under the `UserRegisterViewSet` class:
    ```python
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
    ```

### User Login View:
- Here include the user login view. With the login functionalities include the user `JWT` Authentication and Email based `2FA OTP` authentication. Step by step process how a user can access their data into their dashboard or account:
    - Goto `/api/login/` endpoint and Login using `username` and `password`
    - After that send a `OTP` user registered email address.
    - To validate the OTP goto `/api/verify-otp/` endpoint and verify the otp using username and otp.
    - After validation generate a `refresh token` and `access token`. Using the `access token` user can access their data.
- Now create `Loginview` method. At first need to import some libries:
    ```python
    from rest_framework.exceptions import ValidationError
    ```
    Create an in-memory dictionary `otp_storage` to stored the OTP temporarily in an in-memory dictionary. It declare globally:
    ```python
    otp_storage = {}
    ```
    ```python
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

    ```