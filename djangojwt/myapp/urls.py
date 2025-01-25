from django.urls import path,include
from .views import UserRegisterViewSet,LoginView, DashboardView
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register('users', UserRegisterViewSet, basename='user')

urlpatterns = [
    path('',include(router.urls)),
    path('login/',LoginView.as_view(), name='login'),
    path('dashboard/',DashboardView.as_view(), name='dashboard'),     
    
]