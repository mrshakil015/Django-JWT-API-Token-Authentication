from django.urls import path,include
from .views import UserRegisterViewSet,LoginView, DashboardView
from rest_framework.routers import DefaultRouter

from drf_yasg.views import get_schema_view
from drf_yasg import openapi
schema_view = get_schema_view(
    openapi.Info(
        title="API documentation for Django JWT API Token Authentication",
        default_version="v1",
        description="API documentation for Django JWT API Token Authentication",
    ),
    public=True
)


router = DefaultRouter()
router.register('users', UserRegisterViewSet, basename='user')

urlpatterns = [
    path('',include(router.urls)),
    path('login/',LoginView.as_view(), name='login'),
    path('dashboard/',DashboardView.as_view(), name='dashboard'),  
    path('docs/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='redoc'),   
    
]