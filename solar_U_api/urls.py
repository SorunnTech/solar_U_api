
from django.contrib import admin
from django.urls import path, re_path,include
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView


schema_view = get_schema_view(
    openapi.Info(
        title="Solar-U API",
        default_version='v1',
        description="Solar-U API Documentation",
        # terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="hopefuledi@gmail.com"),
        public=True,
    )
)

urlpatterns = [
    path('admin/', admin.site.urls),
    
    #apps urls
    path('api/v1/auth/', include('authentication.urls')),
    path('api/v1/role/', include('roles.urls')),
    path('api/v1/user/', include('users.urls')),


    #jwt urls
    path('api/v1/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/v1/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    #swagger urls
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
