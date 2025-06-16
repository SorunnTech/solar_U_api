from django.urls import path
from roles import views


urlpatterns = [
    path('roles/',views.RolesList.as_view()),
    path('roles/<int:pk>/',views.RolesDetails.as_view())
]
