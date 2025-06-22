from django.urls import path
from users import views


urlpatterns = [
    path('users/', views.UsersList.as_view()),
    path('users/<int:pk>/',views.UsersDetails.as_view())
]