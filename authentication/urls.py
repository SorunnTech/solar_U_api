from django.urls import path
from authentication import views


urlpatterns = [
    path('login/', views.Login.as_view()),
    path('register/', views.Register.as_view()),
    path('generate-otp/', views.GenerateOTP.as_view()),
    path('verify-otp/', views.VerifyOTP.as_view()),
    path('forgot-password/', views.ForgotPassword.as_view()),
    path('verify-reset-password-link/', views.verifyResetPasswordLink.as_view()),
    path('reset-password/', views.ResetPassword.as_view()),
    path('change-password/',views.ChangePassword.as_view())
]
