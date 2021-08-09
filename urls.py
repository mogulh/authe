from django.contrib.auth.models import User
from django.urls import path
from .views import *

urlpatterns = [
    path('register/', register),
    path('activate/', activate),
    path("reset_activate/",activate_reset),

    path('token/', CustomAuthToken.as_view()),
    path('reset/', pass_reset),
    path('reset-confirm/', reset_confirm),
    path('password/', password),
]
