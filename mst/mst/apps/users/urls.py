
from django.conf.urls import url,include
from .views import RegisterView
# from . import views
urlpatterns = [
    url(r'^register/$', RegisterView.as_view(), name='register'),# 注册
]