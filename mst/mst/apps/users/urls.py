
from django.conf.urls import url,include
from .views import RegisterView,UsernameCountView,LoginView
# from . import views
urlpatterns = [
    url(r'^register/$', RegisterView.as_view(), name='register'),# 注册
    url(r'^usernames/(?P<username>[a-zA-Z0-9_-]{5,20})/count/$', UsernameCountView.as_view()),  # 判断用户名是否重复注册
    url(r'^login/$', LoginView.as_view(), name='login'),    # 用户登录
]