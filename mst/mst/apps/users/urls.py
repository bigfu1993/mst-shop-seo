
from django.conf.urls import url,include
# from users.views import RegisterView
import users
urlpatterns = [
    url(r'^register/$', users.views.RegisterView.as_view(), name='register'),# 注册
]