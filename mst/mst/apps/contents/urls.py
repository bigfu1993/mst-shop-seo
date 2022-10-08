
from django.conf.urls import url,include
from .views import IndexView
# from . import views
urlpatterns = [
    url(r'^$', IndexView.as_view(), name='register'),# 注册
]