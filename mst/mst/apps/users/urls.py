
from django.conf.urls import url,include
from .views import RegisterView,UsernameCountView,LoginView,LogoutView,UserInfoView,MobileCountView,EmailView
from . import views
# from . import views
urlpatterns = [
    url(r'^register/$', RegisterView.as_view(), name='register'),# 注册
    url(r'^usernames/(?P<username>[a-zA-Z0-9_-]{5,20})/count/$', UsernameCountView.as_view()),  # 判断用户名是否重复注册
    url(r'^mobiles/(?P<mobile>1[3-9]\d{9})/count/$', MobileCountView.as_view()),    # 判断用户名是否重复注册
    url(r'^login/$', LoginView.as_view(), name='login'),    # 用户登录
    url(r'^logout/$', LogoutView.as_view(), name='logout'), # 用户退出登录
    url(r'^info/$', UserInfoView.as_view(), name='info'), # 用户中心
    url(r'^emails/$', EmailView.as_view()), # 添加邮箱
    url(r'^emails/verification/$', views.VerifyEmailView.as_view()),    # 验证邮箱
    url(r'^addresses/$', views.AddressView.as_view(), name='address'), # 展示用户地址
    url(r'^addresses/create/$', views.AddressCreateView.as_view()),    # 新增用户地址
    # # 更新和删除地址
    # url(r'^addresses/(?P<address_id>\d+)/$', views.UpdateDestoryAddressView.as_view()),
    # # 设置默认地址
    # url(r'^addresses/(?P<address_id>\d+)/default/$', views.DefaultAddressView.as_view()),
    # # 更新地址标题
    # url(r'^addresses/(?P<address_id>\d+)/title/$', views.UpdateTitleAddressView.as_view()),
]