from django.shortcuts import render,redirect
from django.views import View
from django import http
from django.db import DatabaseError
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse
import re

from mst.utils.response_code import RETCODE
from users.models import User

class UsernameCountView(View):
    """判断用户名是否重复注册"""

    def get(self, request, username):
        """
        :param username: 用户名
        :return: JSON
        """
        # 实现主体业务逻辑：使用username查询对应的记录的条数(filter返回的是满足条件的结果集)
        count = User.objects.filter(username=username).count()
        # 响应结果
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK', 'count': count})


# Create your views here.
class RegisterView(View):
    """用户注册"""

    def get(self, request):
        """提供用户注册页面"""
        return render(request, 'register.html')

    def post(self, request):
        """实现用户注册业务逻辑"""
        # 接收参数：表单参数
        username = request.POST.get('username')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        mobile = request.POST.get('mobile')
        allow = request.POST.get('allow')

        # 校验参数：前后端的校验需要分开，避免恶意用户越过前端逻辑发请求，要保证后端的安全，前后端的校验逻辑相同
        # 判断参数是否齐全:all([列表])：会去校验列表中的元素是否为空，只要有一个为空，返回false
        if not all([username, password, password2, mobile, allow]):
            return http.HttpResponseForbidden('缺少必传参数')
        # 判断用户名是否是5-20个字符
        if not re.match(r'^[a-zA-Z0-9_-]{5,20}$', username):
            return http.HttpResponseForbidden('请输入5-20个字符的用户名')
        # 判断密码是否是8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return http.HttpResponseForbidden('请输入8-20位的密码')
        # 判断两次密码是否一致
        if password != password2:
            return http.HttpResponseForbidden('两次输入的密码不一致')
        # 判断手机号是否合法
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('请输入正确的手机号码')
        # 判断是否勾选用户协议
        if allow != 'on':
            return http.HttpResponseForbidden('请勾选用户协议')

        # 保存注册数据：是注册业务的核心

        print(f'username:{username},password:{password},mobile:{mobile},')

        try:
            user = User.objects.create_user(username=username, password=password, mobile=mobile)
        except DatabaseError as e:
            print(f'create_user error:{e}')
            return render(request, 'register.html', {'register_errmsg':'注册失败'})

        # 实现状态保持
        login(request, user)

        # 响应结果：重定向到首页
        # return http.HttpResponse('注册成功，重定向到首页')
        # return redirect('/')
        # reverse('contents:index') == '/'
        # return redirect(reverse('contents:index'))

        # 响应注册结果
        response = redirect(reverse('contents:index'))
        # 注册时用户名写入到cookie，有效期15天
        response.set_cookie('username', user.username, max_age=3600 * 24 * 15)

        return response

class LoginView(View):
    """用户名登录"""

    def get(self, request):
        """
        提供登录界面
        :param request: 请求对象
        :return: 登录界面
        """
        return render(request, 'login.html')

    def post(self, request):
        """
        实现登录逻辑
        :param request: 请求对象
        :return: 登录结果
        """
        # 接受参数
        username = request.POST.get('username')
        password = request.POST.get('password')
        remembered = request.POST.get('remembered')

        # 校验参数
        # 判断参数是否齐全
        if not all([username, password]):
            return http.HttpResponseForbidden('缺少必传参数')

        # 判断用户名是否是5-20个字符
        if not re.match(r'^[a-zA-Z0-9_-]{5,20}$', username):
            return http.HttpResponseForbidden('请输入正确的用户名或手机号')

        # 判断密码是否是8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return http.HttpResponseForbidden('密码最少8位，最长20位')

        # 认证登录用户
        user = authenticate(username=username, password=password)
        if user is None:
            return render(request, 'login.html', {'account_errmsg': '用户名或密码错误'})

        # 实现状态保持
        login(request, user)
        # 设置状态保持的周期
        if remembered != 'on':
            # 没有记住用户：浏览器会话结束就过期
            request.session.set_expiry(0)
        else:
            # 记住用户：None表示两周后过期
            request.session.set_expiry(None)

        # 响应注册结果
        response = redirect(reverse('contents:index'))
        # 注册时用户名写入到cookie，有效期15天
        response.set_cookie('username', user.username, max_age=3600 * 24 * 15)
        return response


class LogoutView(View):
    """退出登录"""

    def get(self, request):
        """实现退出登录逻辑"""
        # 清理session
        logout(request)
        # 退出登录，重定向到登录页
        response = redirect(reverse('contents:index'))
        # 退出登录时清除cookie中的username
        response.delete_cookie('username')

        return response


class UserInfoView(LoginRequiredMixin, View):
    """用户中心"""

    def get(self,request):
        """提供用户中心页面"""
        return render(request, 'user_center_info.html')
        # 如果LoginRequiredMixin判断出用户已登录，那么request.user就是登陆用户对象
        # context = {
        #     'username': request.user.username,
        #     'mobile': request.user.mobile,
        #     'email': request.user.email,
        #     'email_active': request.user.email_active
        # }
        # return render(request, 'user_center_info.html', context)
