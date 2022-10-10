
from django.conf.urls import url,include
from .views import ImageCodeView
# from . import views
urlpatterns = [
    url(r'^image_codes/(?P<uuid>[\w-]+)/$', ImageCodeView.as_view()),
]