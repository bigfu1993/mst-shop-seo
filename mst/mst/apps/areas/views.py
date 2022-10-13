from django.shortcuts import render
from django.views import View
import logging

logger = logging.getLogger('django')
# Create your views here.
class AreasView(View):
    def get(self,request):
        pass