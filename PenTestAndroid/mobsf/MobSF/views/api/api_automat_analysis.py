# -*- coding: utf_8 -*-
"""REST API Automation."""
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from mobsf.MobSF.utils import api_key

from mobsf.MobSF.views.helpers import request_method
from mobsf.MobSF.views.api.api_middleware import make_api_response

OK = 200

@request_method(['GET'])
@csrf_exempt
def api_test(request):
    return make_api_response({'error': 'JSON Generation Error'}, OK)