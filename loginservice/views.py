from django.http import HttpResponse
from django.shortcuts import render
from . import loginView
from . import backends
from django.shortcuts import redirect

from .backends import custom_logout

@backends.custom_login_required
def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")

def login_view(request) :
    return loginView.login_view(request)

def zalogowano(request) :
    return render(request, "zalogowano.html")
