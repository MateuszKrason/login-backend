from django.contrib.auth import logout
from django.contrib.auth.backends import BaseBackend
from django.http import JsonResponse
from . import models
from django.shortcuts import redirect
from django.urls import reverse
import jwt


class UserBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = models.User.objects.get(login=username)
        except models.User.DoesNotExist:
            return None

        if user.check_password(password):
            return user
        else:
            return None

    def get_user(self, user_id):
        try:
            return models.User.objects.get(pk=user_id)
        except models.User.DoesNotExist:
            return None


def custom_login_required(view_func):
    def wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect(reverse('login'))
        return view_func(request, *args, **kwargs)

    return wrapped_view


def custom_logout(request):
    jwt_token = request.COOKIES.get('jwt_token')
    if jwt_token:
        try:
            decoded_token = jwt.decode(jwt_token, 'SECRET_KEY', algorithms=['HS256'])
            user_id = decoded_token['user_id']
        except jwt.InvalidTokenError:
            pass
    logout(request)
    # Delete JWT token from cookie
    response = JsonResponse({'success': True})
    response.delete_cookie('jwt_token')

    # Return JSON response with success message
    return JsonResponse({'success': True})
