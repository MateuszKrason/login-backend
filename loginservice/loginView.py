from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
import jwt


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        print("username is " + str(username) + " and password is " + str(password) + " the value of user is ", user)
        if user is not None:
            login(request, user)
            jwt_token = jwt.encode({'user_id': user.id}, 'SECRET_KEY', algorithm='HS256')
            response = redirect('zalogowano')
            response.set_cookie('jwt_token', jwt_token)
            return response
        else:
            return render(request, 'login.html', {'error': 'Invalid login credentials.'})
    else:
        return render(request, 'login.html')
