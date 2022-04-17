import datetime

import jwt
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from user.models import User
from user.serializers import UserSerializer


class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LoginView(APIView):
    def post(self, request):
        email = request.data["email"]
        password = request.data["password"]
        user = User.objects.filter(email=email).first()
        payload = {"id": user.id,
                   "expiration": str(datetime.datetime.utcnow() + datetime.timedelta(minutes=60)),
                   "created": str(datetime.datetime.utcnow())
                   }

        token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
        if user:
            if not user.check_password(password):
                raise AuthenticationFailed("Incorrect password")
        else:
            raise AuthenticationFailed("User not found")
        response = Response()
        response.set_cookie(key="jwt", value=token, httponly=True)
        response.data = token
        return response


class UserView(APIView):
    @staticmethod
    def user(token):
        user = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256", ])
        user = User.objects.filter(id=user["id"]).first()
        return user

    def get(self, request):
        token = request.COOKIES.get("jwt")
        if not token:
            raise AuthenticationFailed("Unauthenticated user")
        user = self.user(token)
        serializer = UserSerializer(user)
        return Response({"user": serializer.data})


class TestView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        return Response({"message": "Yay"})
