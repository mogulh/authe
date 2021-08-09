from accounts.models import Profile
import json

from asgiref.sync import sync_to_async
from django.contrib.auth.models import User, Group
from django.core.mail import EmailMessage
from django.utils import timezone
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from swyftAPI import settings

from .models import ActivateToken, ResetToken


class CustomAuthToken(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'key': token.key,
            'user_id': user.pk,
            # 'group': user.groups.all()[0].id
        })


@api_view(["POST"])
def activate_reset(request):
    data = request.data
    email = data['email']

    try:
        user = User.objects.get(email=email)
        code, created = ActivateToken.objects.get_or_create(user=user)
        if code.expiry < timezone.now():
            code.delete()
            ActivateToken.objects.get_or_create(user=user)

        print('sending', code.token)
        send_email(email, code.token,"activate")
        return Response(status=status.HTTP_200_OK)

    except:
        return Response({'error': "user with that email does not exist"}, status=status.HTTP_403_FORBIDDEN)

@api_view(['POST'])
def activate(request):
    data = request.data
    email=data['email']
    code = int(data['code'])

    user = User.objects.get(email=email)
    try:
        kode = ActivateToken.objects.get(user=user)
    except:
        return Response({'error':"code is not valid"}, status=status.HTTP_403_FORBIDDEN)

    if kode.expiry < timezone.now():
        return Response({'error': 'code has expired'}, status=status.HTTP_403_FORBIDDEN)

    if kode.token == code:
        kode.delete()
        token, created = Token.objects.get_or_create(user=user)
        user.is_active=True
        user.save()
        return Response({
            'key': token.key,
            'user_id': user.pk,
            # 'group': user.groups.all()[0].id
        })
    else:
        return Response({'error': 'code is not valid'}, status=status.HTTP_403_FORBIDDEN)


@api_view(['POST'])
def register(request):
    data = request.data
    first_name = data['first_name']
    last_name = data['last_name']
    email = data['email']
    password = data['password']
    group = data['group']
    
    print(group)

    group = Group.objects.get(name=group)

    if User.objects.filter(email=email).exists():
        return Response({'error': "user with that email already exists"}, status=status.HTTP_403_FORBIDDEN)

    user = User.objects.create_user(first_name=first_name, last_name=last_name, password=password,
                                    email=email, username=email)
    code = ActivateToken.objects.create(user=user)
    user.is_active=False
    user.save()
    Profile.objects.create(user=user)
    send_email(email,code.token,"activate")

    Token.objects.get_or_create(user=user)
    user.groups.add(group)

    return Response(status=status.HTTP_201_CREATED)


def send_email(email, token, em_type):
    print('sending email...')
    if em_type=="reset":
        msg = EmailMessage(subject="password reset token",
                            body=f"Use the code to reset your password \n {token}",

                        to=[email])
    else:
        msg = EmailMessage(subject="account activation token",
                            body=f"Use the code to activate your account \n {token}",

                        to=[email])
    msg.send(fail_silently=False)
   
    print('success')


@api_view(['POST'])
def pass_reset(request):
    data = request.data
    email = data['email']

    try:
        user = User.objects.get(email=email)
        code, created = ResetToken.objects.get_or_create(user=user)
        if code.expiry < timezone.now():
            code.delete()
            ResetToken.objects.get_or_create(user=user)

        print('sending', code.token)
        send_email(email, code.token,"reset")
        return Response(status=status.HTTP_200_OK)

    except:
        return Response({'error': "user with that email does not exist"}, status=status.HTTP_403_FORBIDDEN)


@api_view(['POST'])
def reset_confirm(request):
    data = request.data
    email = data['email']
    code = int(data['code'])

    user = User.objects.get(email=email)
    try:
        kode = ResetToken.objects.get(user=user)
    except:
        return Response({'error':"code is not valid"}, status=status.HTTP_403_FORBIDDEN)

    if kode.expiry < timezone.now():
        return Response({'error': 'code has expired'}, status=status.HTTP_403_FORBIDDEN)

    if kode.token == code:
        kode.delete()
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'key': token.key,
            'user_id': user.pk,
            # 'group': user.groups.all()[0].id
        })
    else:
        return Response({'error': 'code is not valid'}, status=status.HTTP_403_FORBIDDEN)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def password(request):
    user = request.user
    data = request.data
    oldPass = data['oldPass']
    newPass = data['newPass']

   

    if user.password is not oldPass:
        return Response(status.HTTP_401_UNAUTHORIZED)
    else:
        user.password = newPass
        user.save()

        print("password after", user.password)

        return Response(status=status.HTTP_201_CREATED)
