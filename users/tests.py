from django.test import TestCase, Client
from django.urls import reverse
from rest_framework import status

from users.models import User


# Create your tests here.

class UserLoginTest(TestCase):
    def setUp(self):
        # 使用 set_password 方法确保密码被正确哈希
        self.user = User.objects.create_user(username='admin')
        self.user.set_password('123456')
        self.user.save()

    def test_login_success(self):
        client = Client()
        data = {
            "username": "admin",
            "password": "123456",
        }
        response = client.post(reverse('user-login'), data=data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)