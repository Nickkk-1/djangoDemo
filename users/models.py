from django.db import models

# Create your models here.

# users/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    phone = models.CharField(max_length=11, blank=True, null=True)
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)

    def __str__(self):
        return self.username

class Menu(models.Model):
    parent = models.ForeignKey('self', on_delete=models.CASCADE, blank=True, null=True, related_name='children')
    name = models.CharField(max_length=50)
    url = models.CharField(max_length=200, blank=True, null=True)
    icon = models.CharField(max_length=50, blank=True, null=True)  # 存储Font Awesome图标名
    order = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    is_hidden = models.BooleanField(default=False)  # 控制菜单是否隐藏（如仅用于权限控制）

    def __str__(self):
        return self.name