# users/views.py

from django.contrib.auth.models import update_last_login
from django.shortcuts import render
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework.generics import RetrieveAPIView
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken

from .permissions import MenuObjectPermissions
from .serializers import UserRegisterSerializer, UserLoginSerializer, UserSerializer, MenuSerializer, PasswordChangeSerializer
from .models import Menu, User


def login_view(request):
    return render(request, 'login.html')

# 用户注册
class UserRegisterView(APIView):
    permission_classes = [AllowAny]  # 允许匿名访问

    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "注册成功"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# 用户登录
class UserLoginView(APIView):
    permission_classes = [AllowAny]  # 允许匿名访问


    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            user = authenticate(username=username, password=password)

            if user is not None:
                # 更新last_login字段
                update_last_login(None, user)
                # 生成JWT Token
                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'user_id': user.id,
                    'username': user.username,
                }, status=status.HTTP_200_OK)
            else:
                return Response({"message": "用户名或密码错误"}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# 修改密码
class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            if not user.check_password(serializer.validated_data['old_password']):
                return Response({"old_password": ["原密码错误"]}, status=400)
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            return Response({"message": "密码修改成功"})
        return Response(serializer.errors, status=400)

# 获取当前用户信息
class UserInfoView(RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


# 获取所有用户信息
# 1、判断登录得是否是admin用户，不是则返回"非admin用户无法查询所有用户信息"，是则正常返回
# class UserAllInfoView(ListAPIView):
#     serializer_class = UserSerializer
#     permission_classes = [IsAdminUser]
#
#     def get_queryset(self):
#         return User.objects.filter(is_active=True)

class UserAllInfoView(APIView):
    def get(self, request):
        if not request.user.is_superuser:
            return Response({"message": "无权限", "code": status.HTTP_200_OK})

        user = User.objects.filter(is_active=True, is_superuser=False)

        serializer = UserSerializer(user, many=True)

        return Response(serializer.data)




# GET + POST，返回列表或创建资源
class MenuListCreateView(generics.ListCreateAPIView):
    queryset = Menu.objects.all()
    serializer_class = MenuSerializer
    permission_classes = [MenuObjectPermissions]

# GET + PUT/PATCH + DELETE，返回详情、更新或删除资源
class MenuRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Menu.objects.all()
    serializer_class = MenuSerializer
    permission_classes = [MenuObjectPermissions]

# GET，仅返回列表
class MenuTreeView(generics.ListAPIView):
    """获取菜单树形结构（用于前端导航）"""
    serializer_class = MenuSerializer
    permission_classes = [MenuObjectPermissions]

    def get_queryset(self):
        # 获取所有顶级菜单（无父级）并按order排序
        return Menu.objects.filter(parent=None).order_by('order')


class UserPermissionView(APIView):
    """获取用户的菜单权限"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        # 获取用户角色对应的所有权限
        permissions = user.get_all_permissions()
        print(permissions)

        permission_groups = {}
        for perm in permissions:
            app_label, codename = perm.split('.', 1)
            curd, model_name = codename.split('_', 1)
            if model_name not in permission_groups:
                permission_groups[model_name] = []
            permission_groups[model_name].append(codename)

        return Response({
            'username': user.username,
            'permissions': permission_groups
        })