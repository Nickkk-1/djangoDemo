# users/views.py
from django.contrib.auth.models import Permission
from django.shortcuts import render
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework.generics import RetrieveAPIView
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken

from .permissions import MenuObjectPermissions
from .serializers import UserRegisterSerializer, UserLoginSerializer, UserSerializer, MenuSerializer, PasswordChangeSerializer
from .models import Menu


def login_view(request):
    return render(request, 'login.html')



class UserRegisterView(APIView):
    permission_classes = [AllowAny]  # 允许匿名访问

    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "注册成功"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



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


class UserLoginView(APIView):
    permission_classes = [AllowAny]  # 允许匿名访问

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            user = authenticate(username=username, password=password)

            if user is not None:
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


class UserInfoView(RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

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