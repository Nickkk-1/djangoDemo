# users/serializers.py
from rest_framework import serializers
from .models import User, Menu


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'phone', 'avatar']

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,  # 该字段只用于写入（创建/更新），不用于读取
        required=True,  # 该字段为必填项
        style={'input_type': 'password'}  # 前端显示为密码输入框（掩码效果）
    )
    password2 = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password2', 'phone']
        extra_kwargs = {
            'password': {'write_only': True}, # 等价于在字段定义时写write_only=True
            'password2': {'write_only': True},
        }

    def validate_password(self, value):
        if len(value) < 6:
            raise serializers.ValidationError({"password": "密码长度至少为6位"})
        return value


    def validate(self, attrs):
        # 验证两次输入的密码是否一致
        print(f"原始数据: {attrs}")  # 添加调试打印
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "两次输入的密码不一致"})
        return attrs


    def create(self, validated_data):
        # 删除password2字段，不需要存储
        validated_data.pop('password2')
        # 创建用户并设置密码
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email', ''),
            password=validated_data['password'],
            phone=validated_data.get('phone', '')
        )
        return user

class PasswordChangeSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(
        write_only=True,  # 该字段只用于写入（创建/更新），不用于读取
        required=True,  # 该字段为必填项
        style={'input_type': 'password'}  # 前端显示为密码输入框（掩码效果）
    )
    new_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    new_password2 = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ["old_password", "new_password", 'new_password2']
        extra_kwargs = {
            'new_password': {'write_only': True}, # 等价于在字段定义时写write_only=True
            'new_password2': {'write_only': True},
        }

    def validate_password(self, value):
        if len(value) < 6:
            raise serializers.ValidationError({"new_password": "密码长度至少为6位"})
        return value


    def validate(self, attrs):
        # 验证两次输入的密码是否一致
        print(f"原始数据: {attrs}")  # 添加调试打印
        if attrs['new_password'] != attrs['new_password2']:
            raise serializers.ValidationError({"new_password": "两次输入的密码不一致"})
        return attrs


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})


class MenuSerializer(serializers.ModelSerializer):
    children = serializers.SerializerMethodField()

    class Meta:
        model = Menu
        fields = ['id', 'parent', 'name', 'url', 'icon', 'order', 'is_active', 'is_hidden', 'children']

    def get_children(self, obj):
        # 递归序列化子菜单
        children = obj.children.filter(is_active=True, is_hidden=False).order_by('order')
        return MenuSerializer(children, many=True).data