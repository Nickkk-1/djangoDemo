# users/urls.py
from django.urls import path
from .views import UserRegisterView, UserLoginView, UserInfoView, MenuListCreateView, MenuRetrieveUpdateDestroyView, \
    MenuTreeView, UserPermissionView, login_view, PasswordChangeView

urlpatterns = [
    path('register/', UserRegisterView.as_view(), name='user-register'),
    path('change/', PasswordChangeView.as_view(), name='user-register'),
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('info/', UserInfoView.as_view(), name='user-info'),

    path('menus/', MenuListCreateView.as_view(), name='menu-list-create'),
    path('menus/<int:pk>/', MenuRetrieveUpdateDestroyView.as_view(), name='menu-detail'),
    path('menus/tree/', MenuTreeView.as_view(), name='menu-tree'),
    path('permissions/', UserPermissionView.as_view(), name='user-permissions'),
    path('login-page/', login_view, name='login-page'),
]

