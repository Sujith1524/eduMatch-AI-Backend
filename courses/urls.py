from . import views
from django.urls import path
from .views import ProviderLoginView
from courses.views import provider_register
from .views import search_institutes_by_distance
from .views import user_register, admin_list_users, admin_list_institutes, admin_list_courses, logout_user
from .views import unified_login, provider_institutes, edit_institute, provider_institute_details, edit_course, delete_institute, delete_course

urlpatterns = [
    path('list/', views.list_courses, name='list-courses'),
    path('add-institute/', views.add_institute, name='add-institute'),
    path('add-course/', views.add_course, name='add-course'),
    path('provider-register/', provider_register, name='provider-register'),
    path('provider-login/', ProviderLoginView.as_view(), name='provider-login'),
    path('admin-login/', views.admin_login, name='admin-login'),
    path('user-register/', user_register, name='user-register'),
    path('user-login/', views.user_login, name='user-login'),
    path('login/', unified_login, name='unified-login'),  
    path("provider-institutes/", provider_institutes, name="provider_institutes"),
    path("institutes/<int:institute_id>/edit/", edit_institute, name="edit_institute"),
    path("institutes/<int:institute_id>/details/", provider_institute_details, name="provider_institute_details"),
    path("courses/<int:course_id>/edit/", edit_course, name="edit_course"),
    path("institutes/<int:institute_id>/delete/", delete_institute, name="delete_institute"),
    path("courses/<int:course_id>/delete/", delete_course, name="delete_course"),
    path("admin/users/", admin_list_users, name="admin-list-users"),
    path("admin/institutes/", admin_list_institutes, name="admin-list-institutes"),
    path("admin/courses/", admin_list_courses, name="admin-list-courses"),
    path("logout/", logout_user, name="Logout"),
    path("search-institutes/", search_institutes_by_distance, name="search-institutes"),
    path("recommend/", views.recommend_courses, name="recommend_courses"),
    path("course-names/", views.get_course_names, name="get_course_names"),
    path("institutions-courses/", views.get_all_institutions, name="list_institutions_with_courses"),

]
