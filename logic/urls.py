from django.urls import include, path,re_path
from .views import DeptView, NUserViewSet, OrgView, RolesViewset ,AUserViewSet,InviteUserView, create_dept, create_orgs, delete_dept, elevate, list_depts, list_orgs, list_roles, list_users, update_dept
from rest_framework.routers import DefaultRouter

router =DefaultRouter()
router.register('org',OrgView,basename='orgs')
urlpatterns = [
    #Org Paths`
    # path('',include(router.urls)),
    path('org/list_orgs',list_orgs,name="list_orgs"),
    path('org/createOrgs',create_orgs,name="create_orgs"),

    #Dept Paths
    path('dept/listDepts',list_depts,name="list_depts"),
    path('dept/createDepts',create_dept,name="create_dept"),
    re_path(r'^dept/deleteDept/?(?P<id>[\w-]*)',delete_dept,name="delete_dept"),
    re_path(r'^dept/updateDept/?(?P<id>[\w-]*)',update_dept,name="update_dept"),

    # User Paths For Admins
    re_path(r'^users/list_users/?(?P<dept>[\w-]*)',list_users,name="list_users"),
    re_path(r'users/getUserInfo/(?P<id>[\w-]*)',AUserViewSet.as_view({'get':"get_user_info"}),name="Getuser Info"),
    re_path(r'^users/elevate/(?P<id>[\w-]+)', elevate, name='elevate'),
    re_path(r'^users/deleteUser/?(?P<id>[\w-]*)',AUserViewSet.as_view({'delete':'delete_user'}),name="delete user"),
    path('users/invite',InviteUserView.as_view({'post':"invite_driver"}),name='InviteUsers'),
    path('users/invites/pending',InviteUserView.as_view({'get':"get_pending_invites"}),name='Get Pending user Invites'),
    # For Normal Users
    path('users/getProfileInfo',NUserViewSet.as_view({'get':'get_current_user_info'}),name="get current user info"),
    path('users/updateProfile',NUserViewSet.as_view({'put':'update_profile_data'}),name="Update user Profile data"),
    # Roles Paths
    path('role/listRoles',list_roles,name="list_roles"),
    path('role/updateRoles/<str:id>', RolesViewset.as_view({'put': 'update_roles'}), name='update_roles'),
    path('role/deleteRoles/<str:id>',RolesViewset.as_view({'delete': 'delete_roles'}),name='delete-roles'),
    path('role/createRoles',RolesViewset.as_view({'post':'create_roles'}),name="create-roles"),

    
]