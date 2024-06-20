from django.urls import path,include, re_path
from .views import *
from django.urls import path
from .views import ShareViewSetSender, ShareViewSetReceiver,add_departments_to_file, list_files, delete_file, add_file_to_folder, list_files_in_current_folder, share_file, LoggingView, GeoLocationView, get_shared_file_url
from rest_framework.routers import DefaultRouter

router = DefaultRouter(trailing_slash=False)
router.register(r'folder',FolderViewSet,basename='folder')

urlpatterns = [
    # File Listing and Operations
    re_path(r'files', list_files, name="list_files"),
    path('delete-file/<str:file_id>/', delete_file, name='delete_file'),
    re_path(r'addDepartment/(?P<file_id>[\w-]*)',add_departments_to_file , name='add_departments_to_file'),
    
    
    # Shared File Operations
    re_path(r'shareFile', share_file, name="shareFile"),
    path('sharedFileInfo/<str:file_id>/', get_file_info, name="get_file_info"),    
    re_path(r'deleteShare/(?P<file_id>[\w-]*)', delete_share, name='delete_share'),
    path('editShare/<str:file_id>/',edit_access,name="edit_access"),

    # Folder Interactions
    re_path(r'folder/addFile/(?P<folder_id>[\w-]*)',add_file_to_folder,name="add_file_to_folder"),
    re_path(r'folder/listFiles/(?P<folder_id>[\w-]*)',list_files_in_current_folder,name="list_files_in_current_folder"),
    # Get a Presigned URL for a Shared File
    path('getPresigned/<str:file_id>', get_shared_file_url, name="get_shared_file_url"),

    # Store ScreenShot Attempt
    re_path(r'logEvent/(?P<file>[\w-]*)',event_log_handler,name="event_log_handler"),
    re_path(r'getLogs/?(?:(?P<event>[\w-]*)/)?(?P<file>[\w-]*)',get_logs,name="get_logs"),

    # GeoLocation Endpoints
    re_path(r'createLocation',GeoLocationView.as_view({'post':'create_location'}),name="Creating an allowed location"),
    re_path(r'listLocation',GeoLocationView.as_view({"get":"get_locations"}),name="List all the allowed locations"),
    re_path(r'deleteLocation/(?P<id>[\w-]*)',GeoLocationView.as_view({"delete":"delete_location"}),name="Delete locations"),
    re_path(r'updateLocation/(?P<id>[\w-]*)',GeoLocationView.as_view({"put":"update_location"}),name="Update locations"),

    # path('test',SetDepartment.as_view(),name="DELETE This ENDPT")
]

urlpatterns += router.urls