CAN_VIEW_PERMISSION = "can_view_permission"

CAN_VIEW_ROLE = "can_view_role"
CAN_CREATE_ROLE = "can_create_role"
CAN_EDIT_ROLE = "can_edit_role"
CAN_DEACTIVATE_ROLE = "can_deactivate_role"

CAN_VIEW_USER = "can_view_user"
CAN_CREATE_USER = "can_create_user"
CAN_EDIT_USER = "can_edit_user"
CAN_DEACTIVATE_USER = "can_deactivate_user"

CAN_VIEW_TEAM = "can_view_team"
CAN_CREATE_TEAM = "can_create_team"
CAN_EDIT_TEAM = "can_edit_team"
CAN_DEACTIVATE_TEAM = "can_deactivate_team"

CAN_VIEW_ACCOUNTS = "can_view_accounts"
CAN_CREATE_ACCOUNTS = "can_create_accounts"
CAN_UPDATE_ACCOUNTS = "can_update_accounts"
CAN_DEACTIVATE_ACCOUNTS = "can_deactivate_accounts"

CAN_VIEW_BRAND = "can_view_brand"
CAN_CREATE_BRAND = "can_create_brand"
CAN_UPDATE_BRAND = "can_update_brand"
CAN_DEACTIVATE_BRAND = "can_deactivate_brand"

CAN_VIEW_COMPANY = "can_view_company"
CAN_CREATE_COMPANY = "can_create_company"
CAN_UPDATE_COMPANY = "can_update_company"
CAN_DEACTIVATE_COMPANY = "can_deactivate_company"

CAN_CREATE_PACKAGES = "can_create_packages"
CAN_UPDATE_PACKAGES = "can_update_packages"
CAN_DEACTIVATE_PACKAGES = "can_deactivate_packages"

CAN_CREATE_FEATURES = "can_create_features"
CAN_UPDATE_FEATURES = "can_update_features"
CAN_DEACTIVATE_FEATURES = "can_deactivate_features"

CAN_VIEW_POI = "can_view_poi"
CAN_CREATE_POI = "can_create_poi"
CAN_UPDATE_POI = "can_update_poi"
CAN_DEACTIVATE_POI = "can_deactivate_poi"

CAN_VIEW_GEOGRAPHICAL_AREA = "can_view_geographical_area"
CAN_CREATE_GEOGRAPHICAL_AREA = "can_create_geographical_area"
CAN_UPDATE_GEOGRAPHICAL_AREA = "can_update_geographical_area"
CAN_DEACTIVATE_GEOGRAPHICAL_AREA = "can_deactivate_geographical_area"

CAN_CHAT = "can_chat"

CAN_VIEW_ATTENDANCE = "can_view_attendance"
CAN_EDIT_ATTENDANCE = "can_edit_attendance"

CAN_VIEW_SHIFT = "can_view_shift"
CAN_CREATE_SHIFT = "can_create_shift"
CAN_EDIT_SHIFT = "can_edit_shift"
CAN_DEACTIVATE_SHIFT = "can_deactivate_shift"
CAN_VIEW_SHIFT_REQUEST = "can_view_shift_request"
CAN_CREATE_SHIFT_REQUEST = "can_create_shift_request"
CAN_ACT_ON_SHIFT_REQUEST = "can_act_on_shift_request"
CAN_VIEW_LEAVE = "can_view_leave"
CAN_CREATE_LEAVE = "can_create_leave"
CAN_EDIT_LEAVE = "can_edit_leave"
CAN_DEACTIVATE_LEAVE = "can_deactivate_leave"
CAN_VIEW_TIME_OFF_REQUEST = "can_view_time_off_request"
CAN_CREATE_TIME_OFF_REQUEST = "can_create_time_off_request"
CAN_EDIT_TIME_OFF_REQUEST = "can_edit_time_off_request"
CAN_DEACTIVATE_TIME_OFF_REQUEST = "can_deactivate_time_off_request"
CAN_ACT_ON_TIME_OFF_REQUEST = "can_act_on_time_off_request"

CAN_ACCESS_OPEN_API = "can_access_open_api"

permission_choices = (
    (CAN_VIEW_PERMISSION, "Can view permission"),
    (CAN_VIEW_ROLE, "Can view role"),
    (CAN_CREATE_ROLE, "Can create role"),
    (CAN_EDIT_ROLE, "Can edit role"),
    (CAN_DEACTIVATE_ROLE, "Can deactivate role"),
    (CAN_VIEW_USER, "Can view user"),
    (CAN_CREATE_USER, "Can create user"),
    (CAN_EDIT_USER, "Can edit user"),
    (CAN_DEACTIVATE_USER, "Can deactivate user"),
    (CAN_VIEW_TEAM, "Can view team"),
    (CAN_CREATE_TEAM, "Can create team"),
    (CAN_EDIT_TEAM, "Can edit team"),
    (CAN_DEACTIVATE_TEAM, "Can deactivate team"),
    (CAN_VIEW_ACCOUNTS, "Can view accounts"),
    (CAN_CREATE_ACCOUNTS, "Can create accounts"),
    (CAN_UPDATE_ACCOUNTS, "Can update accounts"),
    (CAN_DEACTIVATE_ACCOUNTS, "Can deactivate accounts"),
    (CAN_VIEW_BRAND, "Can view brand"),
    (CAN_CREATE_BRAND, "Can create brand"),
    (CAN_UPDATE_BRAND, "Can update brand"),
    (CAN_DEACTIVATE_BRAND, "Can deactivate brand"),
    (CAN_VIEW_COMPANY, "Can view company"),
    (CAN_CREATE_COMPANY, "Can create company"),
    (CAN_UPDATE_COMPANY, "Can update company"),
    (CAN_DEACTIVATE_COMPANY, "Can deactivate company"),
    (CAN_CREATE_PACKAGES, "Can create packages"),
    (CAN_UPDATE_PACKAGES, "Can update packages"),
    (CAN_DEACTIVATE_PACKAGES, "Can deactivate packages"),
    (CAN_VIEW_POI, "Can view poi"),
    (CAN_CREATE_POI, "Can create poi"),
    (CAN_UPDATE_POI, "Can update poi"),
    (CAN_DEACTIVATE_POI, "Can deactivate poi"),
    (CAN_VIEW_GEOGRAPHICAL_AREA, "Can view geographical area"),
    (CAN_CREATE_GEOGRAPHICAL_AREA, "Can create geographical area"),
    (CAN_UPDATE_GEOGRAPHICAL_AREA, "Can update geographical area"),
    (CAN_DEACTIVATE_GEOGRAPHICAL_AREA, "Can deactivate geographical area"),
    (CAN_CHAT, "Can chat"),
    (CAN_VIEW_ATTENDANCE, "Can view attendance"),
    (CAN_EDIT_ATTENDANCE, "Can edit attendance"),
    (CAN_VIEW_SHIFT, "Can View Shift"),
    (CAN_CREATE_SHIFT, "Can Create Shift"),
    (CAN_EDIT_SHIFT, "Can Edit Shift"),
    (CAN_DEACTIVATE_SHIFT, "Can Deactivate Shift"),
    (CAN_VIEW_SHIFT_REQUEST, "Can View Shift Request"),
    (CAN_CREATE_SHIFT_REQUEST, "Can Create Shift Request"),
    (CAN_ACT_ON_SHIFT_REQUEST, "Can Act On Shift Request"),
    (CAN_VIEW_LEAVE, "Can View Leave"),
    (CAN_CREATE_LEAVE, "Can Create Leave"),
    (CAN_EDIT_LEAVE, "Can Edit Leave"),
    (CAN_DEACTIVATE_LEAVE, "Can Deactivate Leave"),
    (CAN_VIEW_TIME_OFF_REQUEST, "Can View Time-Off Request"),
    (CAN_CREATE_TIME_OFF_REQUEST, "Can Create Time-Off Request"),
    (CAN_ACT_ON_TIME_OFF_REQUEST, "Can Act On Time-Off Request"),
    (CAN_CREATE_FEATURES, "Can Create Features"),
    (CAN_UPDATE_FEATURES, "Can Update Features"),
    (CAN_DEACTIVATE_FEATURES, "Can Deactivate Features"),
    (CAN_EDIT_TIME_OFF_REQUEST, "Can Edit Time-Off Request"),
    (CAN_DEACTIVATE_TIME_OFF_REQUEST, "Can Deactivate Time-Off Request"),
    (CAN_ACCESS_OPEN_API, "Can Access Open API")
    )

start_page_choices = (
    ("settings", "Settings"),
    ("dashboard", "Dashboard")
)
