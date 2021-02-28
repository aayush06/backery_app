from django.utils.translation import ugettext_lazy as _

INVALID_CREDENTIALS_ERROR = _("Your credentials do not match.")
INACTIVE_ACCOUNT_ERROR = _(
    'Your account is inactive. Please contact admin to activate your account.')
NON_REGISTERED_ACCOUNT = _("User does not exists")
INVALID_PHONENUMBER = _("Please enter valid phone number.")
INVALID_OTP = _("Invalid OTP. Please enter valid OTP.")
PHONE_NUMBER_VALIDATION_ERROR = _(
    "User with this mobile number does not exists")
PASSWORD_RESET_CONFIRM = _("Password Reset Successfully")
PHONE_NUMBER_VALIDATED = ("Phone number verified")
UNREGISTERED_EMAIL = ("No account is founded with this email id")
OTP_SENT_SUCCESSFULLY = _("Otp sent successfully.")
PHONE_NUMBER_CHANGED = ("Phone number successfully changed")
PHONE_NUMBER_ALREADY_EXISTS = ("This number is already in use")
WRONG_PASSWORD = _("Password is not correct")
WRONG_OLD_PASSWORD = _("Incorrect old password.")
SAME_PASSWORD_AS_OLD = _("""You can not have the new password same as the last one you were using.""")
OTP_NUMBER_MISMATCH = (
    """Number provided in request to change Phone number
    does not match with provided number""")
PHONE_NUMBER_ALREADY_EXISTS = ("User with this phone number already exists.")
PHONE_MAX_MIN_VALIDATION_MESSAGE = _("Length should be between 8-13 digits, excluding '+'")
EMAIL_ALREADY_EXITS = ('User with this email address already exists.')
USERNAME_ALREADY_EXISTS = ('user with this username already exists.')
CANNOT_UPDATE_ADMIN_USER = _("You dont have access to update your profile.")
USER_DOES_NOT_EXIST = _("User doesn't exist.")
ROLE_NAME_NOT_ALLOWED = _("Role with this role name is not allowed")
ROLENAME_ALREADY_EXISTS = _("Role with this role_name already exist for your account")
NO_MOBILE_ACCESS = _("You have no mobile access. Please contact admin to grant access")
NO_WEB_ACCESS = _("You have no web access. Please contact admin to grant access")
DEVICE_NOT_REGISTERED = _("You have tried to log in from a new device. Please contact the admin to remove the old device for your account.")

INVALID_USER_REDIS_API_FILTER_KEYS = _("Only 'team'/'id'/'account' filter keys are valid. One at a time.")
USER_DATA_CACHE_SCRIPT_INITIATED = _("Successfully initiated script for storing current user data in cache.")
USER_DATA_CACHE_FLUSH_SCRIPT_INITIATED = _("Successfully initiated script for flushing current user data in cache.")
