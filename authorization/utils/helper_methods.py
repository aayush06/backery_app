from authorization.models import User
from helpers.requests_handler import ConfigurationRequestHandler

conf_req_handler = ConfigurationRequestHandler()


def chk_user_can_be_assigned_account(account_id, site_id, instance_id=None):
    linking_id_mandatory = False
    if account_id:
        account_data = None
        no_of_user_associated_with_account = None
        if instance_id:
            no_of_user_associated_with_account = User.objects.filter(
                account_id=account_id,
                is_active=True
            ).exclude(id=instance_id).count()
        else:
            no_of_user_associated_with_account = User.objects.filter(
                account_id=account_id,
                is_active=True
            ).count()
        account_data = conf_req_handler.get_account_details(
            account_id,
            site_id
        )
        no_of_users_in_account = 0
        if account_data:
            no_of_users_in_account, linking_id_mandatory = account_data['number_of_users'], account_data["linking_id_field"]
        if no_of_user_associated_with_account and (no_of_user_associated_with_account+1) > no_of_users_in_account:
            return False, linking_id_mandatory
    return True, linking_id_mandatory






