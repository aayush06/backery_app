from django.db.models.query import QuerySet


class AccountQueryMixin(object):
    """ account  query mixin """

    def get_user_by_email(self, email):
        """ get user by email id """

        return self.get(email=email)

    def get_user_by_username(self, username):
        """ get user by email id """

        return self.get(username=username)

    def get_user_by_id(self, id):
        """ get user by id """

        return self.get(id=id)


class AccountQuerySet(QuerySet, AccountQueryMixin):
    """ account query set """
    pass
