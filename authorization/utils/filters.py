from django_filters import rest_framework as filters_rest
from django.db.models import Case, When
from django.db.models import Q
from authorization.models import User, Role


class UserFilter(filters_rest.FilterSet):
    is_active = filters_rest.BooleanFilter(method="filter_is_active")
    poi_id = filters_rest.NumberFilter(method="filter_poi_id")
    account_id = filters_rest.NumberFilter(method="filter_account_id")
    team_id = filters_rest.CharFilter(method="filter_team_id")
    assigned_team = filters_rest.BooleanFilter(method="filter_assigned_team")
    user_id = filters_rest.CharFilter(method="filter_user_id")
    role_id = filters_rest.CharFilter(method="filter_role_id")
    role_name = filters_rest.CharFilter(method="filter_role_name")
    username = filters_rest.CharFilter(method="filter_username")
    site_id = filters_rest.CharFilter(method="filter_site_id")
    hidden_on_scheduler = filters_rest.BooleanFilter(
        method="filter_hidden_on_scheduler")
    has_linking_id = filters_rest.BooleanFilter(
        method="filter_has_linking_id")

    class Meta:
        model = User
        fields = [
            "is_active", "poi_id", "account_id", "team",
            "role", "site_id"]

    def filter_has_linking_id(self, queryset, name, has_linking_id):
        if has_linking_id in [True, False]:
            if has_linking_id:
                return queryset.filter(Q(
                    linking_id__isnull=False) & ~Q(
                        linking_id=''
                    ))
            else:
                return queryset.filter(Q(
                    linking_id__isnull=True) | Q(
                        linking_id=''
                    ))

    def filter_hidden_on_scheduler(self, queryset, name, hidden_on_scheduler):
        if hidden_on_scheduler in [True, False]:
            if hidden_on_scheduler:
                return queryset.filter(hidden_on_scheduler=True)
            else:
                return queryset.filter(hidden_on_scheduler=False)

    def filter_site_id(self, queryset, name, site_id):
        return queryset.filter(Q(site_id=site_id) |
                               Q(site_id=0))

    def filter_user_id(self, queryset, name, user_id):
        if user_id:
            user_id = [int(i) for i in user_id.split(',')]
            preserved = Case(*[When(pk=pk, then=pos)
                               for pos, pk in enumerate(user_id)])
            return queryset.filter(id__in=user_id).order_by(preserved)

    def filter_role_id(self, queryset, name, role_id):
        if role_id:
            role_id = [int(i) for i in role_id.split(',')]
            preserved = Case(*[When(pk=pk, then=pos)
                               for pos, pk in enumerate(role_id)])
            return queryset.filter(role__id__in=role_id).order_by(preserved)

    def filter_username(self, queryset, name, username):
        if username:
            username = [i for i in username.split(',')]
            preserved = Case(*[When(username=pk, then=pos)
                               for pos, pk in enumerate(username)])
            return queryset.filter(
                username__in=username).order_by(preserved)

    def filter_role_name(self, queryset, name, role_name):
        if role_name:
            return queryset.filter(role__role_name__iexact=role_name)

    def filter_team_id(self, queryset, name, team_id):
        team_ids = team_id.split(",")
        team_ids = list(map(int, team_ids))
        queryset = queryset.filter(team__in=team_ids)
        return queryset.distinct()

    def filter_assigned_team(self, queryset, name, assigned_team):
        if assigned_team:
            return queryset.filter(team__isnull=False)
        else:
            return queryset.filter(team__isnull=True)

    def filter_is_active(self, queryset, name, is_active):
        if is_active:
            return queryset.filter(is_active=True)
        else:
            return queryset.filter(is_active=False)

    def filter_poi_id(self, queryset, name, poi_id):
        return queryset.filter(poi_id=poi_id)

    def filter_account_id(self, queryset, name, account_id):
        return queryset.filter(account_id=account_id)


class RoleFilter(filters_rest.FilterSet):
    is_active = filters_rest.BooleanFilter(method="filter_is_active")
    role_id = filters_rest.CharFilter(method="filter_role_id")
    lower_importance = filters_rest.BooleanFilter(method="filter_lower_importance")
    site_id = filters_rest.CharFilter(method="filter_site_id")
    role_name = filters_rest.CharFilter(method="filter_role_name")

    class Meta:
        model = Role
        fields = ['is_active', 'site_id']

    def filter_site_id(self, queryset, name, site_id):
        return queryset.filter(Q(site_id=site_id) |
                               Q(site_id=0))

    def filter_role_id(self, queryset, name, role_id):
        if role_id:
            role_id = [int(i) for i in role_id.split(',')]
            return queryset.filter(id__in=role_id)

    def filter_is_active(self, queryset, name, is_active):
        if is_active:
            return queryset.filter(is_active=True)
        else:
            return queryset.filter(is_active=False)

    def filter_lower_importance(self, queryset, name, lower_importance):
        if lower_importance:
            if self.request.user.role:
                return queryset.filter(
                    role_importance__gte=self.request.user.role.role_importance
                )
        return queryset

    def filter_role_name(self, queryset, name, role_name):
        if role_name:
            return queryset.filter(role_name=role_name)


class UserByTeamFilterClass(filters_rest.FilterSet):
    team = filters_rest.CharFilter(method="filter_by_team")

    class Meta:
        model = User
        fields = ['team', 'account_id']

    def filter_by_team(self, queryset, name, team):
        team_list = team.split(",")
        team_list = list(map(int, team_list))
        return queryset.filter(team__in=team_list).distinct()
