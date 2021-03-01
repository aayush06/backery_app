from django.contrib.postgres.fields import JSONField
from django.db import models

from authorization.models import DatabaseCommonFields


class BackeryIngredients(DatabaseCommonFields):
    ingredient_name = models.CharField(
        max_length=30,
        unique=True
    )


class BackeryItem(DatabaseCommonFields):
    item_name = models.CharField(
        max_length=30,
        unique=True
    )
    quantity = models.PositiveIntegerField(
        null=True, blank=True
    )
    backery_item_ingredient = JSONField(
        default=dict
    )
    cp = models.FloatField(
        null=True, blank=True
    )
    sp = models.FloatField(
        null=True, blank=True
    )
