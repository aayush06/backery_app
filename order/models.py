from django.db import models
from django.contrib.postgres.fields import JSONField

from authorization.models import User, DatabaseCommonFields


class Order(DatabaseCommonFields):
    user = models.ForeignKey(
        User,
        related_name="user",
        on_delete=models.CASCADE
    )
    products = JSONField(
        default=list
    )
    payment_success = models.BooleanField(
        default=False
    )
    amount = models.FloatField()
    invoice_path = models.FileField(
        upload_to="media/invoice/",
        null=True,
        blank=True
    )
