from rest_framework import serializers

from order.models import Order


class OrderSerializer(serializers.ModelSerializer):
    products = serializers.ListField(
        child=serializers.CharField(
            min_length=2, max_length=30
        ), required=True
    )

    class Meta:
        model = Order
        fields = '__all__'


class ConfirmOrderSerializer(serializers.Serializer):
    order_id = serializers.IntegerField(
        min_value=0
    )
