from rest_framework import serializers

from backery_item.models import BackeryIngredients, BackeryItem


class BackeryIngredientsSerializer(serializers.ModelSerializer):
    ingredient_name = serializers.CharField(
        min_length=2,
        max_length=30,
        required=True
    )

    def validate_ingredient_name(self, ingredient_name):
        if BackeryIngredients.objects.filter(
                ingredient_name=ingredient_name).exists():
            raise serializers.ValidationError("Ingredient already saved")
        return ingredient_name

    class Meta:
        model = BackeryIngredients
        fields = "__all__"


class BackeryItemSerializer(serializers.ModelSerializer):
    item_name = serializers.CharField(
        min_length=2,
        max_length=30,
        required=True
    )
    quantity = serializers.IntegerField(
        min_value=0, required=True
    )

    def validate_item_name(self, item_name):
        if BackeryItem.objects.filter(
                item_name=item_name).exists():
            raise serializers.ValidationError("Item already saved")
        return item_name

    def validate_backery_item_ingredient(self, backery_item_ingredient):
        allowed_keys = ['bakery_ingredient', 'quantity_percentage']
        for i in backery_item_ingredient:
            if list(i.keys()) != allowed_keys:
                raise serializers.ValidationError("allowed mandatory keys are bakery_ingredient and quantity_percentage")
            bakey_item = BackeryIngredients.objects.filter(
                ingredient_name=i.get("bakery_ingredient"))
            if not bakey_item:
                raise serializers.ValidationError("%s not available in bakery ingredient" %i.get("bakery_ingredient"))
        return backery_item_ingredient

    class Meta:
        model = BackeryItem
        fields = "__all__"
        swagger_schema_fields = {
            'example': {
                'item_name': "cupcake",
                'quantity': 100,
                'backery_item_ingredient': [
                    {"bakery_ingredient": "sugar", "quantity_percentage": 20},
                    {"bakery_ingredient": "flour", "quantity_percentage": 80}
                ],
                "cp": 80.0,
                "sp": 90.0
            }}


class BakeryInventorySerializer(serializers.Serializer):
    item_name = serializers.CharField(
        min_length=2,
        max_length=30,
        required=True
    )
    quantity = serializers.IntegerField(
        min_value=0,
        required=True
    )


class AvailableItemSerializer(serializers.ModelSerializer):

    class Meta:
        model = BackeryItem
        fields = ('id', 'item_name', 'sp')
