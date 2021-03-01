from rest_framework import (permissions, response, status,
                            viewsets, exceptions)
from rest_framework.viewsets import mixins

from backery_item.models import BackeryIngredients, BackeryItem
from backery_item.serializers import (BackeryIngredientsSerializer,
                                      BackeryItemSerializer,
                                      BakeryInventorySerializer,
                                      AvailableItemSerializer)

from helpers.permissions import AdminOnly


class BackeryIngredientView(viewsets.ModelViewSet):
    """ Endpoint for backery ingredients """
    http_method_names = ["get", "post"]
    permission_classes = (permissions.IsAuthenticated, AdminOnly)
    model = BackeryIngredients
    serializer_class = BackeryIngredientsSerializer
    queryset = BackeryIngredients.objects.all()


class BackeryItemView(viewsets.ModelViewSet):
    """ Endpoint for backery item """
    http_method_names = ["get", "post"]
    permission_classes = (permissions.IsAuthenticated, AdminOnly)
    model = BackeryItem
    serializer_class = BackeryItemSerializer
    queryset = BackeryItem.objects.all()

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return response.Response(
                serializer.data,
                status=status.HTTP_201_CREATED
            )
        else:
            return response.Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )


class ManageInventoryView(viewsets.ModelViewSet):
    """ Endpoint for inventory management """
    http_method_names = ["post"]
    permission_classes = (permissions.IsAuthenticated, AdminOnly)
    model = BackeryItem
    serializer_class = BakeryInventorySerializer
    queryset = BackeryItem.objects.all()

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            data = serializer.validated_data
            item_obj = self.model.objects.filter(item_name=data.get("item_name")).first()
            if item_obj:
                item_obj.quantity = data.get("quantity")
                item_obj.save()
            else:
                raise exceptions.ValidationError("Enter valid item_name")
            return response.Response(
                {"msg": "Inventory updated"},
                status=status.HTTP_200_OK
            )
        else:
            return response.Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )


class ListAvailableProducts(mixins.ListModelMixin,
                            viewsets.GenericViewSet):
    permission_classes = (permissions.IsAuthenticated, )
    model = BackeryItem
    serializer_class = AvailableItemSerializer
    queryset = BackeryItem.objects.filter(quantity__gt=0)
