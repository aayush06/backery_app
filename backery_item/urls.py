from django.conf.urls import url, include
from rest_framework.routers import DefaultRouter

from . import apis

router = DefaultRouter()
router.register(r"backery-ingredient", apis.BackeryIngredientView,
                base_name="backery-ingredient")
router.register(r"backery-item", apis.BackeryItemView,
                base_name="backery-item")
router.register(r"manage-inventory", apis.ManageInventoryView,
                base_name="manage-inventory")
router.register(r"available-products", apis.ListAvailableProducts,
                base_name="available-products")

urlpatterns = [
    url(r'^', include(router.urls)),
]
