from django.conf.urls import url, include

from rest_framework.routers import DefaultRouter

from . import apis

router = DefaultRouter()
router.register(r"list-transactions", apis.InvoiceListAPIView,
                base_name="list-transactions")
router.register(r"create-order", apis.CreateOrderView,
                base_name="create-order")


urlpatterns = [
    url(r'', include(router.urls)),
    url(r'^confirm-payment/$', apis.ConfirmPayment.as_view(),
        name='confirm-payment'),
]
