from rest_framework import (views, permissions,
                            response, status,
                            viewsets, exceptions)
from rest_framework.viewsets import mixins
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from backery_item.models import BackeryItem
from order.models import Order
from order.serializers import OrderSerializer, ConfirmOrderSerializer
from order.utils.helper import GenerateInvoice

generate_invoice = GenerateInvoice()


class CreateOrderView(mixins.CreateModelMixin,
                      viewsets.GenericViewSet):
    """
        endpoint to create order
    """
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = OrderSerializer
    model = Order
    queryset = Order.objects.all()

    def create(self, request, *args, **kwargs):
        user = request.user
        request.data.update({
            "user": user.id,
            "amount": 0
        })
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            products = serializer.validated_data.get("products")
            amount = 0
            for product_name in products:
                product_obj = BackeryItem.objects.filter(
                    item_name=product_name).first()
                if not product_obj:
                    raise exceptions.ValidationError("%s not a valid item" % product_name)
                amount += product_obj.sp
            obj = serializer.save()
            obj.amount = amount
            obj.save()
            return response.Response(
                {"id": obj.id},
                status=status.HTTP_201_CREATED
            )
        else:
            return response.Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )


class ConfirmPayment(views.APIView):
    permission_classes = (permissions.IsAuthenticated,)
    model = Order
    serializer_class = ConfirmOrderSerializer

    @swagger_auto_schema(operation_id="confirm user payment",
                         request_body=openapi.Schema(
                             type=openapi.TYPE_OBJECT,
                             properties={
                                 'order_id': openapi.Schema(type=openapi.TYPE_INTEGER, description='order_id')
                             }
                         ))
    def post(self, request, *args, **kwargs):
        user = request.user
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            order_obj = self.model.objects.filter(
                id=serializer.validated_data.get("order_id")).first()
            if order_obj:
                order_obj.payment_success = True
                order_obj.save()
                ctx = {
                    'user_fullname': (user.first_name+' '+user.last_name) if user.last_name else user.first_name,
                    'user_email': user.email,
                    'products': ', '.join(i for i in order_obj.products),
                    'amount': order_obj.amount
                }
                generate_invoice.generate_pdf_invoice(order_obj,
                                                      request.build_absolute_uri(),
                                                      **ctx)
                order_obj = self.model.objects.filter(id=order_obj.id).first()
                return response.Response(
                    {"msg": "payment confirmed"},
                    status=status.HTTP_200_OK
                )
            else:
                raise exceptions.ValidationError("Provide valid order id")
        else:
            return response.Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )


class InvoiceListAPIView(mixins.ListModelMixin, viewsets.GenericViewSet):
    """
        endpoint to view invoices for payments/transactions
    """
    permission_classes = (permissions.IsAuthenticated,)
    model = Order
    serializer_class = OrderSerializer

    def get_queryset(self):
        user = self.request.user
        queryset = self.model.objects.filter(user=user).order_by('-created_on')
        return queryset
