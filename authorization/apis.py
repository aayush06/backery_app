from rest_framework import (generics, permissions,
                            response, status)

from authorization.serializers import (LoginSerializer,
                                       RegistrationSerializer,
                                       BackeryAdminRegistrationSerializer)


class LoginView(generics.GenericAPIView):
    """ Endpoint for the user login """

    permission_classes = (permissions.AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request, *args, **kargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.user
            response_dict = dict()
            auth_token = user.get_jwt_token_for_user()
            response_dict["auth_token"] = auth_token
            response_dict["is_bakery_admin"] = user.is_bakery_admin
            response_dict["id"] = user.id
            response_dict["last_login"] = user.last_login
            return response.Response(
                data=response_dict,
                status=status.HTTP_200_OK,
            )


class UserRegistrationView(generics.CreateAPIView):
    """ endpoint to register user """

    permission_classes = (permissions.AllowAny,)
    serializer_class = RegistrationSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            user.set_password(serializer.validated_data.get("password"))
            user.save()
            return response.Response(
                serializer.data,
                status=status.HTTP_201_CREATED,
            )
        else:
            return response.Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )


class BackeryAdminRegistrationView(generics.CreateAPIView):
    """ endpoint to register user """

    permission_classes = (permissions.AllowAny,)
    serializer_class = BackeryAdminRegistrationSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            return response.Response(
                serializer.data,
                status=status.HTTP_201_CREATED,
            )
        else:
            return response.Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
