from rest_framework import serializers


class CustomEmailSerializerField(serializers.EmailField):

    def to_internal_value(self, value):
        value = super(CustomEmailSerializerField,
                      self).to_internal_value(value)
        return value.lower()
