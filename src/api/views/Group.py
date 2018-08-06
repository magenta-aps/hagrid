"""API endpoint for Group."""
from __future__ import unicode_literals

from django.contrib.auth.models import Group

from rest_framework import serializers
from rest_framework import viewsets

from api.views.User import UserSerializer


# Serializers define the API representation.
class GroupSerializer(serializers.HyperlinkedModelSerializer):
    """Serializer to present groups."""

    class Meta:
        model = Group
        fields = '__all__'

    pk = serializers.PrimaryKeyRelatedField(
        read_only=True,
    )

    user_set = UserSerializer(
        many=True,
        read_only=True
    )


# ViewSets define the view behavior.
class GroupViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
