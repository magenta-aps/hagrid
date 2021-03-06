"""API endpoint for Group."""
from __future__ import unicode_literals

from django.db import transaction
from django.contrib.auth.models import Group

from django_filters.rest_framework import DjangoFilterBackend

from rest_framework import serializers
from rest_framework import viewsets
from rest_framework import mixins

from api.views.User import UserSerializer
from api.models.util import get_lock


# Serializers define the API representation.
class GroupSerializer(serializers.HyperlinkedModelSerializer):
    """Serializer to present groups."""

    class Meta:
        model = Group
        exclude = ['permissions',]

    pk = serializers.PrimaryKeyRelatedField(
        read_only=True,
    )

    user_set = UserSerializer(
        many=True,
        read_only=True
    )

    def create(self, validated_data):
        user = self.context['request'].user
        with transaction.atomic(savepoint=True):
            # Acquire lock on master key user
            lock = get_lock()

            # Create a group
            group = Group(
                name=validated_data['name'],
            )
            group.full_clean()
            group.save()
            # Add the current user to the group
            group.user_set.add(user)

            return group


# ViewSets define the view behavior.
class GroupViewSet(mixins.CreateModelMixin,
                  mixins.RetrieveModelMixin,
                  mixins.ListModelMixin,
                  viewsets.GenericViewSet):

    queryset = Group.objects.all()
    serializer_class = GroupSerializer

    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('name',)

    def get_queryset_raw(self):
        """Filter the queryset for non-admin users.

        Non admin users can only see themself and staff users.
        """
        user = self.request.user
        # If staff, show everything
        if user.is_staff:
            return Group.objects.all()
        # If user, only show our own passwords
        return Group.objects.filter(
            user=user
        )

    def get_queryset(self):
        queryset = self.get_queryset_raw()
        return queryset.order_by('pk')

    def perform_create(self, serializer):
        # Send from the current user
        serializer.save(
            user=self.request.user,
        )
