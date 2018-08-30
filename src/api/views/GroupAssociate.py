"""API endpoint for Group."""
from __future__ import unicode_literals

from django.db import transaction
from django.contrib.auth.models import Group
from django.contrib.auth import get_user_model

from django_filters.rest_framework import DjangoFilterBackend

from rest_framework import serializers
from rest_framework import viewsets
from rest_framework import mixins

from api.views.User import UserSerializer
from api.models.util import get_lock


# Serializers define the API representation.
class GroupAssociateSerializer(serializers.HyperlinkedModelSerializer):
    """Serializer to associate users with groups."""

    class Meta:
        model = Group
        fields = ['pk', 'user_pk',]

    pk = serializers.PrimaryKeyRelatedField(
        read_only=True,
    )

    user_pk = serializers.PrimaryKeyRelatedField(
        queryset=get_user_model().objects.all(),
        write_only=True,
    )

    def update(self, instance, validated_data):
        # TODO: Check that current user is allowed to add
        with transaction.atomic(savepoint=True):
            # Acquire lock on master key user
            lock = get_lock()
            
            user = validated_data['user_pk']
            # # Get the provided user
            # user = get_user_model().objects.get(pk=validated_data['user_pk'])

            # Check that no passwords exist on the group
            if instance.key_entries.count() != 0:
                raise ValueError("Cannot add to groups with passwords")

            # Add the provided user to the group
            instance.user_set.add(user)

            return instance


# ViewSets define the view behavior.
class GroupAssociateViewSet(mixins.UpdateModelMixin,
                            viewsets.GenericViewSet):
    """
    """
  
    queryset = Group.objects.all()
    serializer_class = GroupAssociateSerializer

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
