"""API endpoint for Password."""
# pylint: disable=W9903
# TODO: Do translations wherever required.
from __future__ import unicode_literals

from django.forms import widgets
from django.db.models import Q

from django_filters.rest_framework import DjangoFilterBackend

from rest_framework import serializers
from rest_framework import viewsets

from api.models import Password
from api.views.PublicKey import PublicKeySerializer


# Serializers define the API representation.
class PasswordSerializer(serializers.HyperlinkedModelSerializer):
    """Serializer to present users (get_user_model())."""

    class Meta:
        model = Password
        fields = ('__all__')

    signing_key = PublicKeySerializer(
        read_only=True
    )

    public_key = PublicKeySerializer(
        read_only=True
    )


# ViewSets define the view behavior.
class PasswordViewSet(viewsets.ReadOnlyModelViewSet):
    """Get a list of all passwords visible to the current user.

    If the current user is staff, all users are visible.

    If the current user is in applicant, only their own user and staff users
    are visible.

    Note: Should not be accessed directly, but rather indirectly via. the links
    provided in messages.
    """

    queryset = Password.objects.none()
    serializer_class = PasswordSerializer

    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('key_entry', 'public_key',)

    def get_queryset_raw(self):
        """Filter the queryset for non-admin users.

        Non admin users can only see themself and staff users.
        """
        user = self.request.user
        # If staff, show everything
        if user.is_staff:
            return Password.objects.all()
        # If user, only show our own passwords
        return Password.objects.filter(
            Q(public_key__user__pk=user.pk)
        )

    def get_queryset(self):
        queryset = self.get_queryset_raw()
        return queryset.order_by('pk')
