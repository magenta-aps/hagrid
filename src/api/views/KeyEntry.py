"""API endpoint for KeyEntry."""
# pylint: disable=W9903
# TODO: Do translations wherever required.
from __future__ import unicode_literals
from base64 import b64decode

from django.forms import widgets
from django.db.models import Q
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext as _
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import transaction

from rest_framework import serializers
from rest_framework import viewsets
from rest_framework import mixins

import django_filters
from django_filters.rest_framework import DjangoFilterBackend

from api.models import (
    KeyEntry,
    Password,
    PublicKey
)
from api.views.Password import PasswordSerializer


# Serializers define the API representation.
class KeyEntrySerializer(serializers.HyperlinkedModelSerializer):
    """Serializer to present users (get_user_model())."""

    class Meta:
        model = KeyEntry
        fields = ('__all__')

    owner = serializers.PrimaryKeyRelatedField(
        queryset=Group.objects.all()
    )

    passwords = PasswordSerializer(
        read_only=True,
        many=True
    )

    passwords_write = serializers.ListField(
        child=serializers.DictField(
            child=serializers.CharField()    
        ),
        write_only=True,
    )

    signing_key = serializers.PrimaryKeyRelatedField(
        queryset=PublicKey.objects.all(),
        write_only=True
    )

    def validate(self, data):
        # Get the provided group
        group = data['owner']
        if not isinstance(group, Group):
            group = Group.objects.get(pk=int(group_pk))
        # Get all users we expect passwords provided for; i.e. all users in the
        # provided group and our master user
        from api.models.util import get_master_user
        users = get_user_model().objects.filter(
            Q(groups=group) | Q(pk=get_master_user().pk)
        )
        # Get all public keys corresponding to these users, these are the keys
        # we expect the passwords to be provided under
        public_keys = PublicKey.objects.filter(
            user__in=users
        )

        # List a public key pks to compare to the provided pks
        keyset = set(public_keys.values_list('pk', flat=True))
        passwords = data['passwords_write']
        passwords_keyset = set([int(x['key_pk']) for x in passwords])
        # Error if we have to many or too few entries
        if keyset != passwords_keyset:
            extra = passwords_keyset - keyset
            missing = keyset - passwords_keyset
            raise ValidationError(
                _("Request did not contain required passwords. " + 
                  "Extra keys: " + str(list(extra)) + " "
                  "Missing keys: " + str(list(missing))
                )
            )

        # Get key used to sign the passwords
        signing_key = data['signing_key']
        if not isinstance(signing_key, PublicKey):
            signing_key = PublicKey.objects.get(pk=int(signing_key))
        # Error if the current user isn't the holder of that key
        user = self.context['request'].user
        if signing_key.user != user:
            raise ValidationError(
                _("Signing key does not belong to current user.")
            )

        # Check each entry in the provided passwords
        for dicty in passwords:
            # Check that all members are present
            try:
                key_pk = int(dicty['key_pk'])
                encoded_password = dicty['password']
                encoded_signature = dicty['signature']
            except KeyError as error:
                raise ValidationError(
                    _("'passwords_write' dict(s) missing content: " + str(error))
                )
            
            # Check that the key was expected
            if key_pk not in keyset:
                raise ValidationError(
                    _("Primary key not in expected keyset.")
                )

        return data

    def create(self, validated_data):
        passwords = validated_data['passwords_write']
        signing_key = validated_data['signing_key']
        del validated_data['passwords_write']
        del validated_data['signing_key']
        del validated_data['user']
        with transaction.atomic(savepoint=True):
            keyentry = KeyEntry.objects.create(**validated_data)

            for dicty in passwords:
                key_pk = int(dicty['key_pk'])
                encoded_password = dicty['password']
                encoded_signature = dicty['signature']
                password_object = Password(
                    key_entry=keyentry,
                    public_key=PublicKey.objects.get(pk=key_pk),
                    password=encoded_password,
                    signature=encoded_signature,
                    signing_key=signing_key,
                )
                password_object.full_clean()
                password_object.save()

            return keyentry


# ViewSets define the view behavior.
class KeyEntryViewSet(mixins.CreateModelMixin,
                      mixins.RetrieveModelMixin,
                      mixins.ListModelMixin,
                      mixins.DestroyModelMixin,
                      viewsets.GenericViewSet):
    """
    """

    queryset = KeyEntry.objects.none()
    serializer_class = KeyEntrySerializer

    def get_queryset_raw(self):
        """Filter the queryset for non-admin users.

        Non admin users can only see themself and staff users.
        """
        user = self.request.user
        # If staff, show everything
        if user.is_staff:
            return KeyEntry.objects.all()
        # If user, only show our own passwords
        return KeyEntry.objects.filter(
            Q(passwords__user__pk=user.pk)
        )

    def get_queryset(self):
        queryset = self.get_queryset_raw()
        return queryset.order_by('pk')

    def perform_create(self, serializer):
        # Send from the current user
        serializer.save(
            user=self.request.user,
        )
