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

from django.contrib.auth.models import Group
from api.models import (
    KeyEntry,
    Password,
    PublicKey
)
from api.views.Password import PasswordSerializer
from api.views.Group import GroupSerializer
from api.models.util import get_lock


# Serializers define the API representation.
class KeyEntrySerializer(serializers.HyperlinkedModelSerializer):
    """Serializer to present users (get_user_model())."""

    class Meta:
        model = KeyEntry
        fields = ('__all__')

    pk = serializers.PrimaryKeyRelatedField(
        read_only=True,
    )

    owner = GroupSerializer(
        read_only=True,
    )

    owner_write = serializers.PrimaryKeyRelatedField(
        queryset=Group.objects.all(),
        write_only=True
    )

    passwords = PasswordSerializer(
        many=True,
        read_only=True,
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

    def check_password_dict(self, group, password_write):
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
        passwords = password_write
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
        return keyset

    def check_password_dict_entry(self, entry, keyset):
        # Check that all members are present
        try:
            key_pk = int(entry['key_pk'])
            encoded_password = entry['password']
            encoded_signature = entry['signature']
        except KeyError as error:
            raise ValidationError(
                _("'passwords_write' dict(s) missing content: " + str(error))
            )

        # Check that the key was expected
        if key_pk not in keyset:
            raise ValidationError(
                _("Primary key not in expected keyset.")
            )

        return key_pk, encoded_password, encoded_signature

    def check_signing_key(self, signing_key):
        # Error if the current user isn't the holder of that key
        user = self.context['request'].user
        if signing_key.user != user:
            raise ValidationError(
                _("Signing key does not belong to current user.")
            )

    def create(self, validated_data):
        owner = validated_data['owner_write']
        passwords = validated_data['passwords_write']
        signing_key = validated_data['signing_key']
        del validated_data['owner_write']
        del validated_data['passwords_write']
        del validated_data['signing_key']
        del validated_data['user']
        validated_data['owner'] = owner
        with transaction.atomic(savepoint=True):
            # Acquire lock on master key user
            lock = get_lock()
            # Validate our password dict looks good
            keyset = self.check_password_dict(owner, passwords)
            self.check_signing_key(signing_key)
            # Create our key entry object
            keyentry = KeyEntry.objects.create(**validated_data)
            for entry in passwords:
                key_pk, encoded_password, encoded_signature = self.check_password_dict_entry(entry, keyset)

                password_object = Password(
                    key_entry=keyentry,
                    public_key=PublicKey.objects.get(pk=key_pk),
                    password=encoded_password,
                    signature=encoded_signature,
                    signing_key=signing_key,
                )
                password_object.full_clean()
                password_object.save()

            keyentry.check_passwords()

            return keyentry

    def update(self, instance, validated_data):
        owner = instance.owner
        passwords = validated_data['passwords_write']
        signing_key = validated_data['signing_key']
        with transaction.atomic(savepoint=True):
            # Acquire lock on master key user
            lock = get_lock()
            # Validate our password dict looks good
            keyset = self.check_password_dict(owner, passwords)
            self.check_signing_key(signing_key)
            # Get our key entry object
            keyentry = instance
            for entry in passwords:
                key_pk, encoded_password, encoded_signature = self.check_password_dict_entry(entry, keyset)
                # Get the corresponding password entry
                password_object = keyentry.passwords.get(
                    public_key=PublicKey.objects.get(pk=key_pk)
                )
                password_object.password=encoded_password
                password_object.signature=encoded_signature
                password_object.signing_key=signing_key
                password_object.full_clean()
                password_object.save()
            keyentry.check_passwords()

            return keyentry


# ViewSets define the view behavior.
class KeyEntryViewSet(mixins.CreateModelMixin,
                      mixins.RetrieveModelMixin,
                      mixins.UpdateModelMixin,
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
            Q(passwords__public_key__user=user)
        )

    def get_queryset(self):
        queryset = self.get_queryset_raw()
        return queryset.order_by('pk')

    def perform_create(self, serializer):
        # Send from the current user
        serializer.save(
            user=self.request.user,
        )
