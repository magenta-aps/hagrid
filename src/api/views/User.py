"""API endpoint for User."""
from __future__ import unicode_literals

from django.contrib.auth.models import Group
from django.contrib.auth import get_user_model
from django.db import transaction

from rest_framework.permissions import AllowAny
from rest_framework import serializers
from rest_framework import viewsets
from rest_framework import mixins

from api.models import PublicKey
from api.models.util import get_lock


# Serializers define the API representation.
class UserSerializer(serializers.HyperlinkedModelSerializer):
    """Serializer to present users (get_user_model())."""

    class Meta:
        model = get_user_model()
        fields = '__all__'
        fields = ('pk', 'username', 'first_name', 'last_name', 'email',
                  'password', 'public_key',)

    pk = serializers.PrimaryKeyRelatedField(
        read_only=True,
    )

    password = serializers.CharField(
        write_only=True,
    )

    public_key = serializers.CharField(
        write_only=True
    )

    def create(self, validated_data):
        with transaction.atomic(savepoint=True):
            # Acquire lock on master key user
            lock = get_lock()

            # Don't provide public key to user constructor
            public_key_string = validated_data['public_key']
            del validated_data['public_key']

            # Create the user
            user = super(UserSerializer, self).create(validated_data)
            user.set_password(validated_data['password'])
            user.full_clean()
            user.save()

            # Create an identity group
            group = Group(
                name=validated_data['username'],
            )
            group.full_clean()
            group.save()
            # Add our user to the group
            group.user_set.add(user)
            
            # Create the public key object for the user
            public_key = PublicKey(
                user=user,
                key=public_key_string,
            )
            public_key.full_clean()
            public_key.save()
            
            # Return the user
            return user


# ViewSets define the view behavior.
class UserViewSet(mixins.CreateModelMixin,
                  mixins.RetrieveModelMixin,
                  mixins.ListModelMixin,
                  viewsets.GenericViewSet):

    permission_classes = (AllowAny,)

    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer
