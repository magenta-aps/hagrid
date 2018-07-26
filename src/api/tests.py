# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from base64 import (
    b64encode,
    b64decode
)

from django.urls import reverse

from rest_framework.test import APITestCase
from nose_parameterized import parameterized

from api.models.gen import (
    gen_user,
    gen_group,
    gen_key_pair,
    gen_public_key,
    stringify_public_key
)

from api.models import (
    KeyEntry,
    Password
)

from api.models.util import (
    encrypt,
    sign
)


class KeyEntryCreationTest(APITestCase):

    def setUp(self):
        password = 'hagrid'
        self.user = gen_user(password=password)
        self.group = gen_group()
        # Add our user to the group
        self.group.user_set.add(self.user)
        # Prepare our POST url
        self.list_url = reverse('keyentry-list')
        # Log in our user
        logged_in = self.client.login(username=self.user.username,
                                      password=password)
        self.assertTrue(logged_in)
        # Ensure the master key is installed
        from api.apps import ensure_master_key
        self.master_key_object = ensure_master_key()
        # Generate our users key
        self.user_private_key, public_key = gen_key_pair()
        self.user_key_object = gen_public_key(
            user=self.user,
            key=stringify_public_key(public_key)
        )
        self.assertEqual(self.user.public_keys.count(), 1)

    def test_entry_creation(self):
        service_password = str('password1')

        master_password_encrypted = encrypt(self.master_key_object.as_key(), service_password)
        master_signature = sign(self.user_private_key, master_password_encrypted)
        master_password_encoded = b64encode(master_password_encrypted)
        master_signature_encoded = b64encode(master_signature)

        user_password_encrypted = encrypt(self.user_key_object.as_key(), service_password)
        user_signature = sign(self.user_private_key, user_password_encrypted)
        user_password_encoded = b64encode(user_password_encrypted)
        user_signature_encoded = b64encode(user_signature)

        self.assertEqual(KeyEntry.objects.count(), 0)
        self.assertEqual(Password.objects.count(), 0)
        self.assertEqual(self.user_key_object.passwords.count(), 0)
        self.assertEqual(self.master_key_object.passwords.count(), 0)
        response = self.client.post(self.list_url, {
            # Write-only fields (for creating password entries)
            'passwords_write': [
                # The master key user (always included)
                {
                    'key_pk': self.master_key_object.pk,
                    'password': master_password_encoded,
                    'signature': master_signature_encoded,
                },
                # The user in the group (us)
                {
                    'key_pk': self.user_key_object.pk,
                    'password': user_password_encoded,
                    'signature': user_signature_encoded,
                },
            ],
            'signing_key': self.user_key_object.pk,
            # Variables passed directly to KeyEntry
            'owner': self.group.pk,
            'title': 'Bank',
            'username': 'MrRich',
            'url': 'www.bank.com',
            'notes': 'Nothing to see here!',
        })
        self.assertEqual(response.status_code, 201)
        self.assertEqual(KeyEntry.objects.count(), 1)
        self.assertEqual(Password.objects.count(), 2)
        self.assertEqual(self.user_key_object.passwords.count(), 1)
        self.assertEqual(self.master_key_object.passwords.count(), 1)

        self.assertEqual(response.data['title'], 'Bank')
        self.assertEqual(response.data['username'], 'MrRich')
        self.assertEqual(response.data['url'], 'www.bank.com')
        self.assertEqual(response.data['notes'], 'Nothing to see here!')

        key_entry = KeyEntry.objects.first()
        self.assertEqual(key_entry.owner, self.group)
        self.assertEqual(key_entry.title, 'Bank')
        self.assertEqual(key_entry.username, 'MrRich')
        self.assertEqual(key_entry.url, 'www.bank.com')
        self.assertEqual(key_entry.notes, 'Nothing to see here!')
