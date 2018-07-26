from django.contrib.auth import get_user_model

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature



MAX_LENGTH_NUMBER=2000

def parse_key(key):
    return serialization.load_ssh_public_key(
        key,
        backend=default_backend()
    )


def get_master_user():
    # Ensure our master key user exists
    user, created = get_user_model().objects.get_or_create(
        username='masterkey',
        defaults={
            'password': 'masterpass'
        }
    )
    # If just created, ensure password is unusable
    if created:
        user.set_unusable_password()
        user.save()

    return user


def get_lock():
    lock = get_user_model().objects.select_for_update().filter(
        username='masterkey'
    )
    return lock


def encrypt(public_key, message):
    cipher = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher


def decrypt(private_key, ciphertext):
    plain = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plain


def sign(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


