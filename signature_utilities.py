#!/bin/false
"""
this file contains hopefully useful functions for digital signature.
"""
import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import ssh
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def create_signature(private_key, data_to_sign):
    signature = private_key.sign(data_to_sign,
                                 padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                 hashes.SHA256())
    base64_signature = base64.b64encode(signature).decode('utf-8')
    return base64_signature


def validate_signature(public_key, signature, data_to_validate):
    try:
        signature_binary = base64.b64decode(signature.encode('utf-8'))
        public_key.verify(signature_binary,
                          data_to_validate,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                          hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def read_ssh_public_key(filename):
    with open(filename, 'rb') as key_file:
        return ssh.load_ssh_public_key(key_file.read())


def read_ssh_private_key(filename):
    with open(filename, 'rb') as key_file:
        return ssh.load_ssh_private_key(key_file.read(), password=b'')
