#!/bin/false
"""
this file contains useful functions for digital signature.
"""
__author__ = 'J. B. Otterson'
__copyright__ = """
Copyright 2021, J. B. Otterson.
Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice, 
     this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright notice, 
     this list of conditions and the following disclaimer in the documentation 
     and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE 
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import base64

from cryptography import x509
from cryptography.exceptions import InvalidSignature
# noinspection PyProtectedMember
from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey, _RSAPublicKey
from cryptography.hazmat.primitives.serialization import ssh
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization


def create_signature(private_key, data_to_sign):
    """
    create a digital signature, using the private key supplied, of the data supplied
    :param private_key: the RSA private key used to sign the data
    :param data_to_sign: a byte array of data to sign
    :return: the digital signature as a base-64 encoded string
    """
    signature = private_key.sign(data_to_sign,
                                 padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                 hashes.SHA256())
    base64_signature = base64.b64encode(signature).decode('utf-8')
    return base64_signature


def validate_signature(public_key, signature, data_to_validate):
    """
    validate that the data_to_validate is authentic based on the digital signature and the public key used to
    test the signature
    :param public_key: the RSA Public Key used to validate the digital signature
    :param signature: the digital signature to validate
    :param data_to_validate:  the data to validate with the digital signature
    :return: True if the signature matches
    """
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
    """
    read an RSA public key from an SSH key file, like the one that you could create with ssh-keygen
    :param filename: the name of the file to read
    :return: the RSA Public Key
    """
    with open(filename, 'rb') as key_file:
        key = ssh.load_ssh_public_key(key_file.read())
    if isinstance(key, _RSAPublicKey):
        return key
    else:
        raise Exception('{} is not a RSA Public Key'.format(filename))


def read_ssh_private_key(filename):
    """
    read an RSA private key from an SSH key file, like the one that you could create with ssh-keygen
    :param filename: the name of the file to read
    :return: the RSA Private Key
    """
    with open(filename, 'rb') as key_file:
        key = ssh.load_ssh_private_key(key_file.read(), password=b'')
    if isinstance(key, _RSAPrivateKey):
        return key
    else:
        raise Exception('{} is not a RSA Private Key'.format(filename))


def read_rsa_public_key_from_x509_cert(filename):
    """
    read an RSA public key from an X.509 PEM file
    :param filename: the certificate PEM file to read
    :return: an RSA public key
    """
    with open(filename, 'rb') as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read())
    if not isinstance(cert, x509.Certificate):
        raise Exception('{} is not a x509 certificate'.format(filename))
    key = cert.public_key()
    if isinstance(key, _RSAPublicKey):
        return key
    else:
        raise Exception('{} does not contain a RSA public key/'.format(filename))


def read_rsa_private_key(filename):
    """
    read an RSA private key from a PEM file
    :param filename: the name of the PEM file that contains the private key data
    :return: the RSA private key data
    """
    with open(filename, 'rb') as key_file:
        key = serialization.load_pem_private_key(key_file.read(), password=None)
    if isinstance(key, _RSAPrivateKey):
        return key
    else:
        raise Exception('{} is not a RSA Private Key'.format(filename))
