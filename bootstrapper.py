#!/usr/bin/env python3.9
"""
This script generates (bootstraps) a SBOM file from existing data.
This is used to get a quick stake in the ground with a usable SBOM file
for integrity checking.  This should only be done once, then the SBOM file
should be maintained by some other means going forward.
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

import argparse
import logging
import os

import signature_utilities
from spdx_utilities import \
    add_checksum_to_spdx_file, \
    add_signature_to_spdx_document, \
    get_digital_signature_from_spdx_document, \
    new_spdx_doc, \
    new_spdx_file, \
    new_spdx_pkg, \
    read_tv_file, \
    set_spdx_file_type, \
    serialize_spdx_doc, \
    write_tv_file
from validation_utilities import calculate_hash_for_file, files_in_dir

spdx_id_counter = 0


def new_spdx_id():
    global spdx_id_counter
    spdx_id_counter += 1
    return 'SPDXRef-{:06d}'.format(spdx_id_counter)


# noinspection DuplicatedCode
def main():
    parser = argparse.ArgumentParser(description='Bootstrap SBOM file')
    parser.add_argument('--debug', action='store_true', help='output API debug data')
    parser.add_argument('--tvfile', type=str, help='SBOM tag/value filename to write')
    parser.add_argument('--packagepath', type=str, help='path to base of package')
    parser.add_argument('--privatekey', type=str, help='private key for signing SBOM')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(format='%(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)

    if args.packagepath is None:
        logging.error('--packagepath must be supplied')
        exit(1)

    if args.tvfile is None:
        logging.error('--tvfile must be present')
        exit(1)

    if args.privatekey:
        private_key = signature_utilities.read_ssh_private_key(args.privatekey)
    else:
        private_key = None

    if not os.path.isdir(args.packagepath):
        logging.error('packagepath "{}" is not a directory.'.format(args.packagepath))
        exit(1)
    package_path = args.packagepath

    logging.info('Enumerating files...')
    files = files_in_dir(package_path)
    logging.info('Directory enumeration found {} files'.format(len(files)))

    spdx_doc = new_spdx_doc()
    spdx_pkg = new_spdx_pkg(spdx_id=new_spdx_id(), name='BaseApp', version='0.0.0')

    # add all the discovered files to the package.
    for file in files:
        full_path = '{}/{}'.format(package_path, file)
        spdx_file = new_spdx_file(filename=file, spdx_id=new_spdx_id())
        hash_names = ['sha1', 'sha256', 'sha512']
        for hash_name in hash_names:
            hash_value = calculate_hash_for_file(full_path, hash_name)
            add_checksum_to_spdx_file(spdx_file, hash_name.upper(), hash_value)
        set_spdx_file_type(spdx_file, full_path)
        spdx_pkg.add_file(spdx_file)

    # update pkg verification code.
    spdx_pkg.verif_code = spdx_pkg.calc_verif_code()
    spdx_doc.add_package(spdx_pkg)

    # sign the spdx file if the private key was specified
    if private_key:
        signature = signature_utilities.create_signature(private_key,
                                                         serialize_spdx_doc(spdx_doc))
        add_signature_to_spdx_document(spdx_doc, signature)

    # write the spdx file.
    logging.info('Writing file {}'.format(args.tvfile))
    write_tv_file(spdx_doc, args.tvfile)

    # read the spdx file for basic verification
    logging.info('Reading file {}'.format(args.tvfile))
    new_doc = read_tv_file(args.tvfile)

    if True:  # debug
        if args.privatekey:
            public_key = signature_utilities.read_ssh_public_key(args.privatekey + '.pub')
        else:
            public_key = None
        if public_key:
            # validate digital signature on sbom document data
            new_doc_data = serialize_spdx_doc(new_doc)
            signature = get_digital_signature_from_spdx_document(new_doc)
            if not signature_utilities.validate_signature(public_key, signature, new_doc_data):
                logging.error('Digital signature mismatch')
                exit(13)
            else:
                logging.info('Digital signature on SBOM file is good.')
        logging.info('SBOM file contains {} file entries'.format(len(new_doc.packages[0].files)))

    exit(0)


if __name__ == "__main__":
    main()
