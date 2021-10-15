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
import hashlib
import logging
import os
from zipfile import ZipFile

import signature_utilities
from spdx_utilities import \
    add_checksum_to_spdx_file, \
    add_signature_to_spdx_document, \
    get_digital_signature_from_spdx_document, \
    guess_spdx_file_type_from_data, \
    guess_spdx_file_type_from_extension, \
    new_spdx_doc, \
    new_spdx_file, \
    new_spdx_pkg, \
    read_sbom_file, \
    set_spdx_file_type, \
    serialize_spdx_doc, \
    write_sbom_file
from validation_utilities import calculate_hash_for_file, files_in_dir

spdx_id_counter = 0


def new_spdx_id():
    global spdx_id_counter
    spdx_id_counter += 1
    return 'SPDXRef-{:06d}'.format(spdx_id_counter)


def package_path_to_spdx_doc(args):
    package_path = args.package_path
    spdx_doc = new_spdx_doc(toolname='create-sbom.py')
    package_name = package_path
    if package_name[-1] == '/':
        package_name = package_name[0:-1]
    _, package_name = os.path.split(package_name)
    spdx_pkg = new_spdx_pkg(spdx_id=new_spdx_id(), name='Example', version='0.0.0', file_name=package_name)

    logging.info('Enumerating files at {}...'.format(package_path))
    files = files_in_dir(package_path)
    logging.info('Directory enumeration found {} files'.format(len(files)))
    # add all the discovered files to the package.
    for file in files:
        full_path = '{}/{}'.format(package_path, file)
        if args.flat:
            _, file = os.path.split(file)
        spdx_file = new_spdx_file(filename=file, spdx_id=new_spdx_id())
        if args.file_comment is not None:
            spdx_file.comment = args.file_comment
        hash_names = ['sha1', 'sha256', 'sha512']
        for hash_name in hash_names:
            hash_value = calculate_hash_for_file(full_path, hash_name)
            add_checksum_to_spdx_file(spdx_file, hash_name.upper(), hash_value)
        set_spdx_file_type(spdx_file, full_path)
        spdx_pkg.add_file(spdx_file)

    # update pkg verification code.
    spdx_pkg.verif_code = spdx_pkg.calc_verif_code()
    spdx_doc.add_package(spdx_pkg)
    return spdx_doc


def package_zip_to_spdx_doc(args):
    package_zip = args.package_zip
    spdx_doc = new_spdx_doc(toolname='create-sbom.py')
    _, package_name = os.path.split(package_zip)
    spdx_pkg = new_spdx_pkg(spdx_id=new_spdx_id(), name=package_name, version='0.0.0', file_name=package_name)
    logging.info('Enumerating files in {}...'.format(package_zip))
    with ZipFile(package_zip, 'r') as zipfile:
        namelist = zipfile.namelist()
        files = list(filter(lambda name: not name.endswith('/'), namelist))
        logging.info('Zipfile contains {} files'.format(len(files)))
        for file in files:
            if args.flat:
                _, filename = os.path.split(file)
            else:
                filename = file
            filename = './' + filename
            spdx_file = new_spdx_file(filename=filename, spdx_id=new_spdx_id())
            if args.file_comment is not None:
                spdx_file.comment = args.comment
            data = zipfile.read(file)
            hash_names = ['sha1', 'sha256', 'sha512']
            for hash_name in hash_names:
                hasher = hashlib.new(hash_name)
                hasher.update(data)
                add_checksum_to_spdx_file(spdx_file, hash_name.upper(), hasher.hexdigest())
            spdx_file_types = guess_spdx_file_type_from_extension(file)
            if spdx_file_types is None:
                spdx_file_types = guess_spdx_file_type_from_data(data)
            if spdx_file_types is None or len(spdx_file_types) == 0:
                logging.error('bad... {}'.format(file))
            spdx_file.file_types = spdx_file_types
            spdx_pkg.add_file(spdx_file)

    # update pkg verification code.
    spdx_pkg.verif_code = spdx_pkg.calc_verif_code()
    spdx_doc.add_package(spdx_pkg)
    return spdx_doc


# noinspection DuplicatedCode
def main():
    parser = argparse.ArgumentParser(description='Bootstrap SBOM file')
    parser.add_argument('--debug', action='store_true', help='output API debug data')
    parser.add_argument('--file-comment', type=str, help='file comment to apply to all files')
    parser.add_argument('--flat', action='store_true', help='do not save pathnames, only file names')
    parser.add_argument('--sbom-file', type=str, help='SBOM tag/value filename to write')
    parser.add_argument('--package-path', type=str, help='path to base of package')
    parser.add_argument('--package-zip', type=str, help='path to package zipfile')
    parser.add_argument('--private-key', type=str, help='private key for signing SBOM')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(format='%(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)

    if args.package_path is None and args.package_zip is None:
        logging.error('--package-path or --package-zip must be supplied')
        exit(1)

    if args.package_path is not None and args.package_zip is not None:
        logging.error('only one of --package-path or --package-zip must be supplied')
        exit(1)

    if args.sbom_file is None:
        logging.error('--sbom-file must be specified')
        exit(1)

    if args.private_key:
        private_key = signature_utilities.read_ssh_private_key(args.private_key)
    else:
        private_key = None

    spdx_doc = None

    if args.package_path is not None:
        if not os.path.isdir(args.package_path):
            logging.error('package-path "{}" is not a directory.'.format(args.package_path))
            exit(1)
        spdx_doc = package_path_to_spdx_doc(args)

    if args.package_zip is not None:
        if not os.path.exists(args.package_zip):
            logging.error('package-zip {} not found'.format(args.package_zip))
            exit(1)
        spdx_doc = package_zip_to_spdx_doc(args)

    # sign the spdx file if the private key was specified
    if private_key:
        signature = signature_utilities.create_signature(private_key,
                                                         serialize_spdx_doc(spdx_doc))
        add_signature_to_spdx_document(spdx_doc, signature)

    # write the spdx file.
    logging.info('Writing file {}'.format(args.sbom_file))
    write_sbom_file(spdx_doc, args.sbom_file)

    # read the spdx file for basic verification
    logging.info('Reading file {}'.format(args.sbom_file))
    new_doc = read_sbom_file(args.sbom_file)

    if True:  # debug
        if args.private_key:
            public_key = signature_utilities.read_ssh_public_key(args.private_key + '.pub')
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
