#!/usr/bin/env python3.9
"""
validate-sbom.py -- this script compares a SBOM file with application files on disk.
it will report missing files, additional files, and hash mismatches for matching files.
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
from spdx_tools.spdx.model.checksum import ChecksumAlgorithm, Checksum
from spdx_tools.spdx.model.file import FileType

import signature_utilities
import spdx_utilities
import validation_utilities


def validate_package_path(package_path, sbom_files):
    """
    validate a package installed on disk.
    :param package_path: the path to the package files
    :param sbom_files: a list of SBOM files to compare to
    :return: True if package passes integrity verification.
    """
    logging.info('Enumerating files in {}...'.format(package_path))
    files = validation_utilities.files_in_dir(package_path)
    logging.info('Directory enumeration found {} files'.format(len(files)))

    sbom_file_name_map = {}
    sbom_spdxid_map = {}
    for sbom_file in sbom_files:
        sbom_file_name_map[sbom_file.name] = {'sbom_file': sbom_file, 'found_on_disk': False}
        sbom_spdxid_map[sbom_file.spdx_id] = sbom_file

    files_on_disk = {}
    for file in files:
        sbom_file_dict = sbom_file_name_map.get(file)
        if sbom_file_dict is not None:
            sbom_file_dict['found_on_disk'] = True
            files_on_disk[file] = {'sbom_file': sbom_file_dict.get('sbom_file'),
                                   'found_in_sbom': True}
        else:
            files_on_disk[file] = {'sbom_file': None,
                                   'found_in_sbom': False}  # department of redundancy department.

    # detect missing files
    missing_files = 0
    for file, file_dict in sbom_file_name_map.items():
        if not file_dict.get('found_on_disk'):
            logging.warning('Missing file! File {} was not found on disk.'.format(file))
            missing_files += 1
    # detect extra files
    extra_files = 0
    for file, file_dict in files_on_disk.items():
        if not file_dict.get('found_in_sbom'):
            logging.info('Extra file!   File {} was not found in the SBOM.'.format(file))
            extra_files += 1

    # now compare checksums for all files that are both on disk and in the SBOM.
    mismatched_files = 0
    unchecked_files = 0
    hash_algorithm = 'SHA256'
    for file, file_dict in files_on_disk.items():
        if file_dict.get('found_in_sbom'):
            sbom_file = file_dict.get('sbom_file')
            if FileType.APPLICATION in sbom_file.file_types:
                checksums = sbom_file.chk_sums
                # get checksum hash value from the SBOM
                sbom_file_hash_value = None
                for chk_sum in checksums:
                    if chk_sum.identifier.lower() == hash_algorithm:
                        sbom_file_hash_value = chk_sum.value
                if sbom_file_hash_value is None:
                    logging.error('Cannot get {} hash value for file {}.'.format(hash_algorithm, file))
                    exit(1)
                disk_file_hash_value = validation_utilities.calculate_hash_for_file('{}/{}'.format(package_path,
                                                                                                   file),
                                                                                    hash_algorithm)
                # now compare the hashes
                if sbom_file_hash_value != disk_file_hash_value:
                    # danger will robinson!
                    logging.warning('Checksum mismatch!' +
                                    ' File {} {} checksum does not match the SBOM'.format(file, hash_algorithm))
                    mismatched_files += 1
            else:
                unchecked_files += 1

    if unchecked_files != 0:
        logging.info('{} file(s) were excluded from checksum matching.'.format(unchecked_files))

    if missing_files != 0 or extra_files != 0 or mismatched_files != 0:
        logging.warning('Package fails integrity testing.')
        return False

    logging.info('Package integrity appears OK.')
    return True


def validate_package_zip(package_zip, sbom_files):
    """
    validate a package that is contained in a zip file.
    :param package_zip: the path to the package zip file
    :param sbom_files: a list of SBOM files to compare to
    :return: True if package passes integrity verification.
    """
    logging.info('Enumerating files in {}...'.format(package_zip))
    with ZipFile(package_zip, 'r') as zipfile:
        namelist = zipfile.namelist()
        files = list(filter(lambda name: not name.endswith('/'), namelist))
        logging.info('Zipfile contains {} files'.format(len(files)))

        sbom_file_name_map = {}
        sbom_spdxid_map = {}
        for sbom_file in sbom_files:
            sbom_file_name_map[sbom_file.name] = {'sbom_file': sbom_file, 'found_on_disk': False}
            sbom_spdxid_map[sbom_file.spdx_id] = sbom_file

        files_on_disk = {}
        for file in files:
            sbom_file_name = './' + file
            sbom_file_dict = sbom_file_name_map.get(sbom_file_name)
            if sbom_file_dict is not None:
                sbom_file_dict['found_on_disk'] = True
                files_on_disk[file] = {'sbom_file': sbom_file_dict.get('sbom_file'),
                                       'found_in_sbom': True}
            else:
                files_on_disk[file] = {'sbom_file': None,
                                       'found_in_sbom': False}  # department of redundancy department.

        # detect missing files
        missing_files = 0
        for file, file_dict in sbom_file_name_map.items():
            if not file_dict.get('found_on_disk'):
                logging.warning('Missing file! File {} was not found on disk.'.format(file))
                missing_files += 1
        # detect extra files
        extra_files = 0
        for file, file_dict in files_on_disk.items():
            if not file_dict.get('found_in_sbom'):
                logging.info('Extra file!   File {} was not found in the SBOM.'.format(file))
                extra_files += 1

        # now compare checksums for all files that are both on disk and in the SBOM.
        mismatched_files = 0
        unchecked_files = 0
        hash_algorithm = ChecksumAlgorithm.SHA256

        hash_algorithm_name = str(hash_algorithm).split('.')[1].lower()
        for file, file_dict in files_on_disk.items():
            if file_dict.get('found_in_sbom'):
                sbom_file = file_dict.get('sbom_file')
                if FileType.APPLICATION in sbom_file.file_types:
                    # get checksum hash value from the SBOM
                    checksum = spdx_utilities.get_specified_checksum(sbom_file.checksums, hash_algorithm)
                    sbom_file_hash_value = None if checksum is None else checksum.value
                    if sbom_file_hash_value is None:
                        logging.error('Cannot get {} hash value for file {}.'.format(hash_algorithm_name, file))
                        exit(1)
                    hasher = hashlib.new(hash_algorithm_name)
                    data = zipfile.read(file)
                    hasher.update(data)
                    disk_file_hash_value = hasher.hexdigest()
                    # now compare the hashes
                    if sbom_file_hash_value != disk_file_hash_value:
                        # danger will robinson!
                        logging.warning('Checksum mismatch! ' +
                                        'File {} {} checksum does not match the SBOM'.format(file, hash_algorithm_name))
                        mismatched_files += 1
            else:
                unchecked_files += 1

        if unchecked_files != 0:
            logging.info('{} file(s) were excluded from checksum matching.'.format(unchecked_files))

        if missing_files != 0 or extra_files != 0 or mismatched_files != 0:
            logging.warning('Package fails integrity testing.')
            return False

        logging.info('Package integrity appears OK.')
        return True


# noinspection DuplicatedCode
def main():
    parser = argparse.ArgumentParser(description='Validate File Contents with SBOM file')
    parser.add_argument('--debug', action='store_true', help='show logging informational output')
    parser.add_argument('--info', action='store_true', help='show informational diagnostic output')
    parser.add_argument('--sbom-file', type=str, help='SBOM tag/value filename to write')
    parser.add_argument('--package-path', type=str, help='path to base of package')
    parser.add_argument('--package-zip', type=str, help='path to package zipfile')
    parser.add_argument('--public-key', type=str, help='path to rsa public key used for digital signature validation')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.DEBUG)
    elif args.info:
        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)
    else:
        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.WARNING)

    if args.package_path is None and args.package_zip is None:
        logging.error('--package-path or --package-zip must be supplied')
        exit(1)

    if args.package_path is not None and args.package_zip is not None:
        logging.error('only one of --package-path or --package-zip must be supplied')
        exit(1)

    if args.sbom_file is None:
        logging.error('--sbom-file must be present')
        exit(1)

    if args.package_path is not None:
        if not os.path.isdir(args.package_path):
            logging.error('package-path "{}" is not a directory.'.format(args.package_path))
            exit(1)
        package_path = args.package_path
    else:
        package_path = None

    if args.package_zip is not None:
        if not os.path.exists(args.package_zip):
            logging.error('package-zip {} not found'.format(args.package_zip))
            exit(1)
        package_zip = args.package_zip
    else:
        package_zip = None

    if args.public_key is not None:
        public_key = signature_utilities.read_ssh_public_key(args.public_key)
    else:
        public_key = None

    # read the spdx file that will be used for validation
    logging.info('Reading SBOM file {}'.format(args.sbom_file))

    new_doc = spdx_utilities.read_spdx_file(args.sbom_file)
    if new_doc is not None:
        logging.info('SBOM file contains {} file entries'.format(len(new_doc.files)))
    else:
        logging.error('Could not read SBOM file {}!'.format(args.sbom_file))
        exit(1)

    if public_key is not None:
        # validate signature
        data = spdx_utilities.serialize_spdx_doc(new_doc)
        signature = spdx_utilities.get_digital_signature_from_spdx_document(new_doc)
        if not signature_utilities.validate_signature(public_key, signature, data):
            logging.error('Digital signature mismatch')
            exit(13)
        else:
            logging.info('Digital signature on SBOM file is good.  SBOM file appears authentic.')
    # get all files from all packages in the sbom into a list.
    sbom_files = new_doc.files

    result = False
    if package_path is not None:
        result = validate_package_path(package_path, sbom_files)

    if package_zip is not None:
        result = validate_package_zip(package_zip, sbom_files)

    exit(0 if result else 13)


if __name__ == "__main__":
    main()
