#!/usr/bin/env python3.9
"""
merge-by-sha256.py -- this script merges data from sbom1 into sbom2 when sha256 matches.
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
import spdx_utilities

CHECKSUM_ALGORITHM = 'SHA256'  # MUST be uppercase.
MAGIC = '*BUILD-OUTPUT*'


class FileStatus(object):
    """
    class defines file status constants
    """
    HASH_MISMATCH = -2
    FILE_NOT_FOUND = -1
    UNDETERMINED = 0
    HASH_MATCH = 1
    BUILD_OUTPUT = 2


# noinspection DuplicatedCode,SpellCheckingInspection
def main():
    parser = argparse.ArgumentParser(description='merge-by-sha56')
    parser.add_argument('--debug', action='store_true', help='show logging informational output')
    parser.add_argument('--info', action='store_true', help='show informational diagnostic output')
    parser.add_argument('--source-sbom', type=str, help='SBOM filename to read')
    parser.add_argument('--merge-sbom', type=str, help='SBOM file with data to merge')
    parser.add_argument('--result-sbom', type=str, help='SBOM filename to write')
    parser.add_argument('--private-key', type=str, help='private key for signing SBOM')
    parser.add_argument('--public-key', type=str, help='path to rsa public key used for digital signature validation')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.DEBUG)
    elif args.info:
        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)
    else:
        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.WARNING)

    if args.source_sbom is None:
        logging.error('--source-sbom file must be specified')
        exit(1)
    source_sbom = spdx_utilities.read_sbom_file(args.source_sbom)

    if args.merge_sbom is None:
        logging.error('--merge-sbom file must be specified')
        exit(1)
    merge_sbom = spdx_utilities.read_sbom_file(args.merge_sbom)

    if args.result_sbom is None:
        logging.error('--result-sbom file must be specified')
        exit(1)

    if args.public_key is not None:
        public_key = signature_utilities.read_ssh_public_key(args.public_key)
    else:
        public_key = None

    if args.private_key:
        private_key = signature_utilities.read_ssh_private_key(args.private_key)
    else:
        private_key = None
        
    if public_key is not None:
        # check for signature on source sbom
        signature = spdx_utilities.get_digital_signature_from_spdx_document(source_sbom)
        if signature is not None:
            data = spdx_utilities.serialize_spdx_doc(source_sbom)
            if not signature_utilities.validate_signature(public_key, signature, data):
                logging.error('Digital signature mismatch on source SBOM {}'.format(args.source_sbom))
                exit(1)

        # check for signature on build sbom
        signature = spdx_utilities.get_digital_signature_from_spdx_document(merge_sbom)
        if signature is not None:
            data = spdx_utilities.serialize_spdx_doc(merge_sbom)
            if not signature_utilities.validate_signature(public_key, signature, data):
                logging.error('Digital signature mismatch on merge SBOM {}'.format(args.merge_sbom))
                exit(1)

    # merge and test.
    successes = 0
    warnings = 0
    errors = 0
    source_files = []
    for package in source_sbom.packages:
        source_files.extend(package.files)
    merge_files = []
    for package in merge_sbom.packages:
        merge_files.extend(package.files)

    build_files_by_name = {}
    for file in source_files:
        build_files_by_name[file.name] = {'file': file, 'status': FileStatus.UNDETERMINED}

    merge_files_by_sha256 = {}
    for file in merge_files:
        sha256 = file.get_checksum(CHECKSUM_ALGORITHM)
        merge_files_by_sha256[sha256.value] = file
        
    for source_file in source_files:
        sha256 = source_file.get_checksum(CHECKSUM_ALGORITHM)
        if sha256 is not None:
            merge_file = merge_files_by_sha256.get(sha256.value)
            if merge_file is not None:
                _, source_file_name = os.path.split(source_file.name)
                _, merge_file_name = os.path.split(merge_file.name)
                source_file.comment = merge_file.comment
                if source_file_name != merge_file_name:
                    logging.warning('File names do not match but sha does: {} should be {}'.format(source_file_name,
                                                                                                   merge_file_name))
                    if source_file.comment is None:
                        source_file.comment = ''
                    source_file.comment += 'name is {}'.format(merge_file_name)
                    warnings += 1
                else:
                    successes += 1
                source_file.file_types = merge_file.file_types
                # source_file.chk_sums = merge_file.chk_sums  # not merging hashes -- better not need to!
                source_file.conc_lics = merge_file.conc_lics
                source_file.licenses_in_file = merge_file.licenses_in_file
                source_file.license_comment = merge_file.license_comment
                source_file.copyright = merge_file.copyright
                source_file.notice = merge_file.notice

    if successes > 0:
        logging.info('{} spdx files merged using without error.'.format(successes))
    if errors > 0:
        logging.info('{} spdx file merge errors.'.format(errors))
    if warnings > 0:
        logging.info('{} spdx files merged with warnings.'.format(warnings))
    if errors == 0 and warnings == 0:
        logging.info('No errors or warnings.')
    logging.info('Writing result SBOM {}'.format(args.result_sbom))
    if private_key is not None:
        # sign the result sbom
        signature = signature_utilities.create_signature(private_key,
                                                         spdx_utilities.serialize_spdx_doc(source_sbom))
        spdx_utilities.add_signature_to_spdx_document(source_sbom, signature)
    # write the result sbom spdx file.
    spdx_utilities.write_sbom_file(source_sbom, args.result_sbom)
    logging.info('done.')


if __name__ == "__main__":
    main()
