#!/usr/bin/env python3.9
"""
merge-and-test.py -- this script compares a SBOM file with application files on disk.
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
import logging

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


def main():
    parser = argparse.ArgumentParser(description='Bootstrap SBOM file')
    parser.add_argument('--debug', action='store_true', help='output API debug data')
    parser.add_argument('--ideal-sbom', type=str, help='ideal SBOM filename to read')
    parser.add_argument('--build-sbom', type=str, help='build output SBOM filename to read')
    parser.add_argument('--result-sbom', type=str, help='build output SBOM filename to write')
    parser.add_argument('--private-key', type=str, help='private key for signing SBOM')
    parser.add_argument('--public-key', type=str, help='path to rsa public key used for digital signature validation')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)

    if args.ideal_sbom is None:
        logging.error('--ideal-sbom file must be specified')
        exit(1)
    ideal_sbom = spdx_utilities.read_tv_file(args.ideal_sbom)

    if args.build_sbom is None:
        logging.error('--build-sbom file must be specified')
        exit(1)
    build_sbom = spdx_utilities.read_tv_file(args.build_sbom)

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
        # check for signature on ideal sbom
        signature = spdx_utilities.get_digital_signature_from_spdx_document(ideal_sbom)
        if signature is not None:
            data = spdx_utilities.serialize_spdx_doc(ideal_sbom)
            if not signature_utilities.validate_signature(public_key, signature, data):
                raise RuntimeError('Digital signature mismatch on ideal SBOM {}'.format(args.ideal_sbom))

        # check for signature on build sbom
        signature = spdx_utilities.get_digital_signature_from_spdx_document(build_sbom)
        if signature is not None:
            data = spdx_utilities.serialize_spdx_doc(build_sbom)
            if not signature_utilities.validate_signature(public_key, signature, data):
                raise RuntimeError('Digital signature mismatch on ideal SBOM {}'.format(args.build_sbom))

    # merge and test.
    successes = 0
    warnings = 0
    errors = 0
    ideal_files = []
    for package in ideal_sbom.packages:
        ideal_files.extend(package.files)
    build_files = []
    for package in build_sbom.packages:
        build_files.extend(package.files)

    build_files_by_name = {}
    for file in build_files:
        build_files_by_name[file.name] = {'file': file, 'status': FileStatus.UNDETERMINED}

    ideal_files_by_name = {}
    for file in ideal_files:
        ideal_files_by_name[file.name] = {'file': file, 'status': FileStatus.UNDETERMINED}

    for build_file_name in build_files_by_name.keys():
        build_file_dict = build_files_by_name[build_file_name]
        build_file = build_file_dict['file']
        ideal_file_dict = ideal_files_by_name.get(build_file.name)
        if ideal_file_dict is None:
            build_file_dict['status'] = FileStatus.FILE_NOT_FOUND
            logging.warning('File exists in build but not in ideal SBOM: {}'.format(build_file_name))
            warnings += 1
        else:
            ideal_file = ideal_file_dict['file']
            if ideal_file.comment is not None and ideal_file.comment.startswith(MAGIC):
                build_file_dict['status'] = FileStatus.BUILD_OUTPUT
                ideal_file_dict['status'] = FileStatus.BUILD_OUTPUT
                build_file.comment = ideal_file.comment
                successes += 1
            else:
                ideal_file_sha256 = ideal_file.get_chksum(CHECKSUM_ALGORITHM).value
                build_file_sha256 = build_file.get_chksum(CHECKSUM_ALGORITHM).value
                if ideal_file_sha256 == build_file_sha256:
                    build_file_dict['status'] = FileStatus.HASH_MATCH
                    ideal_file_dict['status'] = FileStatus.HASH_MATCH
                    successes += 1
                else:
                    build_file_dict['status'] = FileStatus.HASH_MISMATCH
                    ideal_file_dict['status'] = FileStatus.HASH_MISMATCH
                    logging.warning('Hash mismatch on file {}'.format(build_file_name))
                    errors += 1

    for ideal_file_dict in ideal_files_by_name.values():
        ideal_file = ideal_file_dict['file']
        status = ideal_file_dict['status']
        if status == 0:
            logging.warning('File found in ideal SBOM but not build SBOM: {}'.format(ideal_file.name))
            warnings += 1

    if errors > 0:
        logging.info('{} errors'.format(errors))
    if warnings > 0:
        logging.info('{} warnings'.format(warnings))
    if errors == 0 and warnings == 0:
        logging.info('No errors or warnings.')
    logging.info('Writing result SBOM {}'.format(args.result_sbom))
    if private_key is not None:
        # sign the result sbom
        signature = signature_utilities.create_signature(private_key,
                                                         spdx_utilities.serialize_spdx_doc(build_sbom))
        spdx_utilities.add_signature_to_spdx_document(build_sbom, signature)
    # write the result sbom spdx file.
    spdx_utilities.write_tv_file(build_sbom, args.result_sbom)
    logging.info('done.')


if __name__ == "__main__":
    main()
