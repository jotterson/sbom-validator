#!/bin/python3.9
"""
validator.py -- this script compares a SBOM file with application files on disk.
it will report missing files, additional files, and hash mismatches for matching files.
"""

import argparse
import logging
import os

from spdx_utilities import \
    add_checksum_to_spdx_file, \
    new_spdx_doc, \
    new_spdx_file, \
    new_spdx_pkg, \
    read_tv_file, \
    write_tv_file
from validation_utilities import calculate_hash_for_file, files_in_dir


def main():
    parser = argparse.ArgumentParser(description='Bootstrap SBOM file')
    parser.add_argument('--debug', action='store_true', help='output API debug data')
    parser.add_argument('--tvfile', type=str, help='SBOM tag/value filename to write')
    parser.add_argument('--packagepath', type=str, help='path to base of package')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(format='%(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.WARNING)

    if args.packagepath is None:
        logging.error('--packagepath must be supplied')
        exit(1)

    if args.tvfile is None:
        logging.error('--tvfile must be present')
        exit(1)

    if not os.path.isdir(args.packagepath):
        logging.error('packagepath "{}" is not a directory.'.format(args.packagepath))
        exit(1)
    package_path = args.packagepath

    logging.info('Enumerating files in {}...'.format(package_path))
    files = files_in_dir(package_path)
    logging.info('directory enumeration found {} files'.format(len(files)))

    # read the spdx file that will be used for validation
    logging.info('reading file {}'.format(args.tvfile))

    new_doc = read_tv_file(args.tvfile)
    if new_doc is not None:
        logging.info('Found {} files'.format(len(new_doc.packages[0].files)))
    else:
        logging.error('could not read tvfile {}!'.format(args.tvfile))
        exit(1)

    # get all files from all packages in the sbom into a list.
    sbom_files = []
    for package in new_doc.packages:
        sbom_files.extend(package.files)

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
            print('Missing file! File {} was not found on disk.'.format(file))
            missing_files += 1
    # detect extra files
    extra_files = 0
    for file, file_dict in files_on_disk.items():
        if not file_dict.get('found_in_sbom'):
            print('Extra file!   File {} was not found in the SBOM.'.format(file))
            extra_files += 1

    # now compare checksums for all files that are both on disk and in the SBOM.
    mismatched_files = 0
    hash_algorithm = 'sha256'
    for file, file_dict in files_on_disk.items():
        if file_dict.get('found_in_sbom'):
            sbom_file = file_dict.get('sbom_file')
            checksums = sbom_file.chk_sums
            # get checksum hash value from the SBOM
            sbom_file_hash_value = None
            for chk_sum in checksums:
                if chk_sum.identifier.lower() == hash_algorithm:
                    sbom_file_hash_value = chk_sum.value
            if sbom_file_hash_value is None:
                logging.error('Cannot get {} hash value for file {}.'.format(hash_algorithm, file))
                exit(1)
            disk_file_hash_value = calculate_hash_for_file('{}/{}'.format(package_path, file), hash_algorithm)
            # now compare the hashes
            if sbom_file_hash_value != disk_file_hash_value:
                # danger will robinson!
                print('Checksum mismatch! File {} {} checksum does not match the SBOM'.format(file, hash_algorithm))
                mismatched_files += 1

    if missing_files != 0 or extra_files != 0 or mismatched_files != 0:
        print('Package fails integrity testing.')
        exit(13)

    logging.info('Package integrity appears OK.')
    exit(0)


if __name__ == "__main__":
    main()
