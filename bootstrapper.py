#!/bin/python3.9
"""
This script generates (bootstraps) a SBOM file from existing data.
This is used to get a quick stake in the ground with a usable SBOM file
for integrity checking.  This should only be done once, then the SBOM file
should be maintained by some other means going forward.
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

spdx_id_counter = 0


def new_spdx_id():
    global spdx_id_counter
    spdx_id_counter += 1
    return 'SPDXRef-{:06d}'.format(spdx_id_counter)

def main():
    parser = argparse.ArgumentParser(description='Bootstrap SBOM file')
    parser.add_argument('--debug', action='store_true', help='output API debug data')
    parser.add_argument('--tvfile', type=str, help='SBOM tag/value filename to write')
    parser.add_argument('--packagepath', type=str, help='path to base of package')
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

    if not os.path.isdir(args.packagepath):
        logging.error('packagepath "{}" is not a directory.'.format(args.packagepath))
        exit(1)
    package_path = args.packagepath

    logging.info('Enumerating files...')
    files = files_in_dir(package_path)
    logging.info('directory enumeration found {} files'.format(len(files)))

    spdx_doc = new_spdx_doc()
    spdx_pkg = new_spdx_pkg(spdx_id=new_spdx_id(), name='BaseApp', version='0.0.0')

    # add all the discovered files to the package.
    for file in files:
        spdx_file = new_spdx_file(filename=file, spdx_id=new_spdx_id())
        hash_names = ['sha1', 'sha256', 'sha512']
        for hash_name in hash_names:
            hash_value = calculate_hash_for_file('{}/{}'.format(package_path, file), hash_name)
            add_checksum_to_spdx_file(spdx_file, hash_name.upper(), hash_value)
        spdx_pkg.add_file(spdx_file)

    # update pkg verification code.
    spdx_pkg.verif_code = spdx_pkg.calc_verif_code()
    spdx_doc.add_package(spdx_pkg)

    # write the spdx file.
    logging.info('writing file {}'.format(args.tvfile))
    write_tv_file(spdx_doc, args.tvfile)

    # read the spdx file for basic verification
    logging.info('reading file {}'.format(args.tvfile))

    #  new_doc = read_tv_file('test.spdx')
    new_doc = read_tv_file(args.tvfile)
    if new_doc is not None:

        logging.info('Found {} files'.format(len(new_doc.packages[0].files)))
    else:
        logging.error('could not read tvfile!')

    logging.info('all done, bye bye.')
    exit(0)


if __name__ == "__main__":
    main()
