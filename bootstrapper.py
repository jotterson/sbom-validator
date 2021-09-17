#!/bin/python3.9
"""
Some file that does something. Jeff wrote it.
"""


import argparse
import hashlib
import logging
import os

from spdx_utilities import add_checksum_to_spdx_file, new_spdx_doc, new_spdx_file, new_spdx_pkg, read_tv_file, set_spdx_file_type, write_tv_file

from spdx.checksum import Algorithm

spdx_id_counter = 0

def new_spdx_id():
    global spdx_id_counter
    spdx_id_counter += 1
    return 'SPDXRef-{:06d}'.format(spdx_id_counter)


def files_in_dir(path, start='.'):
    """
    return a list of filenames found by walking the directory tree starting at path
    """
    files = []
    with os.scandir(path) as iterable:
        dir_files = []
        dir_dirs = []
        for dir_entry in iterable:
            if dir_entry.is_dir():
                dir_dirs.append(dir_entry.name)
            else:
                dir_files.append(dir_entry.name)
        for fn in sorted(dir_files):
            files.append('{}/{}'.format(start, fn))
        for dn in sorted(dir_dirs):
            dir_files = files_in_dir('{}/{}'.format(path, dn), '{}/{}'.format(start, dn))
            if dir_files is not None and len(dir_files) > 0:
                files.extend(dir_files)
    return files


def calculate_hash_for_file(filename, hash_name='sha256'):
    """
    calculate the hash for a file.
    returns a string containing the hex value of the hash.
    hash_name can be sha256, sha512, md5, sha1, etc.  only the names shown here are tested. YMMV.
    """
    file_hash = None
    hasher = hashlib.new(hash_name)
    with open(filename, 'rb') as fh:
        while True:
            block = fh.read(64*1024)
            if not block:
                break
            hasher.update(block)
    return hasher.hexdigest()


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
        logging.error(('--tvfile must be present'))
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
