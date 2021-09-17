#!/bin/python3.9
"""
Some file that does something. Jeff wrote it.
"""


import argparse
import codecs
import hashlib
import logging
import os
import pathlib
import sys

# SPDX imports.  (duh)
from spdx.writers.tagvalue import write_document, InvalidDocumentError
from spdx.parsers.loggers import ErrorMessages
from spdx.parsers.loggers import StandardLogger
from spdx.document import Document, License, LicenseConjunction, ExtractedLicense
from spdx.version import Version
from spdx.creationinfo import Person
from spdx.creationinfo import Tool
from spdx.review import Review
from spdx.package import Package
from spdx.file import File, FileType
from spdx.checksum import Algorithm
from spdx.utils import SPDXNone, NoAssert, UnKnown
from spdx.parsers.tagvalue import Parser
from spdx.parsers.tagvaluebuilders import Builder

spdx_id_counter = 0

"""
this is FUBAR, because only SOURCE, OTHER, BINARY, and ARCHIVE will validate. Always put one of those last in the list.
"""
file_extension_to_spdx_file_type_mapping = {
    '.bat': [FileType.TEXT, FileType.APPLICATION, FileType.OTHER],
    '.class': [FileType.APPLICATION, FileType.BINARY],
    '.css': [FileType.TEXT, FileType.APPLICATION, FileType.SOURCE],
    '.drl': [FileType.TEXT, FileType.APPLICATION, FileType.SOURCE],
    '.dtd': [FileType.TEXT, FileType.APPLICATION, FileType.SOURCE],
    '.eot': [FileType.IMAGE, FileType.OTHER],
    '.exe': [FileType.APPLICATION, FileType.BINARY],
    '.gif': [FileType.IMAGE, FileType.OTHER],
    '.htm': [FileType.TEXT, FileType.DOCUMENTATION, FileType.OTHER],
    '.html': [FileType.TEXT, FileType.DOCUMENTATION, FileType.OTHER],
    '.ico': [FileType.IMAGE, FileType.OTHER],
    '.jar': [FileType.ARCHIVE],
    '.jpg': [FileType.IMAGE, FileType.OTHER],
    '.js': [FileType.TEXT, FileType.APPLICATION, FileType.SOURCE],
    '.jsp': [FileType.TEXT, FileType.APPLICATION, FileType.SOURCE],
    '.map': [FileType.OTHER],
    '.pdf': [FileType.IMAGE, FileType.OTHER],
    '.png': [FileType.IMAGE, FileType.OTHER],
    '.properties': [FileType.TEXT, FileType.OTHER],
    '.sql': [FileType.TEXT, FileType.APPLICATION, FileType.OTHER],
    '.svg': [FileType.IMAGE, FileType.OTHER],
    '.ttf': [FileType.IMAGE, FileType.OTHER],
    '.txt': [FileType.TEXT, FileType.DOCUMENTATION, FileType.OTHER],
    '.xml': [FileType.TEXT, FileType.OTHER],
    '.xsl': [FileType.TEXT, FileType.OTHER],
    '.woff': [FileType.OTHER],
    '.woff2': [FileType.OTHER],
    '.xsd': [FileType.TEXT, FileType.APPLICATION, FileType.OTHER],
    '.zip': [FileType.ARCHIVE]
}


def set_spdx_file_type(spdx_file, filename):
    """
    get a SPDX file type from a file name;
    :param: spdx_file: the spdxfile object to modify.
    :param filename:
    :return:
    """
    file_type = pathlib.Path(filename).suffix.lower()
    spdx_file_types = file_extension_to_spdx_file_type_mapping.get(file_type)
    if spdx_file_types is None:
        #print(filename, file_type)  # indicate dict lookup failure for dev. purposes.
        spdx_file_types = [FileType.OTHER]
    spdx_file.file_types = spdx_file_types


def new_spdx_id():
    global spdx_id_counter
    spdx_id_counter += 1
    return 'SPDXRef-{:06d}'.format(spdx_id_counter)


def new_spdx_doc(name='SimpleSPDX', namespace='http://www.example.com/example'):
    doc = Document()
    doc.version = Version(2, 1)
    doc.name = name
    doc.spdx_id = "SPDXRef-DOCUMENT"
    # doc.comment = "Generated SPDX Document"
    doc.namespace = namespace  # "http://www.example.org/spdx"
    doc.data_license = License.from_identifier("CC0-1.0")
    #doc.creation_info.add_creator(Person("Alice", "alice@example.com"))
    doc.creation_info.add_creator(Tool('bar'))
    doc.creation_info.set_created_now()
    return doc


def new_spdx_pkg(spdx_id, name, version):
    # Package
    package = Package()
    package.name = name
    package.version = version
    #package.file_name = "twt.jar"
    package.spdx_id = spdx_id
    package.download_location = NoAssert()  # "NOASSERTION"
    #package.homepage = SPDXNone()
    #license_set = LicenseConjunction(
    #    License.from_identifier("Apache-2.0"), License.from_identifier("BSD-2-Clause")
    #)
    package.conc_lics = NoAssert()
    package.license_declared = NoAssert()
    package.add_lics_from_file(NoAssert())
    #package.conc_lics = license_set
    #package.license_declared = license_set
    #package.add_lics_from_file(License.from_identifier("Apache-2.0"))
    #package.add_lics_from_file(License.from_identifier("BSD-2-Clause"))
    package.cr_text = NoAssert()
    #package.summary = "Simple package."
    #package.description = "Really simple package."
    return package


def new_spdx_file(filename, spdx_id):
    spdx_file = File(filename)
    set_spdx_file_type(spdx_file, filename)
    #spdx_file.type = spdx_file_type(filename)
    spdx_file.spdx_id = spdx_id
    #spdx_file.comment = "This is a test file."
    #spdx_file.chk_sum = Algorithm("SHA1", "c537c5d99eca5333f23491d47ededd083fefb7ad")
    spdx_file.conc_lics = NoAssert()
    spdx_file.add_lics(NoAssert())
    spdx_file.copyright = NoAssert()
    #spdx_file.add_artifact("name", "TagWriteTest")
    #spdx_file.add_artifact("home", UnKnown())
    #spdx_file.add_artifact("uri", "http://tagwritetest.test")
    return spdx_file


def read_tv_file(filename):
    """
    read the named SPDX tag/value file.
    :param filename: the file to read
    :return: the SPDX document
    """
    p = Parser(Builder(), StandardLogger())
    p.build()
    document = None
    error = None
    with open(filename, "r") as f:
        data = f.read()
        document, error = p.parse(data)
    if error:
        print(error)
        logging.error(error)
        return None
    return document


def write_tv_file(doc, filename):
    """
    write a SPDX tag/value file.  Lifted nearly verbatim from spdx tools-python example code.
    :param doc: the SPDX document to save
    :param filename: the filename to write to
    :return: None
    """
    with codecs.open(filename, mode="w", encoding="utf-8") as out:
        try:
            write_document(doc, out)
        except InvalidDocumentError as e:
            message = "invalid document: " + str(e.args[0])
            print("Document is Invalid:\n\t", end="")
            print("\n\t".join(e.args[0]))
            messages = ErrorMessages()
            doc.validate(messages)
            print("\n".join(messages.messages))
            raise


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
        checksums = []
        for hash_name in hash_names:
            hash_value = calculate_hash_for_file('{}/{}'.format(package_path, file), hash_name)
            checksums.append(Algorithm(hash_name.upper(), hash_value))
        spdx_file.chk_sums = checksums

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
