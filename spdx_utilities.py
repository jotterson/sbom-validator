#!/bin/false

import codecs
import logging
import pathlib

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

"""
map file extensions to SPDX file types.
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


def add_checksum_to_spdx_file(spdx_file, algorithm_name, hash_value):
    spdx_file.chk_sums.append(Algorithm(algorithm_name, hash_value))


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


