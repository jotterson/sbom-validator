#!/bin/false
"""
this file contains useful utility functions for manipulating SPDX SBOM data.
"""
import codecs
import hashlib
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
    '.jar': [FileType.APPLICATION, FileType.ARCHIVE],
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
    '.zip': [FileType.APPLICATION, FileType.ARCHIVE]
}


def set_spdx_file_type(spdx_file, filename):
    """
    get a SPDX file type from a file name;
    :param spdx_file: the spdxfile object to modify.
    :param filename: the filename to examine.
    :return:
    """
    file_type = pathlib.Path(filename).suffix.lower()
    spdx_file_types = file_extension_to_spdx_file_type_mapping.get(file_type)
    if spdx_file_types is None:
        #  print(filename, file_type)  # indicate dict lookup failure for dev. purposes.
        spdx_file_types = [FileType.OTHER]
    spdx_file.file_types = spdx_file_types


def new_spdx_doc(name='SimpleSPDX', namespace='https://www.example.com/example'):
    doc = Document()
    doc.version = Version(2, 1)
    doc.name = name
    doc.spdx_id = 'SPDXRef-DOCUMENT'
    doc.comment = 'Signature: none'
    doc.namespace = namespace  # "http://www.example.org/spdx"
    doc.data_license = License.from_identifier("CC0-1.0")
    #  doc.creation_info.add_creator(Person("Alice", "alice@example.com"))
    doc.creation_info.add_creator(Tool('bar'))
    doc.creation_info.set_created_now()
    return doc


def new_spdx_pkg(spdx_id, name, version):
    # Package
    package = Package()
    package.name = name
    package.version = version
    #  package.file_name = "twt.jar"
    package.spdx_id = spdx_id
    package.download_location = NoAssert()  # "NOASSERTION"
    #  package.homepage = SPDXNone()
    #  license_set = LicenseConjunction(
    #    License.from_identifier("Apache-2.0"), License.from_identifier("BSD-2-Clause")
    #  )
    package.conc_lics = NoAssert()
    package.license_declared = NoAssert()
    package.add_lics_from_file(NoAssert())
    #  package.conc_lics = license_set
    #  package.license_declared = license_set
    #  package.add_lics_from_file(License.from_identifier("Apache-2.0"))
    #  package.add_lics_from_file(License.from_identifier("BSD-2-Clause"))
    package.cr_text = NoAssert()
    #  package.summary = "Simple package."
    #  package.description = "Really simple package."
    return package


def new_spdx_file(filename, spdx_id):
    spdx_file = File(filename)
    set_spdx_file_type(spdx_file, filename)
    #  spdx_file.type = spdx_file_type(filename)
    spdx_file.spdx_id = spdx_id
    #  spdx_file.comment = "This is a test file."
    #  spdx_file.chk_sum = Algorithm("SHA1", "c537c5d99eca5333f23491d47ededd083fefb7ad")
    spdx_file.conc_lics = NoAssert()
    spdx_file.add_lics(NoAssert())
    spdx_file.copyright = NoAssert()
    #  spdx_file.add_artifact("name", "TagWriteTest")
    #  spdx_file.add_artifact("home", UnKnown())
    #  spdx_file.add_artifact("uri", "http://tagwritetest.test")
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
    #document = None
    #error = None
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
            print("Document is Invalid:\n\t", end="")
            print("\n\t".join(e.args[0]))
            messages = ErrorMessages()
            doc.validate(messages)
            print("\n".join(messages.messages))
            raise


def spdx_document_bytes_to_sign(spdx_doc):
    """
    I want to put the digital signature of the SBOM into the 'comment' field of the spdx document.
    in order to do this, I need to make sure the comment field is not included when hashing the spdx
    document in order to create it's unique hash.
    :param spdx_doc:
    :return:
    """
    doc_comment = spdx_doc.comment
    spdx_doc.comment = None
    sign_bytes = serialize_spdx_doc(spdx_doc)
    spdx_doc.comment = doc_comment
    return sign_bytes


def serialize_spdx_doc(spdx_doc):
    """
    so this sucks.  I need to serialize the spdx doc so I can calculate a hash code, but I need it to look the same
    every time.  this is a blune instrument to perform that conversion.  I don't care about deserialization, only
    equality of the hashed value.
    :param spdx_doc: the spdx document to serialize
    :return: a string that kinda represents the spdx document.
    """
    result = str(spdx_doc.version)
    result += str(spdx_doc.data_license)
    result += str(spdx_doc.name)
    result += str(spdx_doc.license_list_version)
    result += str(spdx_doc.spdx_id)
    result += str(spdx_doc.ext_document_references)
    result += str(spdx_doc.namespace)
    result += serialize_spdx_doc_creation_info(spdx_doc.creation_info)
    result += str(spdx_doc.extracted_licenses)
    reviews_strings = []
    for review in spdx_doc.reviews:
        reviews_strings.append('{} {} {}'.format(str(review.reviewer), str(review.review_date), str(review.comment)))
    for review_string in sorted(reviews_strings):
        result += review_string
    annotations_strings = []
    for annotation in spdx_doc.annotations:
        annotations_strings.append('{} {} {} {} {}'.format(str(annotation.annotator),
                                                           str(annotation.annotation_date),
                                                           str(annotation.annotation_type),
                                                           str(annotation.comment),
                                                           str(annotation.spdx_id)))
    for annotations_string in sorted(annotations_strings):
        result += annotations_string
    relationships_strings = []
    for relationship in spdx_doc.relationships:
        relationships_strings.append('{} {}'.format(str(relationship.relationship),
                                                    str(relationship.relationship_comment)))
    for relationships in sorted(relationships_strings):
        result += str(relationships)

    snippet_strings = []
    for snippet in spdx_doc.snippet:
        snippet_strings.append('{} {} {} {} {} {} {} {} {}'.format(str(snippet.spdx_id),
                                                                   str(snippet.name),
                                                                   str(snippet.comment),
                                                                   str(snippet.copyright),
                                                                   str(snippet.licenses_comment),
                                                                   str(snippet.attribution_text),
                                                                   str(snippet.snip_from_file_spdxid),
                                                                   str(snippet.conc_lics),
                                                                   str(snippet.licenses_in_snippet)))  # need loop?
    for snippet_string in snippet_strings:
        result += snippet_string

    for package in spdx_doc.packages:
        result += str(package.name)
        result += str(package.spdx_id)
        result += str(package.version)
        result += str(package.file_name)
        result += str(package.supplier)
        result += str(package.originator)
        result += str(package.download_location)
        result += str(package.files_analyzed)
        result += str(package.homepage)
        result += str(package.verif_code)
        result += str(package.files_analyzed)
        result += str(package.check_sum)
        result += str(package.source_info)
        result += str(package.license_declared)
        result += str(package.license_comment)
        for license_from_file in sorted(package.licenses_from_files):
            result += str(license_from_file)
        result += str(package.cr_text)
        result += str(package.summary)
        result += str(package.description)
        result += str(package.comment)
        result += str(package.attribution_text)
        result += str(package.verif_exc_files)
        result += str(package.pkg_ext_refs)
        for file in sorted(package.files, key=lambda f: f.spdx_id):
            result += str(file.name)
            result += str(file.spdx_id)
            result += str(file.comment)
            for ft in sorted(file.file_types):
                result += str(ft)
            checksum_strings = []
            for cs in file.chk_sums:
                checksum_strings.append('{}: {}'.format(cs.identifier, cs.value))
            for css in sorted(checksum_strings):
                result += str(css)
            result += str(file.conc_lics)
            for lf in sorted(file.licenses_in_file):
                result += str(lf)
            result += str(file.license_comment)
            result += str(file.copyright)
            result += str(file.notice)
            result += str(file.attribution_text)
            for contributor in sorted(file.contributors):
                result += str(contributor)
            for dependency in sorted(file.dependencies):
                result += str(dependency)
            for artifact_of_project_name in sorted(file.artifact_of_project_name):
                result += str(artifact_of_project_name)
            for artifact_of_project_home in sorted(file.artifact_of_project_home):
                result += str(artifact_of_project_home)
            for artifact_of_project_uri in sorted(file.artifact_of_project_uri):
                result += str(artifact_of_project_uri)
    return result.encode('utf-8')


def serialize_spdx_doc_creation_info(creation_info):
    result = ''
    creators = []
    for creator in creation_info.creators:
        creators.append(str(creator))
    for creator in sorted(creators):
        result += creator
    result += str(creation_info.created)[:19]  # trim this, the milliseconds are lost when the file is saved.
    result += str(creation_info.comment)
    result += str(creation_info.license_list_version)
    return result


def get_hash_of_spdx_document(spdx_doc, hash_algorithm='sha512'):
    hasher = hashlib.new(hash_algorithm)
    hasher.update(spdx_document_bytes_to_sign(spdx_doc))
    return hasher.digest()


def get_digital_signature_of_spdx_document(spdx_doc):
    if spdx_doc.comment is not None:
        doc_comment = spdx_doc.comment.strip()
        if doc_comment[0:10] == 'Signature:':
            signature = doc_comment[10:].strip()
            return signature
    return None


def add_signature_to_spdx_document(spdx_doc, signature):
    spdx_doc.comment = 'Signature: {}'.format(signature)
