#!/bin/false
"""
this file contains useful utility functions for manipulating SPDX SBOM data.
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

import logging
import pathlib
from datetime import datetime

from license_expression import get_spdx_licensing, LicenseExpression

from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import CreationInfo, Document
from spdx_tools.spdx.model.version import Version
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.file import File, FileType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.model.spdx_none import SpdxNone
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.writer.write_anything import write_file


PARTIAL_LICENSES_LIST = [
    'Apache-2.0',
    'BSD-2-Clause',
    'BSD-3-Clause',
    'CDDL-1.0',
    'CDDL-1.1',
    'LGPL-2.1',
    'LGPL-3',
    'EPL-1.0',
    'EPL-2.0',
    'MIT',
    'MPL-1.0',
    'MPL-1.1',
    'MPL-2.0',
    'SPL-1.0',  # Sun Public License
    ]


ALL_LICENSES = []


def get_licenses_list():
    global ALL_LICENSES
    if len(ALL_LICENSES) == 0:
        licenses = []
        for license_name in PARTIAL_LICENSES_LIST:
            spdx_license = get_spdx_licensing().parse(license_name)
            licenses.append((str(spdx_license), license_name))
        licenses = sorted(licenses, key=lambda l: l[0])
        full_list = [('None', str(SpdxNone())), ('No Assertion', str(SpdxNoAssertion()))]
        full_list.extend(licenses)
        ALL_LICENSES = full_list
    return ALL_LICENSES


"""
map file extensions to SPDX file types.
"""
file_extension_to_spdx_file_type_mapping = {
    '.bat': [FileType.TEXT, FileType.APPLICATION, FileType.OTHER],
    '.bsh': [FileType.TEXT, FileType.APPLICATION, FileType.OTHER],
    '.class': [FileType.APPLICATION, FileType.BINARY],
    '.conf': [FileType.TEXT, FileType.OTHER],
    '.css': [FileType.TEXT, FileType.APPLICATION, FileType.SOURCE],
    '.drl': [FileType.TEXT, FileType.APPLICATION, FileType.SOURCE],
    '.dtd': [FileType.TEXT, FileType.APPLICATION, FileType.SOURCE],
    '.eot': [FileType.IMAGE, FileType.OTHER],
    '.exe': [FileType.APPLICATION, FileType.BINARY],
    '.gemspec': [FileType.TEXT, FileType.APPLICATION, FileType.OTHER],
    '.gif': [FileType.IMAGE, FileType.OTHER],
    '.gz': [FileType.APPLICATION, FileType.ARCHIVE],
    '.htm': [FileType.TEXT, FileType.OTHER],
    '.html': [FileType.TEXT, FileType.OTHER],
    '.ico': [FileType.IMAGE, FileType.OTHER],
    '.jar': [FileType.APPLICATION, FileType.ARCHIVE],
    '.jpg': [FileType.IMAGE, FileType.OTHER],
    '.js': [FileType.TEXT, FileType.SOURCE],
    '.jsp': [FileType.TEXT, FileType.APPLICATION, FileType.SOURCE],
    '.map': [FileType.OTHER],
    '.md': [FileType.TEXT, FileType.DOCUMENTATION, FileType.OTHER],
    '.pdf': [FileType.IMAGE, FileType.OTHER],
    '.png': [FileType.IMAGE, FileType.OTHER],
    '.properties': [FileType.TEXT, FileType.OTHER],
    '.py': [FileType.TEXT, FileType.APPLICATION, FileType.OTHER],
    '.pyd': [FileType.APPLICATION, FileType.BINARY],
    '.rb': [FileType.TEXT, FileType.APPLICATION, FileType.OTHER],
    '.sh': [FileType.TEXT, FileType.APPLICATION, FileType.OTHER],
    '.so': [FileType.TEXT, FileType.APPLICATION, FileType.BINARY],
    '.sql': [FileType.TEXT, FileType.APPLICATION, FileType.OTHER],
    '.svg': [FileType.IMAGE, FileType.OTHER],
    '.tar': [FileType.APPLICATION, FileType.ARCHIVE],
    '.ttf': [FileType.IMAGE, FileType.OTHER],
    '.txt': [FileType.TEXT, FileType.DOCUMENTATION, FileType.OTHER],
    '.xml': [FileType.TEXT, FileType.OTHER],
    '.xsl': [FileType.TEXT, FileType.OTHER],
    '.woff': [FileType.OTHER],
    '.woff2': [FileType.OTHER],
    '.xsd': [FileType.TEXT, FileType.APPLICATION, FileType.OTHER],
    '.zip': [FileType.APPLICATION, FileType.ARCHIVE]
}


def guess_spdx_file_type_from_extension(filename):
    """
    guess a SPDX file type from a file name extension;
    :param filename: the filename to examine.
    :return:
    """
    file_type = pathlib.Path(filename).suffix.lower()
    if len(file_type) > 0:
        return file_extension_to_spdx_file_type_mapping.get(file_type) or [FileType.OTHER]
    else:
        return None


def set_spdx_file_type(spdx_file, filename):
    """
    get a SPDX file type from a file name;
    :param spdx_file: the spdxfile object to modify.
    :param filename: the filename to examine.
    :return:
    """
    spdx_file_types = guess_spdx_file_type_from_extension(filename)
    if spdx_file_types is None:
        spdx_file_types = probe_file(filename)
    spdx_file.file_types = spdx_file_types


def probe_file(filename):
    """
    try to guess the SPDX file type based on analyzing a block of data from the file.
    :param filename: the file to test
    :return: a list of SPDX File Types
    """
    with open(filename, 'rb') as file:
        data = file.read(128)
        return guess_spdx_file_type_from_data(data)


def guess_spdx_file_type_from_data(data):
    """
    guess a file's SPDX file type by looking at the first several hundred bytes of data
    :param data: a byte list to inspect
    :return: a list of SPDX File Types
    """
    if len(data) > 0:
        if data[0:4] == b'\x7fELF':  # looks like a ELF binary.
            return [FileType.APPLICATION, FileType.OTHER, FileType.BINARY]
        if data[0:3] == b'#!/':  # looks like a script file
            return [FileType.APPLICATION, FileType.OTHER, FileType.TEXT]
        is_text = True
        for b in data[0:128]:
            if (b < 32 or b > 126) and b != 10 and b != 13:
                is_text = False
                break
        if is_text:
            return [FileType.OTHER, FileType.TEXT]
        else:
            return [FileType.BINARY, FileType.OTHER]
    return [FileType.BINARY, FileType.OTHER]


def new_spdx_doc(name='SPDX-SBOM', namespace='https://www.example.com/example', toolname='unknown tool'):
    """
    create a new SPDX SBOM doc
    :param name: name of new SPDX document
    :param namespace: namespace of new SPDX document
    :param toolname: name of tool used to create new SPDX document
    :return: the new SPDX Document object
    """

    creation_info = CreationInfo(
        spdx_version='SPDX-2.3',
        spdx_id='SPDXRef-DOCUMENT',
        name=name,
        data_license='CC0-1.0',
        document_namespace=namespace,
        creators=[Actor(ActorType.TOOL, name=toolname)],
        created=datetime.now(),
    )

    doc = Document(creation_info)
    return doc


def new_spdx_pkg(spdx_id, name, version, file_name=None):
    """
    create a new SPDX package object
    :param spdx_id:
    :param name:
    :param version:
    :param file_name: a file name to associate with the Package.
    :return: the new Package object
    """
    package = Package()
    package.name = name
    package.version = version
    if file_name is not None:
        package.file_name = file_name
    package.spdx_id = spdx_id
    package.download_location = SpdxNoAssertion()  # "NOASSERTION"
    package.conc_lics = SpdxNoAssertion()
    package.license_declared = SpdxNoAssertion()
    package.add_lics_from_file(SpdxNoAssertion())
    package.cr_text = SpdxNoAssertion()
    return package


def new_spdx_file(filename, spdx_id, checksums, comment=None):
    """
    Create a new SPDX File object
    :param filename: the relative path to the file
    :param spdx_id: a unique ID
    :param comment: optional comment string
    :return: the SPDX File object
    """
    spdx_file = File(filename, spdx_id, checksums,
                     license_concluded=SpdxNoAssertion(),
                     license_info_in_file=[SpdxNoAssertion()],
                     copyright_text=SpdxNoAssertion(),
                     comment=comment)
    return spdx_file


def read_spdx_file(filename):
    """
    read the named SPDX file.
    :param filename: the file to read
    :return: the SPDX document
    """
    return parse_file(filename)


def write_spdx_file(doc, filename):
    """
    write a SPDX file.
    :param doc: the SPDX document to save
    :param filename: the filename to write to
    :return: None
    """
    write_file(doc, filename)


# noinspection DuplicatedCode
def serialize_spdx_doc(spdx_doc):
    """
    in order to test the digital signature of the SPDX Document, it needs to be serialized
    so it can be hashed and signed or validated.  This is a specialized serializer that is
    made for that purpose only.  There is no corresponding de-serializer, one is not needed.
    Note that this works with my data, more complex SPDX Documents may not serialize properly,
    this may need further attention.
    :param spdx_doc:
    :return: a byte array that represents the SPDX Document object, more-or-less.
    """
    result = ''
    keys = sorted(spdx_doc.__dict__.keys())
    for k in keys:
        if k == 'comment':  # comment is not included in the serialization
            continue
        v = spdx_doc.__dict__.get(k)
        if v is None:
            result += f'|{k}:None'
        elif isinstance(v, str):
            result += f'|{k}:{str(v)}'
        elif isinstance(v, Version):
            result += f'|{k}:{str(v)}'
        elif isinstance(v, LicenseExpression):
            result += f'|{k}:{str(v)}'
        elif isinstance(v, CreationInfo):
            result += serialize_spdx_doc_creation_info(v)
        elif isinstance(v, list):
            if k == 'packages':
                # sort packages by spdx_id
                packages = sorted(v, key=lambda p: p.spdx_id)
                for item in packages:
                    result += serialize_spdx_package_info(item)
            elif k == 'files':
                files = sorted(v, key=lambda f: f.spdx_id)
                for file in files:
                    result += serialize_spdx_file_info(file)
            else:
                result += f'|{k}:['
                first = True
                for item in sorted(v, key=lambda val: str(val)):
                    if not first:
                        result += f',{str(item)}'
                    else:
                        result += f'{str(item)}'
                        first = False
                result += ']'
        else:
            print(k, v, type(v))
    return result.encode('utf-8')


# noinspection DuplicatedCode
def serialize_spdx_package_info(spdx_package):
    """
    Serialize a SPDX Package object for digital signature analysis.
    Note that there is no de-serializer for this, it is not needed.
    :param spdx_package: the SPDX Package object to serialize
    :return: str
    """
    result = ''
    keys = sorted(spdx_package.__dict__.keys())
    for k in keys:
        v = spdx_package.__dict__.get(k)
        if v is None:
            result += f'|{k}:None'
        elif isinstance(v, str):
            result += f'|{k}:{str(v)}'
        elif isinstance(v, LicenseExpression):
            result += f'|{k}:{str(v)}'
        elif isinstance(v, SpdxNoAssertion):
            result += f'|{k}:NOASSERTION'
        elif isinstance(v, dict):
            if k == 'checksums':
                result += f'|{k}:['
                checksums = []
                for algo, value in v.items():
                    checksums.append(f'{algo.name}:{value.value}')
                first = True
                for checksum in sorted(checksums):
                    if first:
                        result += checksum
                        first = False
                    else:
                        result += f',{checksum}'
                result += ']'

        elif isinstance(v, list):
            result += f'|{k}:['
            first = True
            for item in sorted(v, key=lambda val: str(val)):
                if not first:
                    result += f',{str(item)}'
                else:
                    result += f'{str(item)}'
                    first = False
            result += ']'
        else:
            print('unhandled type', k, v, type(v))
    return result


def serialize_spdx_file_info(spdx_file):
    """
    serialize a SPDX File object for digital signature processing
    :param spdx_file: the SPDX File object to serialize
    :return: str
    """
    result = ''
    keys = sorted(spdx_file.__dict__.keys())
    for k in keys:
        v = spdx_file.__dict__.get(k)
        if v is None:
            result += f'|{k}:None'
        elif isinstance(v, str):
            result += f'|{k}:{v}'
        elif isinstance(v, SpdxNoAssertion):
            result += f'|{k}:NOASSERTION'
        elif isinstance(v, SpdxNone):
            result += f'|{k}:{str(SpdxNone)}'
        elif isinstance(v, LicenseExpression):
            result += f'|{k}:{str(v)}'
        elif isinstance(v, dict):
            if k == 'checksums':
                result += f'|{k}:['
                checksums = []
                for algo, value in v.items():
                    checksums.append(f'{algo.name}:{value.value}')
                first = True
                for checksum in sorted(checksums):
                    if first:
                        result += checksum
                        first = False
                    else:
                        result += f',{checksum}'
                result += ']'
        elif isinstance(v, list):
            result += f'|{k}:['
            first = True
            for item in sorted(v, key=lambda val: str(val)):
                if not first:
                    result += f',{str(item)}'
                else:
                    result += f'{str(item)}'
                    first = False
            result += ']'
        else:
            logging.warning('serialize_spdx_file_info unhandled type', k, v, type(v))
    return result


def serialize_spdx_doc_creation_info(creation_info):
    """
    Serialize a SPDX DocCreationInfo for digital signature analysis
    :param creation_info:
    :return: str
    """
    result = ''
    creators = []
    for creator in creation_info.creators:
        creators.append(str(creator))
    for creator in sorted(creators):
        result += f'|creator:{creator}'
    result += f'|created:{str(creation_info.created)[:19]}'
    result += f'|comment:{str(creation_info.document_comment)}'
    result += f'|license_list_version:{str(creation_info.license_list_version)}'
    return result


def get_digital_signature_from_spdx_document(spdx_doc):
    """
    get the digital signature of a SPDX document from the Document comment.
    the digital signature is stored in the comment because there is no other
    field in which to stick it
    :param spdx_doc: the SPDX Document object
    :return: str
    """
    comment = spdx_doc.creation_info.creator_comment
    if comment is not None:
        doc_comment = comment.strip()
        if doc_comment[0:10] == 'Signature:':
            signature = doc_comment[10:].strip()
            return signature
    return None


def add_signature_to_spdx_document(spdx_doc, signature):
    """
    add the digital signature to the SPDX Document "comment" field.
    :param spdx_doc: the SPDX Document to modify
    :param signature: the base64-encoded digital signature to add to the Document
    :return: None
    """
    spdx_doc.creation_info.creator_comment = f'Signature: {signature}'


def get_specified_checksum(checksums: list[Checksum], algorithm: ChecksumAlgorithm=ChecksumAlgorithm.SHA256):
    for checksum in checksums:
        if checksum.algorithm == algorithm:
            return checksum
    return None