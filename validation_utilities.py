#!/bin/false
"""
this file contains useful utilities related to file integrity validation.
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

import hashlib
import os


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
    hasher = hashlib.new(hash_name)
    with open(filename, 'rb') as fh:
        while True:
            block = fh.read(64*1024)
            if not block:
                break
            hasher.update(block)
    return hasher.hexdigest()
