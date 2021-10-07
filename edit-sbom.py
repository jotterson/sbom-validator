#!/usr/bin/env python3
"""
sbom_editor.py -- this script provides simple edit to file data in a SBOM file.
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

from asciimatics.widgets import Button, Divider, Frame, Layout, MultiColumnListBox, Text, Widget
from asciimatics.scene import Scene
from asciimatics.screen import Screen
from asciimatics.exceptions import NextScene, ResizeScreenError, StopApplication

import signature_utilities
import spdx_utilities
from spdx_utilities import add_signature_to_spdx_document, read_tv_file, serialize_spdx_doc, write_tv_file
from spdx.utils import NoAssert, SPDXNone  # , UnKnown

#        01234567890123
MAGIC = '*BUILD-OUTPUT*'


class SpdxFileFilesAsListModel(object):
    """
    Class presents a SPDX SBOM file as a ListBox data model.
    """
    def __init__(self, filename, public_key=None, private_key=None):
        self.filename = filename
        self.public_key = public_key
        self.private_key = private_key
        self.spdx_doc = read_tv_file(filename)
        if self.public_key is not None:
            # validate signature
            data = spdx_utilities.serialize_spdx_doc(self.spdx_doc)
            signature = spdx_utilities.get_digital_signature_from_spdx_document(self.spdx_doc)
            if signature is not None:
                if not signature_utilities.validate_signature(public_key, signature, data):
                    raise RuntimeError('Digital signature mismatch')
        files = []
        for package in self.spdx_doc.packages:
            files.extend(package.files)
        self.files = files
        self.files_by_spdxid = {}
        if len(self.files) > 0:
            self.current_file = self.files[0]
            for file in self.files:
                self.files_by_spdxid[file.spdx_id] = file

    def get_listbox_options(self):
        """
        get a list of data to use to populate a list box
        :return: a list of tuples of data
        """
        options = []
        for file in self.files:
            options.append(([file.name, file.comment or ''], file.spdx_id))
        return options

    def get_spdxfile(self, spdx_id):
        """
        find a SPDX file by its spdx_id
        :param spdx_id: the spdx_id of the file sought
        :return: the SPDX File object for the specfied file, or None if not found.
        """
        file = self.files_by_spdxid.get(spdx_id)
        self.current_file = file
        return file

    def get_current_file_form_data(self):
        """
        this will create a dict with the data to edit from the SPDX File Object
        :return: a dict of field name/values to edit on a form
        """
        if self.current_file is None:
            data = {'name': '', 'comment': '', 'spdx_id': '', 'copyright': '', 'notice': ''}
        else:
            copyright_text = self.current_file.copyright
            if copyright_text is None:
                copyright_text = SPDXNone()
            elif isinstance(copyright_text, NoAssert):
                copyright_text = 'NOASSERTION'

            data = {'name': self.current_file.name,
                    'comment': self.current_file.comment,
                    'spdx_id': self.current_file.spdx_id,
                    'copyright': copyright_text,
                    'notice': self.current_file.notice,
                    }
            for hash_name in ['SHA1', 'SHA256', 'SHA512']:
                hash_value = self.current_file.get_chksum(hash_name)
                if hash_value is not None:
                    value = hash_value.value
                else:
                    value = ''
                data[hash_name.lower()] = value
        return data

    def set_current_file(self, spdx_id):
        """
        set the current file object to be the file with the given spdx_id. used
        to get the File selected by the ListBox
        :param spdx_id: the file you seek
        :return: None
        """
        self.current_file = self.get_spdxfile(spdx_id)

    def update_current_file(self, data):
        """
        apply dialog edit changes to a File object
        :param data: a dict of key/value pairs
        :return: None
        """
        if self.current_file is not None:
            self.current_file.comment = data.get('comment')
            copyright_text = data.get('copyright') or ''
            if copyright_text.upper() == 'NOASSERTION' or len(copyright_text) == 0:
                self.current_file.copyright = NoAssert()
            else:
                self.current_file.copyright = copyright_text
            self.current_file.notice = data.get('notice')

    def save_spdx_file(self):
        """
        save the spdx file changes
        :return: None
        """
        # sign the spdx file if the private key was specified
        if self.private_key:
            signature = signature_utilities.create_signature(self.private_key,
                                                             serialize_spdx_doc(self.spdx_doc))
            add_signature_to_spdx_document(self.spdx_doc, signature)
        # write the spdx file.
        write_tv_file(self.spdx_doc, self.filename)


class ListView(Frame):
    """
    this class is the UI view of the list of SBOM Files
    """
    def __init__(self, screen, model):
        super(ListView, self).__init__(screen,
                                       screen.height * 3 // 4,
                                       screen.width * 3 // 4,
                                       on_load=self._reload_list,
                                       hover_focus=True,
                                       can_scroll=False,
                                       title='Files Listed in SBOM')
        self._model = model

        # Create the form for displaying the list of files.
        self._list_view = MultiColumnListBox(
            Widget.FILL_FRAME,
            columns=[0, 16],
            options=model.get_listbox_options(),
            titles=['File Name', 'Comment'],
            name='files',
            add_scroll_bar=True,
            on_change=self._on_pick,
            on_select=self._toggle_file)
        self._toggle_file_button = Button('Toggle File', self._toggle_file)
        self._toggle_dir_button = Button('Toggle Dir', self._toggle_dir)
        self._edit_button = Button('Edit', self._edit)

        if self._model.current_file is not None:
            self._list_view.value = self._model.current_file.spdx_id
        layout = Layout([100], fill_frame=True)
        self.add_layout(layout)
        layout.add_widget(self._list_view)
        layout.add_widget(Divider())
        layout2 = Layout([1, 1, 1, 1, 1])
        self.add_layout(layout2)
        layout2.add_widget(self._toggle_file_button, 0)
        layout2.add_widget(self._toggle_dir_button, 1)
        layout2.add_widget(self._edit_button, 2)
        layout2.add_widget(Button('Cancel', self._quit), 3)
        layout2.add_widget(Button('Save', self._save_button_action), 4)
        self.fix()
        self._on_pick()

    def _on_pick(self):
        spdx_file = None
        if self._list_view.value is not None:
            spdx_file = self._model.get_spdxfile(self._list_view.value)

        self._edit_button.disabled = spdx_file is None
        self._toggle_file_button.disabled = spdx_file is None
        self._toggle_dir_button.disabled = spdx_file is None

    def _reload_list(self, new_value=None):
        self._list_view.options = self._model.get_listbox_options()
        self._list_view.value = new_value

    def _edit(self):
        self.save()
        raise NextScene('Edit File')

    def _toggle_file(self):
        if self._model.current_file is not None:
            if self._model.current_file.comment is None:
                self._model.current_file.comment = MAGIC
            elif self._model.current_file.comment.startswith(MAGIC):
                self._model.current_file.comment = self._model.current_file.comment[len(MAGIC):]
                if len(self._model.current_file.comment) == 0:
                    self._model.current_file.comment = None
            else:
                self._model.current_file.comment = MAGIC + self._model.current_file.comment
        self.save()
        self._reload_list(self._model.current_file.spdx_id)

    def _toggle_dir(self):
        if self._model.current_file is not None:
            filename = self._model.current_file.name
            dir, name = os.path.split(filename)
            for file in self._model.files:
                file_dir, file_name = os.path.split(file.name)
                if file_dir == dir:  # same directory!
                    if file.comment is None or len(file.comment) == 0:
                        file.comment = MAGIC
                    elif file.comment.startswith(MAGIC):
                        file.comment = file.comment[len(MAGIC):]
                    else:
                        file.comment = MAGIC + file.comment
        self.save()
        self._reload_list(self._model.current_file.spdx_id)


    def _save_button_action(self):
        self._model.save_spdx_file()
        raise StopApplication('User pressed save')

    @staticmethod
    def _quit():
        raise StopApplication('User pressed quit')


class SpdxFileView(Frame):
    """
    class provides a form to edit some SPDX File metadata
    """
    def __init__(self, screen, model):
        super(SpdxFileView, self).__init__(screen,
                                           11,
                                           100,
                                           hover_focus=True,
                                           can_scroll=False,
                                           title='SBOM File Details',
                                           reduce_cpu=True)
        self._model = model
        self.data = self._model.get_current_file_form_data()
        layout = Layout([100], fill_frame=True)
        self.add_layout(layout)
        layout.add_widget(Text('Name:', 'name', readonly=True))
        layout.add_widget(Text('SPDXID:', 'spdx_id', readonly=True))
        layout.add_widget(Text('SHA1:', 'sha1', readonly=True))
        layout.add_widget(Text('SHA256:', 'sha256', readonly=True))
        layout.add_widget(Text('SHA512:', 'sha512', readonly=True))
        layout.add_widget(Text('Comment:', 'comment'))
        layout.add_widget(Text('Copyright:', 'copyright'))
        layout.add_widget(Text('Notice:', 'notice'))
        layout2 = Layout([1, 1, 1, 1])
        self.add_layout(layout2)
        layout2.add_widget(Button('OK', self._ok), 0)
        layout2.add_widget(Button('Cancel', self._cancel), 3)
        self.fix()

    def reset(self):
        super(SpdxFileView, self).reset()
        self.data = self._model.get_current_file_form_data()

    def _ok(self):
        self.save()
        self._model.update_current_file(self.data)
        raise NextScene('Main')

    @staticmethod
    def _cancel():
        raise NextScene('Main')


def run_tui(screen, scene):
    scenes = [
        Scene([ListView(screen, spdx_files_list_model)], -1, name='Main'),
        Scene([SpdxFileView(screen, spdx_files_list_model)], -1, name='Edit File')
    ]
    screen.play(scenes, stop_on_resize=True, start_scene=scene, allow_int=True)


# noinspection DuplicatedCode
def main():
    parser = argparse.ArgumentParser(description='Bootstrap SBOM file')
    parser.add_argument('--debug', action='store_true', help='output API debug data')
    parser.add_argument('--sbom-file', type=str, help='SBOM tag/value filename to write')
    parser.add_argument('--public-key', type=str, help='path to rsa public key used for digital signature validation')
    parser.add_argument('--private-key', type=str, help='private key for signing SBOM')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(format='%(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)

    if args.sbom_file is None:
        logging.error('--sbom-file must be present')
        exit(1)

    if args.public_key is not None:
        public_key = signature_utilities.read_ssh_public_key(args.public_key)
    else:
        public_key = None

    if args.private_key:
        private_key = signature_utilities.read_ssh_private_key(args.private_key)
    else:
        private_key = None

    # noinspection PyGlobalUndefined
    global spdx_files_list_model
    spdx_files_list_model = SpdxFileFilesAsListModel(filename=args.sbom_file,
                                                     public_key=public_key,
                                                     private_key=private_key)
    last_scene = None
    while True:
        try:
            Screen.wrapper(run_tui, catch_interrupt=True, arguments=[last_scene])
            exit(0)
        except ResizeScreenError as e:
            last_scene = e.scene


if __name__ == '__main__':
    main()
