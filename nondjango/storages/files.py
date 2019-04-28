import logging
import io
import codecs
import difflib
from tempfile import NamedTemporaryFile
from contextlib import ContextDecorator

import editor

from . import utils

logger = logging.getLogger(__name__)
__escape_decoder = codecs.getdecoder('unicode_escape')


class File:
    def __init__(self, name, storage=None, mode='r'):
        self.name = name
        self.mode = mode
        self._storage = storage
        self._stream = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    @property
    def storage(self):
        if not self._storage:
            from .storages import FilesystemStorage
            self._storage = FilesystemStorage()
        return self._storage

    def read_into_stream(self, stream):
        self.storage.read_into_stream(self.name, stream=stream, mode=self.mode)

    def read(self):
        if 'r' not in self.mode and '+' not in self.mode:
            raise IOError('File not open for reading')
        return self.storage.read_into_stream(self.name).read()

    def exists(self):
        if list(self.storage.list(self.name)):
            return True
        return False

    def md5(self, raise_if_not_exists=True):
        try:
            md5hash, _ = next(self.storage.list(self.name))
        except StopIteration:
            if raise_if_not_exists:
                raise FileNotFoundError(self.name)
            else:
                md5hash = None
        return md5hash

    def write(self, data):
        if 'w' not in self.mode and 'a' not in self.mode and '+' not in self.mode:
            raise IOError('File not open for writing')

        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(data, bytes):
            self.storage._write(io.BytesIO(data), self.name)
        else:
            self.storage._write(data, self.name)

    def close(self):
        pass
