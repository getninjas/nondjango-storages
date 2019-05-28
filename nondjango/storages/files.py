import logging
import io
import codecs
import difflib
from tempfile import NamedTemporaryFile
from contextlib import ContextDecorator

from . import utils

logger = logging.getLogger(__name__)
__escape_decoder = codecs.getdecoder('unicode_escape')


class File(ContextDecorator):
    def __init__(self, name, storage=None, mode='r', encoding='UTF-8'):
        self.name = name
        self.mode = mode
        if 'b' not in mode:
            self.encoding = encoding

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
        content = self.storage.read_into_stream(self.name).read()
        if 'b' not in self.mode and isinstance(content, bytes):
            content = content.decode(self.encoding)
        return content

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
        self.storage._close(self)
