import os
import logging
import tempfile

import pytest

from nondjango.storages import utils, files, storages

logging.getLogger('boto3').setLevel(logging.ERROR)
logging.getLogger('botocore').setLevel(logging.ERROR)
logging.getLogger('s3transfer').setLevel(logging.ERROR)


def test_prepare_empty_path():
    utils.prepare_path('')


def test_file():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = os.path.join(temp_dir, 'test_file.txt')
        f = files.File(test_file)
        f.write('test')
        assert f.read() == b'test'

