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


def test_filesystem_storages_honor_workdir():
    storage = storages.TemporaryFilesystemStorage()
    filename = 'test_file.txt'
    f = storage.open(filename, 'w+')
    f.write('test payload')
    f.close()

    workdir = storage._workdir
    assert filename in os.listdir(workdir), 'File is not on the storage workdir'


@pytest.mark.parametrize("storage_class, storage_params", [
    (storages.TemporaryFilesystemStorage, {}),
    (storages.S3Storage, {'workdir': 's3://gn-ninja/storage-test/'}),
])
def test_file_read_write(storage_class, storage_params):
    payload = 'test payload'
    storage = storage_class(**storage_params)
    try:
        storage.delete('test_file.txt')
    except NotImplementedError:
        raise
    except Exception:
        pass

    assert not storage.exists('test_file.txt')

    with storage.open('test_file.txt', 'w+') as f:
        f.write(payload)
    assert storage.exists('test_file.txt')

    with storage.open('test_file.txt', 'r') as f2:
        assert f2.read() == payload
