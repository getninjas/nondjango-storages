import os
import logging
import tempfile
import boto3
import posixpath
from botocore.exceptions import ClientError
from io import BytesIO, StringIO

from .utils import prepare_path, md5s3
from .files import File


logger = logging.getLogger(__name__)


class SuspiciousOperation(Exception):
    pass


class Settings(dict):
    "TODO: Implement something nicer!"
    pass


def force_text(base):
    return base.decode() if isinstance(base, bytes) else base


def safe_join(base, *paths):
    """
    A version of django.utils._os.safe_join for S3 paths.
    Joins one or more path components to the base path component
    intelligently. Returns a normalized version of the final path.
    The final path must be located inside of the base path component
    (otherwise a ValueError is raised).
    Paths outside the base path indicate a possible security
    sensitive operation.
    """
    starts_on_root = base.startswith('/')

    base_path = force_text(base)
    base_path = base_path.rstrip('/')
    paths = [force_text(p) for p in paths]

    final_path = base_path + '/'
    for path in paths:
        _final_path = posixpath.normpath(posixpath.join(final_path, path))
        # posixpath.normpath() strips the trailing /. Add it back.
        if path.endswith('/') or _final_path + '/' == final_path:
            _final_path += '/'
        final_path = _final_path
    if final_path == base_path:
        final_path += '/'

    # Ensure final_path starts with base_path and that the next character after
    # the base path is /.
    base_path_len = len(base_path)
    if (not final_path.startswith(base_path) or final_path[base_path_len] != '/'):
        raise ValueError('the joined path is located outside of the base path'
                         ' component')

    return final_path if starts_on_root else final_path.lstrip('/')


def _strip_prefix(text, prefix):
    return text[len(prefix):] if text.startswith(prefix) else text


def _strip_s3_path(path):
    bucket, _, path = _strip_prefix(path, 's3://').partition('/')
    return bucket, path


class BaseStorage:
    file_class = File

    def __init__(self, workdir=None, settings=None):
        self._settings = settings or Settings()
        self._workdir = workdir or os.getcwd()

    def _normalize_name(self, name):
        """
        Normalizes the name so that paths like /path/to/ignored/../something.txt
        work. We check to make sure that the path pointed to is not outside
        the directory specified by the LOCATION setting.
        """
        try:
            return safe_join(self._workdir, name)
        except ValueError:
            raise SuspiciousOperation(f"Attempted access to '{name}' denied.")

    def read_into_stream(self, file_path, stream=None, mode='r'):
        raise NotImplementedError()

    def open(self, file_name, mode='r'):
        logger.debug('Reading from %s', file_name)
        return self.file_class(file_name, storage=self, mode=mode)

    def _write(self, f, file_name):
        raise NotImplementedError()

    def list(self, path):
        raise NotImplementedError()

    def exists(self, path):
        raise NotImplementedError()


class S3Storage(BaseStorage):
    def __init__(self, settings=None):
        super(__class__, self).__init__(settings=settings)
        self._resource = None

    @property
    def s3(self):
        logger.debug('Getting S3 resource')
        # See how boto resolve credentials in
        # http://boto3.readthedocs.io/en/latest/guide/configuration.html#guide-configuration
        if not self._resource:
            logger.debug('Resource does not exist, creating a new one...')
            self._resource = boto3.resource(
                's3',
                aws_access_key_id=self._settings.get('S3CONF_ACCESS_KEY_ID') or self._settings.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=self._settings.get('S3CONF_SECRET_ACCESS_KEY') or self._settings.get('AWS_SECRET_ACCESS_KEY'),
                aws_session_token=self._settings.get('S3CONF_SESSION_TOKEN') or self._settings.get('AWS_SESSION_TOKEN'),
                region_name=self._settings.get('S3CONF_S3_REGION_NAME') or self._settings.get('AWS_S3_REGION_NAME'),
                use_ssl=self._settings.get('S3CONF_S3_USE_SSL') or self._settings.get('AWS_S3_USE_SSL', True),
                endpoint_url=self._settings.get('S3CONF_S3_ENDPOINT_URL') or self._settings.get('AWS_S3_ENDPOINT_URL'),
            )
        return self._resource

    def read_into_stream(self, file_path, stream=None):
        bucket_name, file_name = _strip_s3_path(file_path)
        stream = stream or BytesIO()
        bucket = self.s3.Bucket(bucket_name)
        try:
            bucket.download_fileobj(file_name, stream)
            stream.seek(0)
            return stream
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                logger.debug('File %s in bucket %s does not exist', file_name, bucket)
                raise FileNotFoundError(f's3://{bucket_name}/{file_name}')
            else:
                raise

    def write(self, f, file_name):
        logger.debug('Writing to %s', file_name)
        bucket, path_target = _strip_s3_path(file_name)
        try:
            bucket = self.s3.create_bucket(Bucket=bucket)
        except ClientError as e:
            if e.response['Error']['Code'] == 'BucketAlreadyExists':
                bucket = self.s3.Bucket(bucket)
            else:
                raise e
        bucket.upload_fileobj(f, path_target)

    def list(self, path):
        logger.debug('Listing %s', path)
        bucket_name, path = _strip_s3_path(path)
        bucket = self.s3.Bucket(bucket_name)
        try:
            for obj in bucket.objects.filter(Prefix=path):
                if not obj.key.endswith('/'):
                    yield obj.e_tag, _strip_prefix(obj.key, path)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucket':
                logger.warning('Bucket does not exist, list() returning empty.')
            else:
                raise
    
    def listdir(self, name):
        path = self._normalize_name(self._clean_name(name))
        # The path needs to end with a slash, but if the root is empty, leave
        # it.
        if path and not path.endswith('/'):
            path += '/'

        directories = []
        files = []
        paginator = self.connection.meta.client.get_paginator('list_objects')
        pages = paginator.paginate(Bucket=self.bucket_name, Delimiter='/', Prefix=path)
        for page in pages:
            for entry in page.get('CommonPrefixes', ()):
                directories.append(posixpath.relpath(entry['Prefix'], path))
            for entry in page.get('Contents', ()):
                files.append(posixpath.relpath(entry['Key'], path))
        return directories, files


class FilesystemStorage(BaseStorage):
    def _validate_path(self, path):
        return True

    def read_into_stream(self, file_name, stream=None, mode='r'):
        self._validate_path(file_name)
        if not stream:
            stream = BytesIO() if 'b' in mode else StringIO()
        with open(file_name, mode) as f:
            stream.write(f.read())
        stream.seek(0)
        return stream

    def _write(self, f, file_name):
        file_name = self._normalize_name(file_name)
        self._validate_path(file_name)
        prepare_path(file_name)
        open(file_name, 'wb').write(f.read())

    def save(self, name, content):
        path = self._normalize_name(name)
        open(path, 'wb').write(content)

    def listdir(self, path):
        self._validate_path(path)
        path = self._normalize_name(path)

        for _, dirnames, filenames in os.walk(path):
            break
        else:
            dirnames, filenames = [], []
        return dirnames, filenames

    def exists(self, name):
        path = self._normalize_name(name)
        dirname, sep, filename = path.rpartition('/')
        dirnames, existing_files = self.listdir(dirname)
        if filename in existing_files:
            return True
        return False

    def list(self, path):
        self._validate_path(path)
        fixed_path = self._normalize_name(path)

        if os.path.isdir(fixed_path):
            for root, dirs, files in os.walk(fixed_path):
                for file in files:
                    yield md5s3(open(file, 'rb')), _strip_prefix(os.path.join(root, file), fixed_path)
        else:
            # only yields if it exists
            if os.path.exists(fixed_path):
                # the relative path of a file to itself is empty
                # same behavior as in boto3
                yield md5s3(open(fixed_path, 'rb')), ''


class TemporaryFilesystemStorage(FilesystemStorage):
    """
    Just a Django-less storage w/ partial Django Storage API implemented
    """
    def __init__(self):
        self._tempdir = None

    @property
    def _workdir(self):
        if not self._tempdir:
            self._tempdir = tempfile.TemporaryDirectory()
        return self._tempdir.name
