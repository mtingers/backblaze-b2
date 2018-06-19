# -*- coding: utf-8 -*-
from __future__ import absolute_import

import mmap
import sys
import time

import Queue
import base64
import hashlib
import json
import os
import re
import tempfile
import threading
import urllib2
from Crypto import Random
from Crypto.Cipher import AES


#
# Author: Matthew Ingersoll <matth@mtingers.com>
#
# A class for accessing the Backblaze B2 API
#
# All of the API methods listed are implemented:
#   https://www.backblaze.com/b2/docs/
#
#


# Thanks to stackoverflow
# http://stackoverflow.com/questions/16761458/how-to-aes-encrypt-decrypt-files-using-python-pycrypto-in-an-openssl-compatible
# TODO: review if these encryption techniques are actually sound.
def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = ''
    while len(d) < key_length + iv_length:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length + iv_length]


def generate_salt_key_iv(password, key_length=32):
    bs = AES.block_size
    salt = Random.new().read(bs - len('Salted__'))
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    return salt, key, iv


def decrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = in_file.read(bs)[len('Salted__'):]
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = ord(chunk[-1])
            chunk = chunk[:-padding_length]
            finished = True
        out_file.write(chunk)


# A stupid way to calculate size of encrypted file and sha1
# B2 requires a header with the sha1 but urllib2 must have the header before streaming
# the data. This means we must read the file once to calculate the sha1, then read it again
# for streaming the data on upload.
def calc_encryption_sha_and_length(in_file, password, salt, key_length, key,
                                   iv):
    bs = AES.block_size
    size = 0
    cipher = AES.new(key, AES.MODE_CBC, iv)
    sha = hashlib.sha1()
    sha.update('Salted__' + salt)
    size += len('Salted__' + salt)
    finished = False
    while not finished:
        chunk = in_file.read(1024 * bs)
        if len(chunk) == 0 or len(chunk) % bs != 0:
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += padding_length * chr(padding_length)
            finished = True
        chunk = cipher.encrypt(chunk)
        sha.update(chunk)
        size += len(chunk)
    return sha.hexdigest(), size


class Read2Encrypt(file):
    """ Return encrypted data from read() calls
        Override read() for urllib2 when streaming encrypted data (uploads)
    """

    def __init__(self, path, mode, password, salt, key_length, key, iv, size=0,
                 *args):
        super(Read2Encrypt, self).__init__(path, mode)
        self.password = password
        self.bs = AES.block_size
        self.cipher = AES.new(key, AES.MODE_CBC, iv)
        (self.salt, self.key_length, self.key, self.iv) = (
            salt, key_length, key, iv)
        self.finished = False
        self._size = size
        self._args = args
        self.sha = None
        self.first_read = True

    def __len__(self):
        return self._size

    def read(self, size):
        if self.first_read:
            self.first_read = False
            return 'Salted__' + self.salt

        if self.finished:
            return None

        chunk = file.read(self, size)
        if len(chunk) == 0 or len(chunk) % self.bs != 0:
            padding_length = (self.bs - len(chunk) % self.bs) or self.bs
            chunk += padding_length * chr(padding_length)
            self.finished = True
            chunk = self.cipher.encrypt(chunk)
            return chunk
        if chunk:
            chunk = self.cipher.encrypt(chunk)
            return chunk


class BackBlazeB2(object):
    def __init__(self, account_id, app_key, mt_queue_size=12, valid_duration=24 * 60 * 60,
                 auth_token_lifetime_in_seconds=2 * 60 * 60, default_timeout=None):
        self.account_id = account_id
        self.app_key = app_key
        self.authorization_token = None
        self.api_url = None
        self.download_url = None
        self.upload_url = None
        self.upload_authorization_token = None
        self.valid_duration = valid_duration
        self.queue_size = mt_queue_size
        self.upload_queue = Queue.Queue(maxsize=mt_queue_size)
        self.default_timeout = default_timeout
        self._last_authorization_token_time = None
        self.auth_token_lifetime_in_seconds = auth_token_lifetime_in_seconds

    def authorize_account(self, timeout=None):
        id_and_key = self.account_id + ':' + self.app_key
        basic_auth_string = 'Basic ' + base64.b64encode(id_and_key)
        headers = {'Authorization': basic_auth_string}
        try:
            request = urllib2.Request(
                'https://api.backblaze.com/b2api/v1/b2_authorize_account',
                headers=headers
            )
            response = self.__url_open_with_timeout(request, timeout)
            response_data = json.loads(response.read())
            response.close()
        except urllib2.HTTPError, error:
            print("ERROR: %s" % error.read())
            raise

        self.authorization_token = response_data['authorizationToken']
        self._last_authorization_token_time = time.time()
        self.api_url = response_data['apiUrl']
        self.download_url = response_data['downloadUrl']
        return response_data

    def _authorize_account(self, timeout):
        if (self._last_authorization_token_time is not None \
            and time.time() - self._last_authorization_token_time > self.auth_token_lifetime_in_seconds) \
                or not self.authorization_token or not self.api_url:
            self.authorize_account(timeout)

    def __url_open_with_timeout(self, request, timeout):
        if timeout is not None or self.default_timeout is not None:
            custom_timeout = timeout or self.default_timeout
            response = urllib2.urlopen(request, timeout=custom_timeout)
        else:
            response = urllib2.urlopen(request)
        return response

    def create_bucket(self, bucket_name, bucket_type='allPrivate', timeout=None):
        self._authorize_account(timeout)
        # bucket_type can be Either allPublic or allPrivate
        return self._api_request('%s/b2api/v1/b2_create_bucket' % self.api_url,
                                 {'accountId': self.account_id,
                                  'bucketName': bucket_name,
                                  'bucketType': bucket_type},
                                 {'Authorization': self.authorization_token}, timeout)

    def get_download_authorization(self, bucket_id, bucket_name,
                                   file_name_prefix, timeout):
        self._authorize_account(timeout)
        url = '%s/b2api/v1/b2_get_download_authorization' % self.api_url
        data = {
            'bucketId': bucket_id,
            'fileNamePrefix': file_name_prefix,
            'validDurationInSeconds': self.valid_duration
        }
        result = self._api_request(
            url,
            data,
            {'Authorization': self.authorization_token},
            timeout
        )
        url_authorized_download = "{}/file/{}/{}?Authorization={}".format(
            self.download_url, bucket_name, result['fileNamePrefix'],
            result['authorizationToken']
        )

        return url_authorized_download

    def list_buckets(self, timeout=None):
        self._authorize_account()
        return self._api_request('%s/b2api/v1/b2_list_buckets' % self.api_url,
                                 {'accountId': self.account_id},
                                 {'Authorization': self.authorization_token}, timeout)

    def get_bucket_info(self, bucket_id, bucket_name, timeout=None):
        bkt = None
        if not bucket_id and not bucket_name:
            raise Exception(
                "create_bucket requires either a bucket_id or bucket_name")
        if bucket_id and bucket_name:
            raise Exception(
                "create_bucket requires only _one_ argument and not both bucket_id and bucket_name")

        buckets = self.list_buckets(timeout)['buckets']
        if not bucket_id:
            key = 'bucketName'
            val = bucket_name
        else:
            key = 'bucketId'
            val = bucket_id
        for bucket in buckets:
            if bucket[key] == val:
                bkt = bucket
                break
        return bkt

    def delete_bucket(self, bucket_id=None, bucket_name=None, timeout=None):
        if not bucket_id and not bucket_name:
            raise Exception(
                "create_bucket requires either a bucket_id or bucket_name")
        if bucket_id and bucket_name:
            raise Exception(
                "create_bucket requires only _one_ argument and not both bucket_id and bucket_name")
        self._authorize_account(timeout)
        bucket = self.get_bucket_info(bucket_id, bucket_name, timeout)
        return self._api_request('%s/b2api/v1/b2_delete_bucket' % self.api_url,
                                 {'accountId': self.account_id,
                                  'bucketId': bucket['bucketId']},
                                 {'Authorization': self.authorization_token}, timeout)

    def get_upload_url(self, bucket_name, bucket_id, timeout=None):
        self._authorize_account(timeout)
        bucket = self.get_bucket_info(bucket_id, bucket_name)
        bucket_id = bucket['bucketId']
        return self._api_request('%s/b2api/v1/b2_get_upload_url' % self.api_url,
                                 {'bucketId': bucket_id},
                                 {'Authorization': self.authorization_token}, timeout)

    # If password is set, encrypt files, else nah
    def upload_file(self, path, password=None, bucket_id=None, bucket_name=None,
                    thread_upload_url=None,
                    thread_upload_authorization_token=None, timeout=None):

        self._authorize_account(timeout)

        if password:
            (salt, key, iv) = generate_salt_key_iv(password, 32)
            in_file = open(path, 'rb')
            (sha, size) = calc_encryption_sha_and_length(in_file, password,
                                                         salt, 32, key, iv)
            in_file.close()
            fp = Read2Encrypt(path, 'rb', password, salt, 32, key, iv,
                              size=size)
        else:
            fp = open(path, 'rb')
            mm_file_data = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
            filename = re.sub('^/', '', path)
            filename = re.sub('//', '/', filename)
            # TODO: Figure out URL encoding issue
            # filename = unicode(filename, "utf-8")
            sha = hashlib.sha1()
            with open(path, 'rb') as f:
                while True:
                    block = f.read(2 ** 10)
                    if not block: break
                    sha.update(block)
            sha = sha.hexdigest()

        if thread_upload_url:
            cur_upload_url = thread_upload_url
            cur_upload_authorization_token = thread_upload_authorization_token

        elif not self.upload_url or not self.upload_authorization_token:
            url = self.get_upload_url(bucket_name=bucket_name,
                                      bucket_id=bucket_id)
            cur_upload_url = url['uploadUrl']
            cur_upload_authorization_token = url['authorizationToken']

        # fixup filename
        filename = re.sub('\\\\', '/',
                          path)  # Make sure Windows paths are converted.
        filename = re.sub('^/', '', filename)
        filename = re.sub('//', '/', filename)
        # All the whitespaces in the filename should be converted to %20
        if " " in filename:
            filename = filename.replace(" ", "%20")
        # TODO: Figure out URL encoding issue
        filename = unicode(filename, "utf-8")
        headers = {
            'Authorization': cur_upload_authorization_token,
            'X-Bz-File-Name': filename,
            'Content-Type': 'application/octet-stream',
            # 'Content-Type' : 'b2/x-auto',
            'X-Bz-Content-Sha1': sha
        }
        try:
            if password:
                request = urllib2.Request(cur_upload_url, fp, headers)
            else:
                request = urllib2.Request(cur_upload_url, mm_file_data, headers)
            response = self.__url_open_with_timeout(request, timeout)
            response_data = json.loads(response.read())
        except urllib2.HTTPError, error:
            print("ERROR: %s" % error.read())
            raise

        response.close()
        fp.close()
        return response_data

    def update_bucket(self, bucket_type, bucket_id=None, bucket_name=None, timeout=None):
        if bucket_type not in ('allPublic', 'allPrivate'):
            raise Exception(
                "update_bucket: Invalid bucket_type.  Must be string allPublic or allPrivate")

        bucket = self.get_bucket_info(bucket_id=bucket_id,
                                      bucket_name=bucket_name, timeout=timeout)
        return self._api_request('%s/b2api/v1/b2_update_bucket' % self.api_url,
                                 {'bucketId': bucket['bucketId'],
                                  'bucketType': bucket_type},
                                 {'Authorization': self.authorization_token}, timeout)

    def list_file_versions(self, bucket_id=None, bucket_name=None, maxFileCount=100, startFileName=None, prefix=None,
                           timeout=None):
        bucket = self.get_bucket_info(bucket_id=bucket_id,
                                      bucket_name=bucket_name, timeout=timeout)
        if maxFileCount > 10000:
            maxFileCount = 10000

        if maxFileCount < 0:
            maxFileCount = 100

        data = {'bucketId': bucket['bucketId'], 'maxFileCount': maxFileCount}

        if startFileName is not None:
            data['startFileName'] = startFileName
        if prefix is not None:
            data['prefix'] = prefix

        return self._api_request(
            '%s/b2api/v1/b2_list_file_versions' % self.api_url,
            data,
            {'Authorization': self.authorization_token}, timeout)

    def list_file_names(self, bucket_id=None, bucket_name=None, maxFileCount=100, startFileName=None, prefix=None,
                        timeout=None):
        bucket = self.get_bucket_info(bucket_id=bucket_id,
                                      bucket_name=bucket_name, timeout=timeout)
        if maxFileCount > 10000:
            maxFileCount = 10000

        if maxFileCount < 0:
            maxFileCount = 100

        data = {'bucketId': bucket['bucketId'], 'maxFileCount': maxFileCount}

        if startFileName is not None:
            data['startFileName'] = startFileName
        if prefix is not None:
            data['prefix'] = prefix

        return self._api_request(
            '%s/b2api/v1/b2_list_file_names' % self.api_url,
            data,
            {'Authorization': self.authorization_token}, timeout)

    def hide_file(self, file_name, bucket_id=None, bucket_name=None, timeout=None):
        bucket = self.get_bucket_info(bucket_id=bucket_id,
                                      bucket_name=bucket_name)
        return self._api_request(
            '%s/b2api/v1/b2_list_file_versions' % self.api_url,
            {'bucketId': bucket['bucketId'], 'fileName': file_name},
            {'Authorization': self.authorization_token}, timeout)

    def delete_file_version(self, file_name, file_id, timeout=None):
        return self._api_request(
            '%s/b2api/v1/b2_delete_file_version' % self.api_url,
            {'fileName': file_name, 'fileId': file_id},
            {'Authorization': self.authorization_token}, timeout)

    def get_file_info_by_name(self, file_name, bucket_id=None, bucket_name=None):
        file_names = self.list_file_names(bucket_id=bucket_id, bucket_name=bucket_name, prefix=file_name)
        for i in file_names['files']:
            if file_name in i['fileName']:
                return self.get_file_info(i['fileId'])
        return None

    def get_file_info(self, file_id, timeout=None):
        return self._api_request('%s/b2api/v1/b2_get_file_info' % self.api_url,
                                 {'fileId': file_id},
                                 {'Authorization': self.authorization_token}, timeout)

    def download_file_with_authorized_url(self, url, dst_file_name, force=False,
                                          password=None, timeout=None):
        if os.path.exists(dst_file_name) and not force:
            raise Exception(
                "Destination file exists. Refusing to overwrite. "
                "Set force=True if you wish to do so.")
        request = urllib2.Request(
            url, None, {})
        response = self.__url_open_with_timeout(request, timeout)

        return BackBlazeB2.write_file(response, dst_file_name, password)

    def download_file_by_name(self, file_name, dst_file_name, bucket_id=None,
                              bucket_name=None, force=False, password=None, timeout=None):
        if os.path.exists(dst_file_name) and not force:
            raise Exception(
                "Destination file exists. Refusing to overwrite. "
                "Set force=True if you wish to do so.")

        self._authorize_account(timeout)
        bucket = self.get_bucket_info(bucket_id=bucket_id,
                                      bucket_name=bucket_name, timeout=timeout)

        url = self.download_url + '/file/' + bucket[
            'bucketName'] + '/' + file_name

        headers = {
            'Authorization': self.authorization_token
        }

        request = urllib2.Request(
            url, None, headers)
        response = self.__url_open_with_timeout(request, timeout)

        return BackBlazeB2.write_file(response, dst_file_name, password)

    def download_file_by_id(self, file_id, dst_file_name, force=False,
                            password=None, timeout=None):
        if os.path.exists(dst_file_name) and not force:
            raise Exception(
                "Destination file exists. Refusing to overwrite. "
                "Set force=True if you wish to do so.")

        self._authorize_account()
        url = self.download_url + '/b2api/v1/b2_download_file_by_id?fileId=' + file_id
        request = urllib2.Request(url, None,
                                  {'Authorization': self.authorization_token})
        resp = self.__url_open_with_timeout(request, timeout)
        return BackBlazeB2.write_file(resp, dst_file_name, password)

    def _upload_worker(self, password, bucket_id, bucket_name):
        # B2 started requiring a unique upload url per thread
        """Uploading in Parallel
        The URL and authorization token that you get from b2_get_upload_url can be used by only one thread at a time.
        If you want multiple threads running, each one needs to get its own URL and auth token. It can keep using that
        URL and auth token for multiple uploads, until it gets a returned status indicating that it should get a
        new upload URL."""
        url = self.get_upload_url(bucket_name=bucket_name, bucket_id=bucket_id)
        thread_upload_url = url['uploadUrl']
        thread_upload_authorization_token = url['authorizationToken']

        while not self.upload_queue_done:
            time.sleep(1)
            try:
                path = self.upload_queue.get_nowait()
            except:
                continue
            # try a few times in case of error
            for i in range(4):
                try:
                    self.upload_file(path, password=password,
                                     bucket_id=bucket_id,
                                     bucket_name=bucket_name,
                                     thread_upload_url=thread_upload_url,
                                     thread_upload_authorization_token=thread_upload_authorization_token)
                    break
                except Exception, e:
                    print(
                            "WARNING: Error processing file '%s'\n%s\nTrying again." % (
                        path, e))
                    time.sleep(1)

    def recursive_upload(self, path, bucket_id=None, bucket_name=None,
                         exclude_regex=None, include_regex=None,
                         exclude_re_flags=None, include_re_flags=None,
                         password=None, multithread=True):
        bucket = self.get_bucket_info(bucket_id=bucket_id,
                                      bucket_name=bucket_name)
        if exclude_regex:
            exclude_regex = re.compile(exclude_regex, flags=exclude_re_flags)
        if include_regex:
            include_regex = re.compile(include_regex, flags=include_re_flags)

        nfiles = 0
        if os.path.isdir(path):
            if multithread:
                # Generate Queue worker threads to match QUEUE_SIZE
                self.threads = []
                self.upload_queue_done = False
                for i in range(self.queue_size):
                    t = threading.Thread(target=self._upload_worker, args=(
                        password, bucket_id, bucket_name,))
                    self.threads.append(t)
                    t.start()

            for root, dirs, files in os.walk(path):
                for f in files:
                    if os.path.islink(root + '/' + f): continue
                    if exclude_regex and exclude_regex.match(
                            root + '/' + f): continue
                    if include_regex and not include_regex.match(
                            root + '/' + f): continue
                    if multithread:
                        print("UPLOAD: %s" % root + '/' + f)
                        self.upload_queue.put(root + '/' + f)
                    else:
                        self.upload_file(root + '/' + f, password=password,
                                         bucket_id=bucket_id,
                                         bucket_name=bucket_name)
                    nfiles += 1
            if multithread:
                self.upload_queue_done = True
                for t in self.threads:
                    t.join()

        else:
            nfiles = 1
            if not os.path.islink(path):
                if exclude_regex and exclude_regex.match(path):
                    nfiles -= 1
                if include_regex and include_regex.match(path):
                    nfiles += 1
            if nfiles > 0:
                print("UPLOAD: %s" % path)
                self.upload_file(path, password=password, bucket_id=bucket_id,
                                 bucket_name=bucket_name)
                return 1
            else:
                print("WARNING: No files uploaded")
        return nfiles

    def _api_request(self, url, data, headers, timeout=None):
        self._authorize_account()
        request = urllib2.Request(url, json.dumps(data), headers)
        response = self.__url_open_with_timeout(request, timeout)
        response_data = json.loads(response.read())
        response.close()
        return response_data

    @staticmethod
    def write_file(response, dst_file_name, password=None):
        with open(dst_file_name, 'wb') as f:
            while True:
                chunk = response.read(2 ** 10)
                if not chunk:
                    break
                f.write(chunk)

        # If password protection, decrypt
        if password:
            d = os.path.dirname(dst_file_name)
            with tempfile.NamedTemporaryFile(prefix='b2-', dir=d, suffix='.tmp',
                                             delete=False) as tfile:
                tname = tfile.name
                with open(dst_file_name, 'rb') as in_file:
                    decrypt(in_file, tfile, password)

            os.unlink(dst_file_name)
            os.rename(tname, dst_file_name)
        return True


# Example command line utility
if __name__ == "__main__":
    import argparse, ConfigParser

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', required=True, dest='config_path',
                        help='Configuration path')
    parser.add_argument('-b', '--bucket-name', required=False,
                        dest='bucket_name',
                        help='Bucket name')
    parser.add_argument('-B', '--bucket-id', required=False, dest='bucket_id',
                        help='Bucket id')
    parser.add_argument('-u', '--upload', required=False, dest='upload_path',
                        help='Upload file or directory path', nargs='*')
    parser.add_argument('-d', '--download', required=False, dest='download',
                        nargs=2,
                        help='Download file source')  # , action='store_const')
    parser.add_argument('-n', '--new-bucket', required=False, dest='new_bucket',
                        nargs=2,
                        help='Create a new bucket [name, type]')
    parser.add_argument('-lb', '--list-buckets', required=False,
                        dest='list_buckets',
                        help='List buckets', action='store_true')
    parser.add_argument('-lf', '--list-files', required=False,
                        dest='list_files',
                        help='List files', action='store_true')
    parser.add_argument('-m', '--multithread', required=False, dest='mt',
                        help='Upload multithreaded worker queue size')
    args = parser.parse_args()

    if (not args.bucket_name and not args.bucket_id and not args.new_bucket and not args.list_buckets) or (
            args.bucket_name and args.bucket_id):
        parser.print_help()
        print("Must specify either -b/--bucket-name or -B/--bucket-id")
        sys.exit(1)

    # Consume config
    config = ConfigParser.ConfigParser()
    config.read(args.config_path)
    account_id = config.get('auth', 'account_id')
    app_key = config.get('auth', 'app_key')
    enc_pass = None
    try:
        enc_pass = config.get('encryption', 'password')
    except:
        pass

    if args.mt:
        b2 = BackBlazeB2(account_id, app_key, mt_queue_size=int(args.mt))
    else:
        b2 = BackBlazeB2(account_id, app_key)

    # Upload an entire directory concurrently, encrypt with a password
    if args.upload_path:
        for path in args.upload_path:
            print("recursive_upload: %s" % path)
            response = b2.recursive_upload(path, bucket_name=args.bucket_name,
                                           bucket_id=args.bucket_id,
                                           multithread=args.mt,
                                           password=enc_pass)
            print("Uploaded %d files" % (response))

    # Download
    if args.download:
        download_src, download_dst = args.download
        print("download_file_by_name: %s to %s" % (download_src, download_dst))
        response = b2.download_file_by_name(download_src, download_dst,
                                            bucket_name=args.bucket_name,
                                            bucket_id=args.bucket_id,
                                            password=enc_pass)
        print(response)

    # Create bucket
    # Currently requires -B or -b even if it doesn't exist
    if args.new_bucket:
        bucket_name, bucket_type = args.new_bucket
        response = b2.create_bucket(bucket_name, bucket_type)
        print(response)

    # List buckets
    if args.list_buckets:
        buckets = b2.list_buckets()
        for bucket in buckets['buckets']:
            print("%s %s %s" % (
                bucket['bucketType'], bucket['bucketId'], bucket['bucketName']))

    # List files in bucket
    if args.list_files:
        print("list_files: %s %s" % (args.bucket_name, args.bucket_id))
        files = b2.list_file_names(bucket_name=args.bucket_name,
                                   bucket_id=args.bucket_id)
        print("contentSha1 size uploadTimestamp fileName")
        for f in files['files']:
            print("%s %s %s %s" % (
                f['contentSha1'], f['size'], f['uploadTimestamp'], f['fileName']))
