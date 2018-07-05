# Copyright 2013 Google, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Contains an example of using Google Cloud Storage Signed URLs."""

import base64
import datetime
import hashlib
import os
import sys
import time
import requests

from oauth2client.service_account import ServiceAccountCredentials
from google.cloud import storage

try:
    import conf
except ImportError:
    sys.exit('Configuration module not found. You must create a conf.py file. '
             'See the example in conf.example.py.')

# The Google Cloud Storage API endpoint. You should not need to change this.
GCS_API_ENDPOINT = 'https://storage.googleapis.com'


class CloudStorageURLSigner(object):
    """Contains methods for generating signed URLs for Google Cloud Storage."""

    def __init__(self, creds, client_storage, client_id_email, gcs_api_endpoint, expiration=None,
                 session=None):
        """Creates a CloudStorageURLSigner that can be used to access signed URLs.

        Args:
          creds: A Google Account Service private key.
          service_account_email: GCS service account email.
          gcs_api_endpoint: Base URL for GCS API.
          expiration: An instance of datetime.datetime containing the time when the
                      signed URL should expire.
          session: A requests.session.Session to use for issuing requests. If not
                   supplied, a new session is created.
        """
        self.creds = creds
        self.client_storage = client_storage
        self.service_account_email = creds.service_account_email
        self.gcs_api_endpoint = gcs_api_endpoint

        self.expiration = expiration or (datetime.datetime.now() +
                                         datetime.timedelta(days=1))
        self.expiration = int(time.mktime(self.expiration.timetuple()))

        self.session = session or requests.Session()

    def __base64_sign(self, plaintext):
        """Signs and returns a base64-encoded SHA256 digest."""
        # shahash = hashlib.sha256(plaintext.encode('utf-8')).hexdigest()

        # signer = PKCS1_v1_5.new(self.key)
        # signature_bytes = signer.sign(shahash)
        # return base64.b64encode(signature_bytes)

        # creds = ServiceAccountCredentials.from_p12_keyfile(os.path.realpath('.'),  'private_key2.der')
        _, signature_bytes = self.creds.sign_blob(plaintext)
        signature = base64.b64encode(signature_bytes)
        return signature

    def __make_signature_string(self, verb, path, content_md5, content_type):
        """Creates the signature string for signing according to GCS docs."""
        signature_string = ('{verb}\n'
                            '{content_md5}\n'
                            '{content_type}\n'
                            '{expiration}\n'
                            '{resource}')
        return signature_string.format(verb=verb,
                                       content_md5=content_md5,
                                       content_type=content_type,
                                       expiration=self.expiration,
                                       resource=path)

    def __make_url(self, verb, path, content_type='', content_md5=''):
        """Forms and returns the full signed URL to access GCS."""
        base_url = '%s%s' % (self.gcs_api_endpoint, path)
        signature_string = self.__make_signature_string(verb, path, content_md5,
                                                        content_type)
        signature_signed = self.__base64_sign(signature_string)
        query_params = {'GoogleAccessId': self.service_account_email,
                        'Expires': str(self.expiration),
                        'Signature': signature_signed}
        return base_url, query_params

    def get(self, path):
        """Performs a GET request.

        Args:
          path: The relative API path to access, e.g. '/bucket/object'.

        Returns:
          An instance of requests.Response containing the HTTP response.
        """
        base_url, query_params = self.__make_url('GET', path)
        return self.session.get(base_url, params=query_params)

    def get_by_signed_url(self):
        bucket = self.client_storage.bucket(conf.BUCKET_NAME)
        blob = bucket.blob(conf.OBJECT_NAME)
        url_lifetime = self.expiration  # Seconds in an hour
        serving_url = blob.generate_signed_url(url_lifetime)
        return self.session.get(serving_url)

    def put(self, path, content_type, data):
        """Performs a PUT request.

        Args:
          path: The relative API path to access, e.g. '/bucket/object'.
          content_type: The content type to assign to the upload.
          data: The file data to upload to the new file.

        Returns:
          An instance of requests.Response containing the HTTP response.
        """
        md5_digest = base64.b64encode(hashlib.md5(data.encode('utf-8')).digest()).decode('utf-8')
        base_url, query_params = self.__make_url('PUT', path, content_type,
                                                 md5_digest)
        headers = {}
        headers['Content-Type'] = content_type
        headers['Content-Length'] = str(len(data))
        headers['Content-MD5'] = md5_digest
        resp = self.session.put(base_url, params=query_params, headers=headers,
                                data=data)
        return resp

    def generate_pre_signed_url(self, path, content_type):
        """Performs a presigned URL to PUT request.

        Args:
          path: The relative API path to access, e.g. '/bucket/object'.
          content_type: The content type to assign to the upload.
          data: The file data to upload to the new file.

        Returns:
          An instance of requests.Response containing the HTTP response.
        """
        base_url, query_params = self.__make_url('PUT', path, content_type)
        headers = {}
        headers['Content-Type'] = content_type
        resp = requests.Request('PUT', base_url, params=query_params, headers=headers).prepare()
        return resp.url

    def delete(self, path):
        """Performs a DELETE request.

        Args:
          path: The relative API path to access, e.g. '/bucket/object'.

        Returns:
          An instance of requests.Response containing the HTTP response.
        """
        base_url, query_params = self.__make_url('DELETE', path)
        return self.session.delete(base_url, params=query_params)


def process_response(r, expected_status=200):
    """Prints request and response information and checks for desired return code.

    Args:
      r: A requests.Response object.
      expected_status: The expected HTTP status code.

    Raises:
      SystemExit if the response code doesn't match expected_status.
    """
    print('--- Request ---')
    print(r.request.url)
    for header, value in r.request.headers.items():
        print('%s: %s' % (header, value))
    print('---------------')
    print('--- Response (Status %s) ---' % r.status_code)
    print(r.content)
    print('-----------------------------')
    print
    if r.status_code != expected_status:
        sys.exit('Exiting due to receiving %d status code when expecting %d.'
                 % (r.status_code, expected_status))


def main():
    try:
        keytext = open(conf.PRIVATE_KEY_PATH, 'rb').read()
    except IOError as e:
        sys.exit('Error while reading private key: %s' % e)

    creds = ServiceAccountCredentials.from_json_keyfile_name(conf.PRIVATE_KEY_PATH)
    client_storage = storage.Client.from_service_account_json(conf.PRIVATE_KEY_PATH)

    signer = CloudStorageURLSigner(creds, client_storage, conf.SERVICE_ACCOUNT_EMAIL,
                                   GCS_API_ENDPOINT)

    file_path = '/%s/%s' % (conf.BUCKET_NAME, conf.OBJECT_NAME)

    print('Creating presigned URL...')
    print('================')
    r = signer.generate_pre_signed_url(file_path, 'text/plain')
    print(r)

    print('Creating file...')
    print('================')
    r = signer.put(file_path, 'text/plain', 'blah blah')
    print(r)

    print('Retrieving file with signed URL...')
    print('==================')
    r = signer.get_by_signed_url()
    process_response(r)

    print('Retrieving file...')
    print('==================')
    r = signer.get(file_path)
    process_response(r)

    print('Deleting file...')
    print('================')
    r = signer.delete(file_path)
    process_response(r, expected_status=204)
    print('Done.')


if __name__ == '__main__':
    main()
