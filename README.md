backblaze-b2
============
Python module for accessing the Backblaze B2 API


Examples
-----
    from backblazeb2 import BackBlazeB2
    b2 = BackBlazeB2(account_id, app_key)
    b2.recursive_upload_mt('/path/to/foobar', bucket_name='my-bucket')

