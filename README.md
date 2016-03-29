backblaze-b2
============
Python module for accessing the Backblaze B2 API


Examples
-----
    from backblazeb2 import BackBlazeB2
    b2 = BackBlazeB2(account_id, app_key)

    # Upload an entire directory concurrently, encrypt with a password
    b2.recursive_upload('/path/to/foobar', bucket_name='my-bucket', multithread=True, password='p@ssW0rdz')

    # Upload a single file without a password
    b2.upload_file('/path/to/file.txt', bucket_name='baz')

    # Upload a single file, password encrypted, then download & decrypt
    b2.upload_file('/path/to/secrets.txt', bucket_name='baz', password='supersecret')
    response = b2.download_file_by_name('/path/to/myfile.txt', 'savedfile.txt', password='supersecret')

    # List all of your buckets
    buckets = b2.list_buckets()

    # Create a bucket
    response = b2.create_bucket('new-bucket', bucket_type='allPrivate')

    # Download a file by name
    response = b2.download_file_by_name('/path/to/myfile.txt', 'savedfile.txt')
