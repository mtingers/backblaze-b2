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

    # Authorize download for a private file
    bucket_id = "" # Id of bucket which you want authorize download file
    bucket_name = "" # Verbose name of bucket
    file_name_prefix = ""
    url_authorized_download = b2.get_download_authorization(
        bucket_id=bucket_id, bucket_name=bucket_name,
        file_name_prefix=file_name_prefix)
    # The response some looks like this:
    # https://f345.backblazeb2.com/file/photos/cute/kitten.jpg?Authorization=3_20160803004041_53982a92f631a8c7303e3266_d940c7f5ee17cd1de3758aaacf1024188bc0cd0b_000_20160804004041_0006_dnld

    # Download with authorized url
    b2.download_file_with_authorized_url(url_authorized_download, 'file_name.log')
