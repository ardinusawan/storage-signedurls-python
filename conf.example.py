import os.path

# The email address for your GCS service account being used for signatures.
SERVICE_ACCOUNT_EMAIL = ('merchant-upload-storage@mapan-merchant-dev.iam.gserviceaccount.com')

# Bucket name to use for writing example file.
BUCKET_NAME = 'stg-merchant-mapan-io'
# Object name to use for writing example file.
OBJECT_NAME = 'object.txt'

# Set this to the path of your service account private key file, in DER format.
#
# PyCrypto requires using the DER key format, but GCS provides key files in
# pkcs12 format. To convert between formats, you can use the provided commands
# below.
#
# The default password for p12 file is `notasecret`
# 
# Given a GCS key in pkcs12 format, convert it to PEM using this command:
#   openssl pkcs12 -in path/to/key.p12 -	nodes -nocerts > path/to/key.pem
# Given a GCS key in PEM format, convert it to DER format using this command:
#   openssl rsa -in privatekey.pem -inform PEM -out privatekey.der -outform DER
# PRIVATE_KEY_PATH = os.path.join(os.path.dirname(__file__), 'privatekey.der')

# BUT I'am using json key
PRIVATE_KEY_PATH = os.path.join(os.path.dirname(__file__), 'service_account.json')
