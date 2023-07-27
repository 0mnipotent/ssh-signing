import os
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from base64 import b64decode

# Load the public key
public_key_path = os.path.expanduser("~/.ssh/id_rsa.pub")
with open(public_key_path, "rb") as public_key_file:
    public_key = serialization.load_ssh_public_key(
        public_key_file.read()
    )

# The original message you signed
original_message = b"Message to sign"

# The signature from the sign_it.py script
signature_base64 = "Signature goes here"
signature = b64decode(signature_base64)

# Verify the signature
try:
    public_key.verify(
        signature,
        original_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Verification succeeded!")
except InvalidSignature:
    print("Verification failed!")
