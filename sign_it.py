import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from base64 import b64encode

# Load the private key
private_key_path = os.path.expanduser("~/.ssh/id_rsa")
with open(private_key_path, "rb") as private_key_file:
    private_key = serialization.load_ssh_private_key(
        private_key_file.read(), password=None
    )

# Sign the message
message = b"Message to sign"
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Base64 encode the signature for easy display
signature_base64 = b64encode(signature).decode()
print("Signature: ", signature_base64)
