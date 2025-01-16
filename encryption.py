from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import os


# RSA is an asymmetric encryption algorithm, meaning it uses two keys:

# Public Key (🔑) → Used to encrypt data.
# Private Key (🔒) → Used to decrypt data.


# 🔹 How RSA Works in Your Project
# The password is encrypted with the public key before being sent from the client.
# The server decrypts the password using the private key for authentication.
# RSA also secures communication between client and server.

def hash_password(password):
    salt = b'somesalt'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key.hex()

# 🔹 Explanation:
# Generates a 2048-bit RSA key pair.
# Saves private key to private.pem and public key to public.pem.
# The private key is used only on the server for decryption.
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# 🔹 Explanation:

# Uses the public key to encrypt data.
# Uses OAEP padding (Optimal Asymmetric Encryption Padding) for security.

def encrypt_rsa(public_key, plaintext):
    return public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# 🔹 Explanation:

# Uses the private key to decrypt messages.
# Uses OAEP padding for secure decryption.
def decrypt_rsa(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()


def save_rsa_keys(private_key, public_key):
    with open("private_key.pem", "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    with open("public_key.pem", "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

def load_rsa_keys():
    with open("private_key.pem", "rb") as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None,
            backend=default_backend()
        )
    with open("public_key.pem", "rb") as public_file:
        public_key = serialization.load_pem_public_key(
            public_file.read(),
            backend=default_backend()
        )
    return private_key, public_key

