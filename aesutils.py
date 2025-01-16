from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os




import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from Crypto.Random import get_random_bytes  


KEY_FILE = "aes_key.txt"

def generate_aes_key():
    key = get_random_bytes(32)  # Ensure the key size is 32 bytes(32 bytes = 256-bit encryption)
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    print("New AES key generated and saved.")

if not os.path.exists(KEY_FILE):
    generate_aes_key()  # ✅ Only generate a key if it doesn't exist

def load_aes_key():
    with open(KEY_FILE, "rb") as key_file:
        key = key_file.read()
    if len(key) not in [16, 24, 32]:
        raise ValueError(f"Invalid AES key size: {len(key)} bytes")
    return key

#  Explanation:

# IV (Initialization Vector) is generated randomly for security.
# Data is padded (AES requires blocks of fixed size).
# Encryption is done using CBC mode.
# The result is encoded in Base64 for easy storage.

def encrypt_aes(data, key):
    iv = os.urandom(16) # Generate a random IV (Initialization Vector 16 byte)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + ciphertext).decode()

#  Explanation:

# Base64 decoding is done first.
# IV is extracted (needed for CBC mode decryption).
# Decryption is performed.
# Padding is removed to get the original text.
def decrypt_aes(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data) #: Converts Base64 back to raw bytes.
    iv = encrypted_data[:16] #The first 16 bytes are the IV.
    ciphertext = encrypted_data[16:] #The rest is the encrypted text.

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data.decode()


if __name__ == "__main__":
    # Example usage
    key = generate_aes_key()
    print(f"Generated AES key: {base64.b64encode(key).decode()}")

    plaintext = "This is a secret message."
    print(f"Plaintext: {plaintext}")

    encrypted = encrypt_aes(plaintext, key)
    print(f"Encrypted: {encrypted}")

    decrypted = decrypt_aes(encrypted, key)
    print(f"Decrypted: {decrypted}")

