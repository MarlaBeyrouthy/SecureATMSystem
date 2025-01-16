from Crypto.Random import get_random_bytes

KEY_FILE = "aes_key.txt"

def generate_aes_key():
    key = get_random_bytes(32)  # Ensure the key size is 32 bytes
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    print("New AES key generated and saved.")

generate_aes_key()

