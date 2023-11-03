import argparse
from cryptography.fernet import Fernet
import os

# Define your encryption and decryption functions
def encrypt_text(plain_text, key):
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(plain_text.encode())
    return cipher_text

def decrypt_text(cipher_text, key):
    cipher_suite = Fernet(key)
    plain_text = cipher_suite.decrypt(cipher_text).decode()
    return plain_text

# Generate the encryption key if it doesn't exist
def generate_key():
    if not os.path.isfile("encryption_key.key"):
        key = Fernet.generate_key()
        with open("encryption_key.key", "wb") as key_file:
            key_file.write(key)
        os.chmod("encryption_key.key", 0o600)  # Set file permissions to allow only the owner to read and write

# Define command-line arguments
parser = argparse.ArgumentParser(description="Text Encryption and Decryption Tool")
parser.add_argument("action", choices=["encrypt", "decrypt"], help="Specify action: 'encrypt' or 'decrypt")
parser.add_argument("file_path", help="Path to the file containing the text to be encrypted/decrypted")

args = parser.parse_args()

# Generate the key if it doesn't exist
generate_key()

# Load the key for both encryption and decryption
with open("encryption_key.key", "rb") as key_file:
    key = key_file.read()

# Handle the action based on user input
if args.action == "encrypt":
    # Perform encryption
    with open(args.file_path, "r") as file:
        plain_text = file.read()
    cipher_text = encrypt_text(plain_text, key)
    with open("encrypted_file.txt", "wb") as output_file:
        output_file.write(cipher_text)
    print("Text encrypted and saved to 'encrypted_file.txt'")

elif args.action == "decrypt":
    # Perform decryption
    with open(args.file_path, "rb") as file:
        cipher_text = file.read()
    plain_text = decrypt_text(cipher_text, key)
    with open("decrypted_file.txt", "w") as output_file:
        output_file.write(plain_text)
    print("Text decrypted and saved to 'decrypted_file.txt'")