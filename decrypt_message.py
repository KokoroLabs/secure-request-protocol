"""
This script takes .srq, references a file with kyber private key, decrypts .srq file as bytearray,
wipes bytearray data.
Not a production level representation of decryption.
"""

import os

from pqcrypto.kem.ml_kem_768 import decrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

OUTPUT_FILE = "decrypted_test.txt"
KEY_FILE = "kyber_keys.txt"

# ML-KEM-768 ciphertext size (fixed by the algorithm)
KEM_CIPHERTEXT_SIZE = 1088

# List all .srq files in the current directory
srq_files = [f for f in os.listdir('.') if f.endswith('.srq')]

if not srq_files:
    print("No .srq files found in the current directory.")
    exit()

print("Select a .srq file to decrypt:")
for idx, filename in enumerate(srq_files, start=1):
    print(f"{idx}. {filename}")

try:
    choice = int(input("Enter the number corresponding to the file: "))
    if choice < 1 or choice > len(srq_files):
        print("Invalid selection.")
        exit()
except ValueError:
    print("Invalid input. Please enter a number.")
    exit()

INPUT_FILE = srq_files[choice - 1]


def main():

    if not os.path.exists(INPUT_FILE):
        print(f"{INPUT_FILE} not found")
        return

    if not os.path.exists(KEY_FILE):
        print("kyber_keys.txt not found")
        return

    # Load Kyber private key from text file
    with open(KEY_FILE, "r") as f:
        content = f.read()

    # Extract private key from the text file
    private_hex = content.split('PRIVATE_KEY:\n')[1].split('\n')[0]
    private_key = bytes.fromhex(private_hex)

    # Read encrypted container
    with open(INPUT_FILE, "rb") as f:
        data = f.read()

    # Split container parts
    kem_ciphertext = data[:KEM_CIPHERTEXT_SIZE]
    nonce = data[KEM_CIPHERTEXT_SIZE:KEM_CIPHERTEXT_SIZE + 12]
    encrypted_data = data[KEM_CIPHERTEXT_SIZE + 12:]

    # Recover shared secret using Kyber private key
    shared_secret = decrypt(private_key, kem_ciphertext)

    # Reconstruct AES key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"srq-aes-key",
    )
    aes_key = hkdf.derive(shared_secret)

    aesgcm = AESGCM(aes_key)

    # Decrypt file
    plaintext = bytearray(aesgcm.decrypt(nonce, encrypted_data, None))
    print(plaintext.decode('utf-8'))
    # Overwrite plaintext in memory with zeros
    for i in range(len(plaintext)):
        plaintext[i] = 0


if __name__ == "__main__":
    main()
