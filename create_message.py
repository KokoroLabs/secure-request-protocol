"""
This script takes user input as bytearray, references a file containing kyber public key, encrypts as .srq file,
wipes bytearray data.
Not a production level representation of message creation.
"""

import os
from datetime import datetime

from pqcrypto.kem.ml_kem_768 import encrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


KEY_FILE = "Share this file.txt"


def main():

    OUTPUT_FILE = datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + " Encrypted Message.srq"

    if not os.path.exists(KEY_FILE):
        print("public key not found")
        return

    # Load Kyber public key from the separate file
    with open(KEY_FILE, "r") as f:
        public_hex = f.read().strip()
    public_key = bytes.fromhex(public_hex)

    # Prompt user for input and convert to bytearray
    user_input = input("Enter the message to encrypt: ")
    plaintext = bytearray(user_input.encode())

    # Kyber encapsulation
    ciphertext_kem, shared_secret = encrypt(public_key)

    # Use HKDF to derive AES key from shared secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"srq-aes-key",
    )
    aes_key = hkdf.derive(shared_secret)

    aesgcm = AESGCM(aes_key)

    nonce = os.urandom(12)

    encrypted_data = aesgcm.encrypt(nonce, plaintext, None)

    # Overwrite plaintext bytearray with zeros
    for i in range(len(plaintext)):
        plaintext[i] = 0

    # Save encrypted container
    with open(OUTPUT_FILE, "wb") as f:
        f.write(ciphertext_kem)  # length is dynamic
        f.write(nonce)
        f.write(encrypted_data)

    print("Encrypted file saved as:", OUTPUT_FILE)
    print("KEM ciphertext length:", len(ciphertext_kem))
    print("Nonce length:", len(nonce))
    print("Encrypted payload length:", len(encrypted_data))
    print(plaintext)


if __name__ == "__main__":
    main()
