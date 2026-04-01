"""
Generate Kyber Public/Private keys and saves to .txt.
Generates file of public key for sharing.
This is not a production level implementation of proper key handling.
This is representative of key generation.
"""

import os
import sys
from pqcrypto.kem.ml_kem_768 import generate_keypair

if os.path.exists("kyber_keys.txt") or os.path.exists("Share this file.txt"):
    print("Key files already exist. Exiting.")
    sys.exit()

# Generate Kyber (ML-KEM) keypair
public_key, private_key = generate_keypair()

# Verify key lengths
assert len(public_key) == 1184, f"Unexpected public key length: {len(public_key)}"
assert len(private_key) == 2400, f"Unexpected private key length: {len(private_key)}"

with open("kyber_keys.txt", "w") as f:
    f.write("PUBLIC_KEY:\n")
    f.write(public_key.hex() + "\n\n")
    f.write("PRIVATE_KEY:\n")
    f.write(private_key.hex() + "\n")

print("Keys saved to kyber_keys.txt")

# Save only the public key to a separate file
with open("Share this file.txt", "w") as f:
    f.write(public_key.hex())

print("Public key saved to 'Share this file.txt'")
