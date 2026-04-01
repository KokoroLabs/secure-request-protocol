# Secure Request Protocol

Secure Request is designed as a full encryption protocol for secure messaging, featuring:

- Formatted metadata structure in `.srq` files  
- Message hashing for integrity  
- Digital signatures using Dilithium  
- Post-quantum encryption using Kyber  

This repository **does not yet implement the full protocol**.

### Current Status

The scripts here represent a **minimal viable encryption implementation** (pre-protocol). They demonstrate:

- Encrypting messages with Kyber (KEM)  
- Deriving a symmetric AES-GCM key from the shared secret via HKDF  
- Encrypting the message payload  

### Notes

- GUI and user-facing tools are **not included**  
- `.srq` file format, metadata, and signatures will be implemented in future updates  
- This repo serves as a **reference/demo** for the cryptographic foundation of Secure Request  
- Currently scripted for MacOS  

### Usage

Both Recipient and Sender must download the repo:

1. **Recipient** – generate keys locally with `generate_keys.py`.  
2. **Recipient** – share the generated file `Share this file.txt` with the Sender.  
3. **Sender** – download the shared file and run `create_message.py`. Type your message into the terminal.  
4. **Sender** – share the resulting `.srq` file with the Recipient.  
5. **Recipient** – read the message with `decrypt_message.py`.  
