# file encrypter

# Advanced File Encryption Tool

A secure file encryption tool written in Python that supports both symmetric (AES-256) and asymmetric (RSA) encryption methods.

## Features

- **AES-256-CBC Encryption**
  - Password-based encryption with PBKDF2 key derivation
  - Random salt and initialization vector (IV) for each encryption
  - PKCS7 padding for block alignment
  - Chunked processing for large files
  - Progress reporting during operations

- **RSA Encryption**
  - RSA-OAEP padding with SHA256
  - Secure key generation (2048-bit or 4096-bit)
  - Public/private key pair management

- **Security Features**
  - Uses Python's cryptography.hazmat primitives
  - Proper key derivation with 100,000 iterations
  - Random salts and IVs for each operation
  - Secure key storage in PEM format

## Installation

1. Ensure you have Python 3.6+ installed
2. Install the required dependencies:

bash
pip install cryptography

Encrypt a file:
bash

python file_encryptor.py aes-encrypt input.txt output.enc

You will be prompted to enter and confirm an encryption password.

Decrypt a file:
bash
```
python file_encryptor.py aes-decrypt output.enc decrypted.txt
```
You will be prompted to enter the decryption password.
RSA Key Management

Generate RSA key pair:
bash
```
python file_encryptor.py rsa-gen private_key.pem public_key.pem [--size 2048]
```
Optional --size parameter specifies key size in bits (default: 2048).
RSA Encryption/Decryption

Encrypt a file with RSA (for small files):
bash
```
python file_encryptor.py rsa-encrypt small_file.txt encrypted.rsa public_key.pem
```
Decrypt a file with RSA:
bash
```
python file_encryptor.py rsa-decrypt encrypted.rsa decrypted.txt private_key.pem
```
Security Notes

    Password Strength: Use strong passwords for AES encryption (minimum 12 characters, mix of character types)

    Key Protection: Keep private keys secure and never share them

    File Size Limitations: RSA encryption is only suitable for small files (smaller than key size minus padding)

    Large Files: For large files, use AES encryption

    Salt and IV: These are generated automatically and included in the encrypted fil
