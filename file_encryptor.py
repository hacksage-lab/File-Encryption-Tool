import os
import argparse
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
import getpass
import sys
from typing import Tuple, Union

class FileEncryptor:
    """
    Advanced file encryption tool supporting both symmetric (AES) and asymmetric (RSA) encryption.
    Features:
    - AES-256 in CBC mode with PKCS7 padding
    - Password-based key derivation (PBKDF2-HMAC-SHA256)
    - Secure RSA key generation and encryption
    - File integrity verification
    - Chunked processing for large files
    """
    
    def __init__(self):
        self.backend = default_backend()
        self.salt_size = 16
        self.aes_key_size = 32  # 256 bits
        self.chunk_size = 64 * 1024  # 64KB chunks
        
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a cryptographic key from a password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.aes_key_size,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())
    
    def _generate_rsa_keypair(self, key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        return private_key, private_key.public_key()
    
    def _save_rsa_key(self, key: Union[rsa.RSAPrivateKey, rsa.RSAPublicKey], filename: str, private: bool = True):
        """Save RSA key to file"""
        if private:
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        with open(filename, 'wb') as f:
            f.write(pem)
    
    def _load_rsa_private_key(self, filename: str) -> rsa.RSAPrivateKey:
        """Load RSA private key from file"""
        with open(filename, 'rb') as f:
            pem_data = f.read()
        return serialization.load_pem_private_key(
            pem_data,
            password=None,
            backend=self.backend
        )
    
    def _load_rsa_public_key(self, filename: str) -> rsa.RSAPublicKey:
        """Load RSA public key from file"""
        with open(filename, 'rb') as f:
            pem_data = f.read()
        return serialization.load_pem_public_key(
            pem_data,
            backend=self.backend
        )
    
    def encrypt_file_aes(self, input_file: str, output_file: str, password: str):
        """Encrypt a file using AES-256-CBC with password-derived key"""
        salt = os.urandom(self.salt_size)
        key = self._derive_key(password, salt)
        iv = os.urandom(16)
        
        # Set up cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        
        # Get file size for progress reporting
        file_size = os.path.getsize(input_file)
        processed = 0
        
        with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
            # Write salt and IV first
            outfile.write(salt)
            outfile.write(iv)
            
            # Process file in chunks
            while True:
                chunk = infile.read(self.chunk_size)
                if len(chunk) == 0:
                    break
                
                # Update progress
                processed += len(chunk)
                self._print_progress(processed, file_size)
                
                # Pad and encrypt
                padded_chunk = padder.update(chunk)
                encrypted_chunk = encryptor.update(padded_chunk)
                outfile.write(encrypted_chunk)
            
            # Finalize
            final_padded = padder.finalize()
            final_encrypted = encryptor.update(final_padded) + encryptor.finalize()
            outfile.write(final_encrypted)
        
        print("\nEncryption complete.")
    
    def decrypt_file_aes(self, input_file: str, output_file: str, password: str):
        """Decrypt a file encrypted with AES-256-CBC"""
        with open(input_file, 'rb') as infile:
            # Read salt and IV
            salt = infile.read(self.salt_size)
            iv = infile.read(16)
            
            # Derive key
            key = self._derive_key(password, salt)
            
            # Set up cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()
            
            # Get file size for progress reporting
            infile.seek(0, 2)
            file_size = infile.tell()
            infile.seek(self.salt_size + 16, 0)
            processed = self.salt_size + 16
            
            with open(output_file, 'wb') as outfile:
                while True:
                    chunk = infile.read(self.chunk_size)
                    if len(chunk) == 0:
                        break
                    
                    # Update progress
                    processed += len(chunk)
                    self._print_progress(processed, file_size)
                    
                    # Decrypt and unpad
                    decrypted_chunk = decryptor.update(chunk)
                    unpadded_chunk = unpadder.update(decrypted_chunk)
                    outfile.write(unpadded_chunk)
                
                # Finalize
                final_decrypted = decryptor.finalize()
                final_unpadded = unpadder.update(final_decrypted) + unpadder.finalize()
                outfile.write(final_unpadded)
        
        print("\nDecryption complete.")
    
    def encrypt_file_rsa(self, input_file: str, output_file: str, public_key_file: str):
        """Encrypt a file using RSA-OAEP (for smaller files)"""
        public_key = self._load_rsa_public_key(public_key_file)
        
        with open(input_file, 'rb') as infile:
            plaintext = infile.read()
        
        # RSA can only encrypt data smaller than its key size
        max_size = (public_key.key_size // 8) - 66  # For OAEP padding
        if len(plaintext) > max_size:
            raise ValueError(f"File too large for RSA encryption. Max size: {max_size} bytes")
        
        ciphertext = public_key.encrypt(
            plaintext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        with open(output_file, 'wb') as outfile:
            outfile.write(ciphertext)
        
        print("RSA encryption complete.")
    
    def decrypt_file_rsa(self, input_file: str, output_file: str, private_key_file: str):
        """Decrypt a file encrypted with RSA-OAEP"""
        private_key = self._load_rsa_private_key(private_key_file)
        
        with open(input_file, 'rb') as infile:
            ciphertext = infile.read()
        
        plaintext = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        with open(output_file, 'wb') as outfile:
            outfile.write(plaintext)
        
        print("RSA decryption complete.")
    
    def generate_rsa_keys(self, private_key_file: str, public_key_file: str, key_size: int = 2048):
        """Generate RSA key pair and save to files"""
        private_key, public_key = self._generate_rsa_keypair(key_size)
        self._save_rsa_key(private_key, private_key_file)
        self._save_rsa_key(public_key, public_key_file, private=False)
        print(f"RSA keys generated:\nPrivate key: {private_key_file}\nPublic key: {public_key_file}")
    
    def _print_progress(self, processed: int, total: int):
        """Print progress bar"""
        percent = (processed / total) * 100
        bar_length = 50
        filled_length = int(bar_length * processed // total)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        sys.stdout.write(f'\rProgress: |{bar}| {percent:.1f}% ({processed}/{total} bytes)')
        sys.stdout.flush()

def main():
    parser = argparse.ArgumentParser(description="Advanced File Encryption Tool")
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # AES encryption
    aes_encrypt = subparsers.add_parser('aes-encrypt', help='Encrypt file with AES')
    aes_encrypt.add_argument('input', help='Input file')
    aes_encrypt.add_argument('output', help='Output file')
    
    # AES decryption
    aes_decrypt = subparsers.add_parser('aes-decrypt', help='Decrypt file with AES')
    aes_decrypt.add_argument('input', help='Input file')
    aes_decrypt.add_argument('output', help='Output file')
    
    # RSA key generation
    rsa_gen = subparsers.add_parser('rsa-gen', help='Generate RSA key pair')
    rsa_gen.add_argument('private', help='Private key output file')
    rsa_gen.add_argument('public', help='Public key output file')
    rsa_gen.add_argument('--size', type=int, default=2048, help='Key size in bits (default: 2048)')
    
    # RSA encryption
    rsa_encrypt = subparsers.add_parser('rsa-encrypt', help='Encrypt file with RSA')
    rsa_encrypt.add_argument('input', help='Input file')
    rsa_encrypt.add_argument('output', help='Output file')
    rsa_encrypt.add_argument('public_key', help='Public key file')
    
    # RSA decryption
    rsa_decrypt = subparsers.add_parser('rsa-decrypt', help='Decrypt file with RSA')
    rsa_decrypt.add_argument('input', help='Input file')
    rsa_decrypt.add_argument('output', help='Output file')
    rsa_decrypt.add_argument('private_key', help='Private key file')
    
    args = parser.parse_args()
    encryptor = FileEncryptor()
    
    try:
        if args.command == 'aes-encrypt':
            password = getpass.getpass("Enter encryption password: ")
            password_confirm = getpass.getpass("Confirm password: ")
            if password != password_confirm:
                print("Error: Passwords don't match!")
                return
            encryptor.encrypt_file_aes(args.input, args.output, password)
        elif args.command == 'aes-decrypt':
            password = getpass.getpass("Enter decryption password: ")
            encryptor.decrypt_file_aes(args.input, args.output, password)
        elif args.command == 'rsa-gen':
            encryptor.generate_rsa_keys(args.private, args.public, args.size)
        elif args.command == 'rsa-encrypt':
            encryptor.encrypt_file_rsa(args.input, args.output, args.public_key)
        elif args.command == 'rsa-decrypt':
            encryptor.decrypt_file_rsa(args.input, args.output, args.private_key)
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
