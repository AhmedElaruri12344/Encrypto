from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode
import os

def derive_key(password: str, salt=None, iterations=100000, length=32):
    """Derive a key from a password."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode()), salt

# AES Encryption/Decryption
def aes_encrypt(plaintext, key):
    # Generate a random IV
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext.decode()

# RSA Encryption/Decryption
def rsa_encrypt(plaintext, public_key):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# RSA Key Generation
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private, pem_public

# AES Key Generation

def generate_aes_key(password: str, salt=None):
    """Generate a 256-bit AES key from a given password and salt."""
    if salt is None:
        salt = os.urandom(16)  # 128-bit salt

    # Use PBKDF2HMAC to derive a key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Derive the key
    return key, salt  # Return the key and salt

# Caesar Cipher
def caesar_cipher_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                start = ord('a')
            else:
                start = ord('A')
            encrypted_text += chr((ord(char) - start + shift_amount) % 26 + start)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_cipher_decrypt(text, shift):
    return caesar_cipher_encrypt(text, -shift)

# Simple Substitution
def simple_substitution_encrypt(text, key):
    key_map = {chr(i + ord('a')): char for i, char in enumerate(key.lower())}
    encrypted_text = ""
    for char in text:
        if char.lower() in key_map:
            encrypted_text += key_map[char.lower()].upper() if char.isupper() else key_map[char.lower()]
        else:
            encrypted_text += char
    return encrypted_text

def simple_substitution_decrypt(text, key):
    key_map = {chr(i + ord('a')): char for i, char in enumerate(key.lower())}
    reversed_key_map = {v: k for k, v in key_map.items()}
    decrypted_text = ""
    for char in text:
        if char.lower() in reversed_key_map:
            decrypted_text += reversed_key_map[char.lower()].upper() if char.isupper() else reversed_key_map[char.lower()]
        else:
            decrypted_text += char
    return decrypted_text

# General Encryption/Decryption
def encrypt(text, algorithm, key):
    if algorithm == 'AES':
        return aes_encrypt(text, key)
    elif algorithm == 'RSA':
        public_key = serialization.load_pem_public_key(key, backend=default_backend())
        return rsa_encrypt(text, public_key)
    elif algorithm == 'caesar':
        shift = int(key)
        return caesar_cipher_encrypt(text, shift)
    elif algorithm == 'simple_substitution':
        return simple_substitution_encrypt(text, key)
    else:
        raise ValueError("Unknown encryption algorithm specified")

def decrypt(text, algorithm, key):
    if algorithm == 'AES':
        return aes_decrypt(text, key)
    elif algorithm == 'RSA':
        private_key = serialization.load_pem_private_key(key, password=None, backend=default_backend())
        return rsa_decrypt(text, private_key)
    elif algorithm == 'caesar':
        shift = int(key)
        return caesar_cipher_decrypt(text, shift)
    elif algorithm == 'simple_substitution':
        return simple_substitution_decrypt(text, key)
    else:
        raise ValueError("Unknown decryption algorithm specified")

