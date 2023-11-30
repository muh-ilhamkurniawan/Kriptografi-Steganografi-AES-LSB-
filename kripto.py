from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
import os

def encrypt_text(key, text):
    key = key.encode('utf-8')
    text = text.encode('utf-8')

    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)

    # Pad the text to be a multiple of 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_text = padder.update(text) + padder.finalize()

    # Create an AES cipher object with the key, mode, and backend
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded text
    ciphertext = encryptor.update(padded_text) + encryptor.finalize()

    # Combine IV and ciphertext and encode in base64 for easy storage or transmission
    encrypted_data = b64encode(iv + ciphertext).decode('utf-8')

    return encrypted_data

def decrypt_text(key, encrypted_data):
    key = key.encode('utf-8')
    encrypted_data = b64decode(encrypted_data)

    # Extract IV from the first 16 bytes of the encrypted data
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    # Create an AES cipher object with the key, mode, and backend
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding from the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data.decode('utf-8')

# Contoh penggunaan
key = "kuncirahasiaanda"
plaintext = "Ini adalah teks rahasia."

encrypted_text = encrypt_text(key, plaintext)
print(f"Plaintext: {plaintext}")
print(f"Encrypted Text: {encrypted_text}")

decrypted_text = decrypt_text(key, encrypted_text)
print(f"Decrypted Text: {decrypted_text}")
