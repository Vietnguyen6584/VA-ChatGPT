import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Function to derive a key from a user-provided key string
def derive_key(key_str, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = kdf.derive(key_str.encode())
    return key

# Function to encrypt a message with a key
def encrypt_message(message, key):
    # Generate an initialization vector (IV)
    iv = os.urandom(16)

    # Create a cipher object with the AES algorithm and CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    # Create a padder object to pad the message to a multiple of 128 bits
    padder = padding.PKCS7(128).padder()

    # Pad the message
    padded_message = padder.update(message.encode()) + padder.finalize()

    # Encrypt the padded message
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    # Return the IV and encrypted message
    return iv + encrypted_message

# Function to decrypt a message with a key
def decrypt_message(encrypted_message, key):
    # Extract the IV from the encrypted message
    iv = encrypted_message[:16]

    # Create a cipher object with the AES algorithm and CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    # Create an unpadder object to remove padding from the decrypted message
    unpadder = padding.PKCS7(128).unpadder()

    # Decrypt the message
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()

    # Remove padding from the decrypted message
    unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()

    # Return the decrypted message as a string
    return unpadded_message.decode()

# Get the message and key from the user
message = input("Enter the message to encrypt: ")
key_str = input("Enter the key: ")
salt = b'\xf8nHCf\xec\xf9V\x0c0\xf1\xc6 \xe5r ' #os.urandom(16)

# Derive a key from the user's input using PBKDF2
key = derive_key(key_str, salt)
# Encrypt the message
print(key)
encrypted_message = encrypt_message(message, key)

print("Encrypted message: " + encrypted_message.hex())

# Decrypt the message
decrypted_message = decrypt_message(encrypted_message, key)

print("Decrypted message: " + decrypted_message)
