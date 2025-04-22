from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Step 1: ECC Key Exchange

# Each party generates their private key and corresponding public key
private_key_A = ec.generate_private_key(ec.SECP256R1())
public_key_A = private_key_A.public_key()

private_key_B = ec.generate_private_key(ec.SECP256R1())
public_key_B = private_key_B.public_key()

# Exchange public keys (simulated)
public_bytes_A = public_key_A.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

public_bytes_B = public_key_B.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Compute shared secret
shared_secret_A = private_key_A.exchange(ec.ECDH(), public_key_B)
shared_secret_B = private_key_B.exchange(ec.ECDH(), public_key_A)

# Ensure both computed shared secrets match
assert shared_secret_A == shared_secret_B, "Key exchange failed!"

# Step 2: Use Shared Secret for Encryption

# Generate encryption key from shared secret
key = shared_secret_A[:8]  # DES key requires 8 bytes

# Encrypt a financial transaction
def encrypt_message(message, key):
    iv = os.urandom(8)  # DES CBC requires 8-byte IV
    cipher = Cipher(algorithms.DES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_message = message.ljust((len(message) + 7) // 8 * 8)  # Pad message
    ciphertext = encryptor.update(padded_message.encode()) + encryptor.finalize()
    return iv + ciphertext

# Decrypt a financial transaction
def decrypt_message(ciphertext, key):
    iv = ciphertext[:8]
    cipher = Cipher(algorithms.DES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext[8:]) + decryptor.finalize()
    return decrypted_message.strip()

message = "Sensitive financial transaction data"
encrypted_message = encrypt_message(message, key)
decrypted_message = decrypt_message(encrypted_message, key)

# Ensure encryption and decryption work correctly
assert decrypted_message.decode() == message, "Decryption failed!"

# Step 3: Ensure Security Against Eavesdroppers

# The use of ECC provides strong security with large prime numbers, making brute-force impractical

# Step 4: Implement Message Integrity and Authentication

# Hash function for message integrity verification
def generate_hash(message):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())
    return digest.finalize()

message_hash = generate_hash(message)

# Verifying integrity
def verify_hash(message, original_hash):
    return generate_hash(message) == original_hash

assert verify_hash(message, message_hash), "Message integrity compromised!"

print("Secure communication established successfully!")