from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import utils
import os

# Step 1: ECC Key Exchange

class User:
    """
    Represents a user in the secure communication system.  Each user
    generates an ECC private/public key pair and can compute a shared
    secret with another user.
    """
    def __init__(self):
        # Generate an ECC private key using the SECP256R1 curve.
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()  # Derive the public key.

    def get_public_key_bytes(self):
        """
        Serializes the user's public key into PEM format for transmission.
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def compute_shared_secret(self, other_public_key_bytes):
        """
        Computes the shared secret using ECDH with the other user's
        public key and this user's private key.
        """
        # Load the other user's public key from its PEM representation.
        other_public_key = serialization.load_pem_public_key(
            other_public_key_bytes,
            backend=None  # Use default backend.
        )
        # Perform the key exchange (ECDH) to get the shared secret.
        return self.private_key.exchange(ec.ECDH(), other_public_key)

# Simulate two users, Alice and Bob.
alice = User()
bob = User()

# Exchange public keys over the untrusted network (simulated).
alice_public_key_bytes = alice.get_public_key_bytes()
bob_public_key_bytes = bob.get_public_key_bytes()

# Compute the shared secret at each end.
alice_shared_secret = alice.compute_shared_secret(bob_public_key_bytes)
bob_shared_secret = bob.compute_shared_secret(alice_public_key_bytes)

# Verify that the shared secrets match.
assert alice_shared_secret == bob_shared_secret, "Shared secrets do not match!"
print("Shared secret successfully established.")

# Step 2: Use the Shared Secret for Encryption

def encrypt_message(message, key):
    """
    Encrypts a message using AES-128 in CBC mode.  AES is much preferred
    over DES for security.
    """
    # Generate a random 16-byte Initialization Vector (IV).  Crucial for CBC.
    iv = os.urandom(16)
    # Create a Cipher object for AES encryption in CBC mode.
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()  # Get an encryptor object.

    # Pad the message to be a multiple of the AES block size (16 bytes).
    padded_message = message.ljust((len(message) + 15) // 16 * 16)
    # Encrypt the padded message.
    ciphertext = encryptor.update(padded_message.encode()) + encryptor.finalize()
    return iv + ciphertext  # Return IV + ciphertext (IV is needed for decryption).

def decrypt_message(ciphertext, key):
    """
    Decrypts a ciphertext using AES-128 in CBC mode.
    """
    iv = ciphertext[:16]  # Extract the IV from the beginning of the ciphertext.
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))  # Create Cipher object.
    decryptor = cipher.decryptor()  # Get a decryptor object.
    # Decrypt the ciphertext (excluding the IV).
    decrypted_message = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return decrypted_message.strip().decode()  # Remove padding and decode.

# Example financial transaction data.
financial_transaction = "Transaction Amount: $1234.56, Account Number: 9876-5432-10"
print(f"Original transaction data: {financial_transaction}")

# Use the shared secret (or a derived key) for encryption.  We use the first
# 16 bytes for AES-128.  In a real system, derive a key using a KDF.
encryption_key = alice_shared_secret[:16]  #  Use a portion of the shared secret.

# Alice encrypts the transaction data.
encrypted_data = encrypt_message(financial_transaction, encryption_key)
print(f"Encrypted data: {encrypted_data.hex()}")  # Display in hex for safety.

# Bob decrypts the transaction data.
decrypted_data = decrypt_message(encrypted_data, encryption_key)
print(f"Decrypted data: {decrypted_data}")

# Verify that the decryption was successful.
assert decrypted_data == financial_transaction, "Decryption failed!"

# Step 3: Ensure Security Against Eavesdroppers

print("\nSecurity Against Eavesdroppers:")
print("-  ECC (using SECP256R1) provides strong security due to the Elliptic Curve Discrete Logarithm Problem (ECDLP).")
print("-  The private keys are never transmitted; only public keys are exchanged.")
print("-  An eavesdropper would need to solve the ECDLP to derive the shared secret from the public keys, which is computationally infeasible.")
print("-  Using a 256-bit curve (SECP256R1) provides a very large key space, making brute-force attacks impossible.")

# Step 4: Implement Message Integrity and Authentication

def generate_hash(message):
    """
    Generates a SHA256 hash of the given message.
    """
    digest = hashes.Hash(hashes.SHA256())  # Use SHA256.
    digest.update(message.encode())  # Hash the message bytes.
    return digest.finalize()  # Get the final hash value.

def verify_hash(message, received_hash):
    """
    Verifies the integrity of a message by comparing its calculated hash
    with a received hash.
    """
    calculated_hash = generate_hash(message)
    return calculated_hash == received_hash

# Generate a hash of the original transaction data.
original_data_hash = generate_hash(financial_transaction)
print(f"Original data hash: {original_data_hash.hex()}")

# Simulate sending the encrypted data and the hash.
transmitted_data = (encrypted_data, original_data_hash)

# Bob receives the data and verifies its integrity.
received_encrypted_data, received_hash = transmitted_data
decrypted_transaction_data = decrypt_message(received_encrypted_data, encryption_key)

# Verify the integrity of the decrypted data.
if verify_hash(decrypted_transaction_data, received_hash):
    print("Message integrity is verified: Data has not been tampered with.")
else:
    print("Message integrity check failed: Data may have been altered!")
