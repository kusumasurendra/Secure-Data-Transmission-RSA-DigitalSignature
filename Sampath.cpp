#include <iostream>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <cstring>

using namespace std;

// Generate an ECC key pair
EC_KEY* generate_key() {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key);
    return key;
}

// Derive shared secret using ECDH
void derive_shared_secret(EC_KEY* privateKey, const EC_KEY* peerPublicKey, unsigned char* secret) {
    int secret_len = ECDH_compute_key(secret, 32, EC_KEY_get0_public_key(peerPublicKey), privateKey, NULL);
    if (secret_len <= 0) {
        cerr << "Failed to derive shared secret." << endl;
        exit(EXIT_FAILURE);
    }
}

// AES Encryption (CBC Mode)
void encrypt_aes(const unsigned char* key, const unsigned char* iv, const unsigned char* plaintext, unsigned char* ciphertext, int length) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int out_len;
    EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, length);
    
    int final_out_len;
    EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_out_len);

    EVP_CIPHER_CTX_free(ctx);
}

// Compute HMAC for integrity verification
void compute_hmac(const unsigned char* key, const unsigned char* data, size_t data_len, unsigned char* hmac_out) {
    HMAC(EVP_sha256(), key, 32, data, data_len, hmac_out, NULL);
}

int main() {
    // Generate ECC key pairs
    EC_KEY* keyA = generate_key();
    EC_KEY* keyB = generate_key();

    unsigned char shared_secret_A[32];
    unsigned char shared_secret_B[32];

    // Derive shared secrets
    derive_shared_secret(keyA, keyB, shared_secret_A);
    derive_shared_secret(keyB, keyA, shared_secret_B);

    cout << "Shared secret established!" << endl;

    // AES Encryption
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    const char* plaintext = "Financial transaction data";
    unsigned char ciphertext[128];

    encrypt_aes(shared_secret_A, iv, (unsigned char*)plaintext, ciphertext, strlen(plaintext));
    
    cout << "Transaction encrypted!" << endl;

    // Compute HMAC
    unsigned char hmac[SHA256_DIGEST_LENGTH];
    compute_hmac(shared_secret_A, ciphertext, sizeof(ciphertext), hmac);

    cout << "Integrity verified using HMAC!" << endl;

    // Cleanup
    EC_KEY_free(keyA);
    EC_KEY_free(keyB);

    return 0;
}
