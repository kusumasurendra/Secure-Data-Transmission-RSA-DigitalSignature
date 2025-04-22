#include <iostream>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>

using namespace std;

const int AES_KEY_SIZE = 32; // AES-256 key size = 32 bytes
const int AES_IV_SIZE = 12;  // GCM recommended IV size = 12 bytes
const int RSA_KEY_SIZE = 2048;
const int TAG_SIZE = 16; // Authentication tag size

// Generate random key and IV
void generate_key_and_iv(unsigned char* key, unsigned char* iv) {
    RAND_bytes(key, AES_KEY_SIZE);
    RAND_bytes(iv, AES_IV_SIZE);
}

// AES-256-GCM Encryption
int encrypt(const unsigned char* plaintext, int plaintext_len,
            const unsigned char* key, const unsigned char* iv,
            unsigned char* ciphertext, unsigned char* tag) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;

    // Initialize encryption context for AES-256-GCM
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);

    // Encrypt the data
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    // Finalize encryption
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    // Get the authentication tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// RSA Key Generation
RSA* generate_rsa_key() {
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);

    if (RSA_generate_key_ex(rsa, RSA_KEY_SIZE, e, NULL) != 1) {
        cout << "RSA key generation failed" << endl;
        exit(1);
    }

    BN_free(e);
    return rsa;
}

// Create RSA Signature
int sign_data(RSA* rsa, const unsigned char* data, size_t data_len,
              unsigned char* signature) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_PKEY* signing_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(signing_key, rsa);

    size_t sig_len;

    EVP_SignInit(md_ctx, EVP_sha256());
    unsigned int len = 0;
    EVP_SignFinal(md_ctx, signature, &len, signing_key);
    sig_len = len;  // If you still need sig_len as size_t elsewhere
    EVP_SignFinal(md_ctx, signature, &sig_len, signing_key);

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(signing_key);

    return sig_len;
}

// Example Usage
int main() {
    // Sample plaintext data (e.g., patient record)
    const char* plaintext = "Patient Record: John Doe, Age: 32, Blood Type: A+";
    int plaintext_len = strlen(plaintext);

    // Generate AES key and IV
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];
    generate_key_and_iv(key, iv);

    unsigned char ciphertext[128];
    unsigned char tag[TAG_SIZE];

    // Encrypt the plaintext using AES-256-GCM
    int ciphertext_len = encrypt((unsigned char*)plaintext, plaintext_len, key, iv, ciphertext, tag);

    cout << "Encrypted Data: ";
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    cout << endl;

    // Generate RSA keys
    RSA* rsa = generate_rsa_key();

    // Sign the ciphertext
    unsigned char signature[256];
    int signature_len = sign_data(rsa, ciphertext, ciphertext_len, signature);

    cout << "\nSignature: ";
    for (int i = 0; i < signature_len; i++) {
        printf("%02x", signature[i]);
    }
    cout << endl;

    // Cleanup
    RSA_free(rsa);

    return 0;
}
