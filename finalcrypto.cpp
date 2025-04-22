#include <iostream>
#include <iomanip>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

using namespace std;

// AES parameters
const int AES_KEY_SIZE_128 = 16;  // AES-128 Key size (ECB mode)
const int AES_KEY_SIZE_256 = 32;  // AES-256 Key size (GCM mode)
const int AES_IV_SIZE = 12;
const int AES_TAG_SIZE = 16;

// RSA parameters
const int RSA_KEY_SIZE = 2048;
const int RSA_EXPONENT = 65537;
const int WEAK_PRIMES[] = {2, 3, 5, 7, 11};

// Function to validate RSA key
bool isWeakRSAKey(int exponent) {
    for (int prime : WEAK_PRIMES) {
        if (exponent == prime) {
            cout << "⚠️ Weak RSA key detected! Exiting..." << endl;
            return true;
        }
    }
    return false;
}

// AES-128-ECB Encryption (Weak Encryption)
bool aes128ECBEncrypt(const string& plaintext, string& ciphertext, unsigned char* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);

    int len;
    unsigned char encrypted[plaintext.size()];
    EVP_EncryptUpdate(ctx, encrypted, &len, (unsigned char*)plaintext.c_str(), plaintext.size());
    int encryptedLen = len;

    EVP_EncryptFinal_ex(ctx, encrypted + len, &len);
    encryptedLen += len;

    ciphertext.assign((char*)encrypted, encryptedLen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// AES-256-GCM Encryption (Strong Encryption)
bool aes256GCMEncrypt(const string& plaintext, string& ciphertext, string& tag, unsigned char* key, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);

    int len;
    unsigned char encrypted[plaintext.size()];
    EVP_EncryptUpdate(ctx, encrypted, &len, (unsigned char*)plaintext.c_str(), plaintext.size());
    int encryptedLen = len;

    EVP_EncryptFinal_ex(ctx, encrypted + len, &len);
    encryptedLen += len;

    unsigned char tagBuf[AES_TAG_SIZE];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tagBuf);

    ciphertext.assign((char*)encrypted, encryptedLen);
    tag.assign((char*)tagBuf, AES_TAG_SIZE);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// RSA Key Generation (Avoiding Weak Keys)
RSA* generateRSAKey() {
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_EXPONENT);

    if (isWeakRSAKey(RSA_EXPONENT)) {
        exit(EXIT_FAILURE);
    }

    RSA* rsa = RSA_new();
    RSA_generate_key_ex(rsa, RSA_KEY_SIZE, bn, NULL);
    BN_free(bn);
    return rsa;
}

// Sign Encrypted Data with RSA
string signData(RSA* rsa, const string& data) {
    unsigned char signature[RSA_size(rsa)];
    unsigned int sigLen;

    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    
    EVP_SignInit(mdCtx, EVP_sha256());
    EVP_SignUpdate(mdCtx, data.c_str(), data.size());
    EVP_SignFinal(mdCtx, signature, &sigLen, pkey);

    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(pkey);

    return string(reinterpret_cast<char*>(signature), sigLen);
}

// Verify RSA Signature
bool verifySignature(RSA* rsa, const string& data, const string& signature) {
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    EVP_VerifyInit(mdCtx, EVP_sha256());
    EVP_VerifyUpdate(mdCtx, data.c_str(), data.size());

    int result = EVP_VerifyFinal(mdCtx, (unsigned char*)signature.c_str(), signature.size(), pkey);

    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(pkey);

    return result == 1;
}

// Main Function
int main() {
    string patientID, diagnosis, diseaseType;
    string keyInput, ivInput;
    
    cout << "Enter Patient ID: ";
    getline(cin, patientID);
    cout << "Enter Diagnosis: ";
    getline(cin, diagnosis);
    cout << "Enter Disease Type: ";
    getline(cin, diseaseType);

    string plaintext = patientID + diagnosis + diseaseType;
    cout << "\n📝 Plaintext Patient Data: " << plaintext << endl;

    unsigned char key128[AES_KEY_SIZE_128];
    unsigned char key256[AES_KEY_SIZE_256];
    unsigned char iv[AES_IV_SIZE];

    cout << "\nEnter AES-128 Key (16 characters): ";
    cin >> keyInput;
    memcpy(key128, keyInput.c_str(), AES_KEY_SIZE_128);

    cout << "\nEnter AES-256 Key (32 characters): ";
    cin >> keyInput;
    memcpy(key256, keyInput.c_str(), AES_KEY_SIZE_256);

    cout << "\nEnter IV for AES-GCM (12 characters): ";
    cin >> ivInput;
    memcpy(iv, ivInput.c_str(), AES_IV_SIZE);

    string ciphertext128, ciphertext256, tag;

    // Encrypt using AES-128-ECB (Insecure)
    if (aes128ECBEncrypt(plaintext, ciphertext128, key128)) {
        cout << "\n🔴 AES-128-ECB Encrypted Output (Weak Security):\n" << ciphertext128 << endl;
    }

    // Encrypt using AES-256-GCM (Secure)
    if (aes256GCMEncrypt(plaintext, ciphertext256, tag, key256, iv)) {
        cout << "\n🟢 AES-256-GCM Encrypted Output (Strong Security):\n" << ciphertext256 << endl;
        cout << "🛡️ Authentication Tag: " << tag << endl;
    }

    // Generate RSA Keys
    RSA* rsa = generateRSAKey();

    // Sign Encrypted Data (AES-256-GCM)
    string signature = signData(rsa, ciphertext256);
    cout << "\n✍️ Digital Signature: " << signature << endl;

    // Verify Signature
    if (verifySignature(rsa, ciphertext256, signature)) {
        cout << "✅ Signature Verification Successful!" << endl;
    } else {
        cout << "❌ Signature Verification Failed!" << endl;
    }

    RSA_free(rsa);
    return 0;
}
