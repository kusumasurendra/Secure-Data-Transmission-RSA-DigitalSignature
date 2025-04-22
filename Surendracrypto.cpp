#include <iostream>
#include <iomanip>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

using namespace std;

// AES Parameters
const int AES_KEY_SIZE = 32;
const int AES_IV_SIZE = 12;
const int AES_TAG_SIZE = 16;

// RSA Key Parameters
const int RSA_KEY_SIZE = 2048;
const int RSA_EXPONENT = 65537;

// First five weak primes
const int WEAK_PRIMES[] = {2, 3, 5, 7, 11};

// Personal Data for Validation
const string NAME = "Kusuma Surendra Paul";
const string REGISTRATION_NUMBER = "12410353";

// Check Key Security: No Name, No Registration Number, No Weak Primes
bool validateKey(const unsigned char* key, int size) {
    string keyStr(reinterpret_cast<const char*>(key), size);
    if (keyStr.find(NAME) != string::npos || keyStr.find(REGISTRATION_NUMBER) != string::npos) {
        cout << "⚠️ ATTACK DETECTED! Key contains sensitive user data." << endl;
        return false;
    }
    for (int prime : WEAK_PRIMES) {
        if (keyStr.find(to_string(prime)) != string::npos) {
            cout << "❌ Weak Key Detected! Prime numbers should not be used." << endl;
            return false;
        }
    }
    return true;
}

// Generate AES Random Key
void generateRandomKey(unsigned char* key, int size) {
    RAND_bytes(key, size);
    if (!validateKey(key, size)) {
        exit(EXIT_FAILURE);
    }
}

// **BEFORE MID-TERM: AES-128 ECB (Insecure)**
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

// **AFTER MID-TERM: AES-256 GCM (Secure)**
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

// RSA Key Pair Generation
RSA* generateRSAKey() {
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_EXPONENT);

    for (int prime : WEAK_PRIMES) {
        if (RSA_EXPONENT == prime) {
            cout << "⚠️ Weak RSA key detected! Exiting..." << endl;
            exit(EXIT_FAILURE);
        }
    }

    RSA* rsa = RSA_new();
    RSA_generate_key_ex(rsa, RSA_KEY_SIZE, bn, NULL);
    BN_free(bn);
    return rsa;
}

// Sign Data with RSA Private Key
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

int main() {
    // User Input
    string patientID, diagnosis, diseaseType;
    cout << "Enter Patient ID: "; getline(cin, patientID);
    cout << "Enter Diagnosis: "; getline(cin, diagnosis);
    cout << "Enter Disease Type: "; getline(cin, diseaseType);

    string plaintext = patientID + diagnosis + diseaseType;

    // Encryption Key Setup
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];
    generateRandomKey(key, AES_KEY_SIZE);
    generateRandomKey(iv, AES_IV_SIZE);

    string ciphertextECB, ciphertextGCM, tag;

    // **Before Mid-Term: AES-128 ECB**
    if (aes128ECBEncrypt(plaintext, ciphertextECB, key)) {
        cout << "\n🔓 Before Mid-Term (AES-128 ECB - Insecure) Encrypted Data: " << ciphertextECB << endl;
    }

    // **After Mid-Term: AES-256 GCM**
    if (aes256GCMEncrypt(plaintext, ciphertextGCM, tag, key, iv)) {
        cout << "\n🔒 After Mid-Term (AES-256 GCM - Secure) Encrypted Data: " << ciphertextGCM << "\n🛡️  Tag: " << tag << endl;
    }

    // Generate RSA Keys
    RSA* rsa = generateRSAKey();

    // Sign Encrypted Data
    string signature = signData(rsa, ciphertextGCM);
    cout << "✍️ Digital Signature: " << signature << endl;

    // Verify Signature
    if (verifySignature(rsa, ciphertextGCM, signature)) {
        cout << "✅ Signature Verified Successfully!" << endl;
    } else {
        cout << "❌ Signature Verification Failed!" << endl;
    }

    RSA_free(rsa);
    return 0;
}
