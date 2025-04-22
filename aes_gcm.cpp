#include <iostream>
#include <iomanip>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

using namespace std;

// AES-256 GCM parameters
const int AES_KEY_SIZE = 32;
const int AES_IV_SIZE = 12;
const int AES_TAG_SIZE = 16;

// Generate a random key
void generateRandomKey(unsigned char* key, int size) {
    RAND_bytes(key, size);
}

// AES-256-GCM encryption
bool aes256GCMEncrypt(const string& plaintext, string& ciphertext, string& tag, unsigned char* key, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        cerr << "Error creating context" << endl;
        return false;
    }

    // Initialize encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        cerr << "Error initializing encryption" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Encrypt plaintext
    int len;
    unsigned char encrypted[plaintext.size()];
    if (EVP_EncryptUpdate(ctx, encrypted, &len, (unsigned char*)plaintext.c_str(), plaintext.size()) != 1) {
        cerr << "Error during encryption" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int encryptedLen = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, encrypted + len, &len) != 1) {
        cerr << "Error finalizing encryption" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    encryptedLen += len;

    // Get authentication tag
    unsigned char tagBuf[AES_TAG_SIZE];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tagBuf) != 1) {
        cerr << "Error getting tag" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext.assign((char*)encrypted, encryptedLen);
    tag.assign((char*)tagBuf, AES_TAG_SIZE);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// AES-256-GCM decryption
bool aes256GCMDecrypt(const string& ciphertext, const string& tag, string& plaintext, unsigned char* key, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        cerr << "Error creating context" << endl;
        return false;
    }

    // Initialize decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        cerr << "Error initializing decryption" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Decrypt ciphertext
    int len;
    unsigned char decrypted[ciphertext.size()];
    if (EVP_DecryptUpdate(ctx, decrypted, &len, (unsigned char*)ciphertext.c_str(), ciphertext.size()) != 1) {
        cerr << "Error during decryption" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int decryptedLen = len;

    // Set expected authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE, (void*)tag.data()) != 1) {
        cerr << "Error setting tag" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, decrypted + len, &len) != 1) {
        cerr << "Decryption failed — tag mismatch" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    decryptedLen += len;

    plaintext.assign((char*)decrypted, decryptedLen);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Generate HMAC-based digital signature
string generateHMAC(const string& message, unsigned char* key) {
    unsigned int len;
    unsigned char* hmac = HMAC(EVP_sha256(), key, AES_KEY_SIZE, (unsigned char*)message.c_str(), message.size(), NULL, &len);

    string signature((char*)hmac, len);
    return signature;
}

// Verify HMAC-based digital signature
bool verifyHMAC(const string& message, const string& signature, unsigned char* key) {
    string expected = generateHMAC(message, key);
    return (expected == signature);
}

int main() {
    // User input
    string patientID, diagnosis, diseaseType;

    cout << "Enter Patient ID: ";
    getline(cin, patientID);
    cout << "Enter Diagnosis: ";
    getline(cin, diagnosis);
    cout << "Enter Disease Type: ";
    getline(cin, diseaseType);

    string plaintext = patientID + diagnosis + diseaseType;

    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];

    generateRandomKey(key, AES_KEY_SIZE);
    generateRandomKey(iv, AES_IV_SIZE);

    string ciphertext, tag;

    // Encrypt
    if (aes256GCMEncrypt(plaintext, ciphertext, tag, key, iv)) {
        cout << "\n🔒 Encrypted Data: ";
        for (char c : ciphertext) {
            cout << hex << setw(2) << setfill('0') << (int)(unsigned char)c;
        }
        cout << "\n Tag: ";
        for (char t : tag) {
            cout << hex << setw(2) << setfill('0') << (int)(unsigned char)t;
        }
        cout << endl;
    }

    // Generate signature
    string signature = generateHMAC(ciphertext, key);
    cout << "Signature: ";
    for (char s : signature) {
        cout << hex << setw(2) << setfill('0') << (int)(unsigned char)s;
    }
    cout << endl;

    // Decrypt
    string decryptedText;
    if (aes256GCMDecrypt(ciphertext, tag, decryptedText, key, iv)) {
        cout << "\n Decrypted Data: " << decryptedText << endl;
    } else {
        cout << "\n Decryption failed." << endl;
    }

    // Verify signature
    if (verifyHMAC(ciphertext, signature, key)) {
        cout << "Signature Verification Successful!" << endl;
    } else {
        cout << "Signature Verification Failed!" << endl;
    }

    return 0;
}
