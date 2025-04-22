#include <iostream>
#include <iomanip>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

const int AES_BLOCK_SIZE = 16;  // AES block size for 128-bit encryption
const int AES_KEY_SIZE = 16;    // AES-128 requires a 16-byte key

// AES-128 ECB Encryption
bool aes128ECBEncrypt(const string& plaintext, string& ciphertext, unsigned char* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error creating encryption context!" << endl;
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        cerr << "Error initializing AES-128 ECB encryption!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len;
    int ciphertext_len = plaintext.size() + AES_BLOCK_SIZE; 
    unsigned char encrypted[ciphertext_len];

    if (EVP_EncryptUpdate(ctx, encrypted, &len, (unsigned char*)plaintext.c_str(), plaintext.size()) != 1) {
        cerr << "Error during AES encryption!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int total_len = len;

    if (EVP_EncryptFinal_ex(ctx, encrypted + len, &len) != 1) {
        cerr << "Error finalizing AES encryption!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    total_len += len;

    ciphertext.assign((char*)encrypted, total_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// AES-128 ECB Decryption
bool aes128ECBDecrypt(const string& ciphertext, string& plaintext, unsigned char* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error creating decryption context!" << endl;
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        cerr << "Error initializing AES-128 ECB decryption!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len;
    unsigned char decrypted[ciphertext.size()];
    
    if (EVP_DecryptUpdate(ctx, decrypted, &len, (unsigned char*)ciphertext.c_str(), ciphertext.size()) != 1) {
        cerr << "Error during AES decryption!" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int total_len = len;

    if (EVP_DecryptFinal_ex(ctx, decrypted + len, &len) != 1) {
        cerr << "Decryption failed! Incorrect key or corrupted data." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    total_len += len;

    plaintext.assign((char*)decrypted, total_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

int main() {
    string patientID, diagnosis, diseaseType;
    cout << "Enter Patient ID: ";
    getline(cin, patientID);
    cout << "Enter Diagnosis: ";
    getline(cin, diagnosis);
    cout << "Enter Disease Type: ";
    getline(cin, diseaseType);

    string plaintext = patientID + diagnosis + diseaseType;

    unsigned char key[AES_KEY_SIZE];
    RAND_bytes(key, AES_KEY_SIZE);  // Generate a random key

    string ciphertext;
    if (aes128ECBEncrypt(plaintext, ciphertext, key)) {
        cout << "\n🔒 Encrypted Data (Hex): ";
        for (unsigned char c : ciphertext) {
            cout << hex << setw(2) << setfill('0') << (int)c;
        }
        cout << endl;
    }

    string decryptedText;
    if (aes128ECBDecrypt(ciphertext, decryptedText, key)) {
        cout << "\n✅ Decrypted Data: " << decryptedText << endl;
    } else {
        cout << "\n❌ Decryption failed!" << endl;
    }

    return 0;
}