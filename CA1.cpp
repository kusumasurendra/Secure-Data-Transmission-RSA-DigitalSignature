#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>

using namespace std;

// --- Utility Functions ---

vector<uint8_t> stringToBytes(const string& str) {
    return vector<uint8_t>(str.begin(), str.end());
}

string bytesToHex(const vector<uint8_t>& bytes) {
    stringstream ss;
    ss << hex << setfill('0');
    for (uint8_t byte : bytes) {
        ss << setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

vector<uint8_t> hexToBytes(const string& hex) {
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        bytes.push_back(static_cast<uint8_t>(stoul(byteString, nullptr, 16)));
    }
    return bytes;
}

// --- Simplified AES-128 ECB (Illustrative - NOT SECURE FOR PRODUCTION) ---

vector<uint8_t> simplified_aes_128_ecb_encrypt(const vector<uint8_t>& plaintext, const vector<uint8_t>& key) {
    vector<uint8_t> ciphertext = plaintext;
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        ciphertext[i] ^= key[i % 16]; // Simple XOR for demonstration
    }
    return ciphertext;
}

vector<uint8_t> simplified_aes_128_ecb_decrypt(const vector<uint8_t>& ciphertext, const vector<uint8_t>& key) {
    vector<uint8_t> decrypted_plaintext = ciphertext;
    for (size_t i = 0; i < decrypted_plaintext.size(); ++i) {
        decrypted_plaintext[i] ^= key[i % 16]; // Reverse XOR
    }
    return decrypted_plaintext;
}

// --- Simplified AES-256 GCM (Illustrative - NOT SECURE FOR PRODUCTION) ---

vector<uint8_t> simplified_aes_256_gcm_encrypt(const vector<uint8_t>& plaintext, const vector<uint8_t>& key, vector<uint8_t>& tag, const vector<uint8_t>& iv) {
    cout << "\n--- Simplified AES-256 GCM Encryption ---" << endl;
    cout << "Plaintext: " << bytesToHex(plaintext) << endl;
    cout << "Key:       " << bytesToHex(key) << endl;
    cout << "IV:        " << bytesToHex(iv) << endl;

    vector<uint8_t> ciphertext = plaintext;
    for (size_t i = 0; i < ciphertext.size() && i < key.size(); ++i) {
        ciphertext[i] ^= key[i % key.size()];
    }
    vector<uint8_t> temp_tag(16);
    for (size_t i = 0; i < temp_tag.size() && i < ciphertext.size(); ++i) {
        temp_tag[i] = ciphertext[i] % 256;
    }
    tag = temp_tag;
    cout << "Ciphertext: " << bytesToHex(ciphertext) << endl;
    cout << "Tag:        " << bytesToHex(tag) << endl;
    return ciphertext;
}

vector<uint8_t> simplified_aes_256_gcm_decrypt(const vector<uint8_t>& ciphertext, const vector<uint8_t>& key, const vector<uint8_t>& received_tag, const vector<uint8_t>& iv) {
    cout << "\n--- Simplified AES-256 GCM Decryption ---" << endl;
    cout << "Ciphertext: " << bytesToHex(ciphertext) << endl;
    cout << "Key:        " << bytesToHex(key) << endl;
    cout << "IV:         " << bytesToHex(iv) << endl;
    cout << "Received Tag: " << bytesToHex(received_tag) << endl;

    vector<uint8_t> decrypted_plaintext = ciphertext;
    for (size_t i = 0; i < decrypted_plaintext.size() && i < key.size(); ++i) {
        decrypted_plaintext[i] ^= key[i % key.size()];
    }
    vector<uint8_t> calculated_tag(16);
    for (size_t i = 0; i < calculated_tag.size() && i < ciphertext.size(); ++i) {
        calculated_tag[i] = ciphertext[i] % 256;
    }
    if (calculated_tag == received_tag) {
        cout << "Tag Verification: SUCCESS" << endl;
        cout << "Decrypted Plaintext: " << bytesToHex(decrypted_plaintext) << endl;
        return decrypted_plaintext;
    } else {
        cout << "Tag Verification: FAILURE - Data integrity compromised!" << endl;
        return {};
    }
}

int main() {
    string patient_id, patient_name, disease, diagnosis;

    cout << "Enter Patient ID: ";
    getline(cin, patient_id);

    cout << "Enter Patient Name: ";
    getline(cin, patient_name);

    cout << "Enter Disease: ";
    getline(cin, disease);

    cout << "Enter Diagnosis: ";
    getline(cin, diagnosis);

    string combined_data = patient_id + patient_name + disease + diagnosis;
    vector<uint8_t> plaintext_bytes = stringToBytes(combined_data);

    cout << "\n📝 Plaintext Before Encryption: " << combined_data << endl << endl;

    // --- Simplified AES-256 GCM ---
    vector<uint8_t> aes256_key = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    vector<uint8_t> gcm_iv = {0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5}; // 12 bytes IV
    vector<uint8_t> gcm_tag_bytes;
    vector<uint8_t> gcm_ciphertext_bytes = simplified_aes_256_gcm_encrypt(plaintext_bytes, aes256_key, gcm_tag_bytes, gcm_iv);
    string gcm_ciphertext_hex = bytesToHex(gcm_ciphertext_bytes);
    string gcm_tag_hex = bytesToHex(gcm_tag_bytes);
    vector<uint8_t> gcm_decrypted_bytes = simplified_aes_256_gcm_decrypt(gcm_ciphertext_bytes, aes256_key, gcm_tag_bytes, gcm_iv);
    string gcm_decrypted_text = string(gcm_decrypted_bytes.begin(), gcm_decrypted_bytes.end());

    cout << "🔒 AES-256 GCM Encrypted Data: " << gcm_ciphertext_hex << endl;
    cout << "🔑 AES-256 Key (256-bit/32 bytes): " << bytesToHex(aes256_key) << endl;
    cout << "🛡️  Tag: " << gcm_tag_hex << endl;
    cout << "🔑 IV (12 bytes): " << bytesToHex(gcm_iv) << endl << endl;
    cout << "🔓 AES-256 GCM Decrypted Text: " << gcm_decrypted_text << endl;
    cout << "🛡️ Tag: " << gcm_tag_hex << endl << endl;

    return 0;
}