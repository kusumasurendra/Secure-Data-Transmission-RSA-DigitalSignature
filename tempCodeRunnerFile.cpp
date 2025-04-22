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

// --- Simplified Digital Signature (Illustrative - NOT SECURE FOR PRODUCTION) ---

vector<uint8_t> simplified_rsa_sign(const vector<uint8_t>& data, const vector<uint8_t>& private_key) {
    cout << "\n--- Simplified RSA Signing ---" << endl;
    cout << "Data to Sign: " << bytesToHex(data) << endl;
    cout << "Private Key:  " << bytesToHex(private_key) << endl;

    vector<uint8_t> signature = data;
    for (size_t i = 0; i < signature.size() && i < private_key.size(); ++i) {
        signature[i] ^= private_key[i % private_key.size()];
    }
    cout << "Signature:    " << bytesToHex(signature) << endl;
    return signature;
}

bool simplified_rsa_verify(const vector<uint8_t>& data, const vector<uint8_t>& signature, const vector<uint8_t>& public_key) {
    cout << "\n--- Simplified RSA Verification ---" << endl;
    cout << "Data to Verify: " << bytesToHex(data) << endl;
    cout << "Signature:      " << bytesToHex(signature) << endl;
    cout << "Public Key:     " << bytesToHex(public_key) << endl;

    vector<uint8_t> reconstructed_data = signature;
    for (size_t i = 0; i < reconstructed_data.size() && i < public_key.size(); ++i) {
        reconstructed_data[i] ^= public_key[i % public_key.size()];
    }
    bool is_valid = (reconstructed_data == data);
    cout << "Verification Result: " << (is_valid ? "SUCCESS" : "FAILURE - Signature is invalid!") << endl;
    return is_valid;
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

    // --- Simplified AES-128 ECB ---
    vector<uint8_t> aes128_key = stringToBytes("Surendra12345678");  // exactly 16 bytes
    vector<uint8_t> ecb_ciphertext_bytes = simplified_aes_128_ecb_encrypt(plaintext_bytes, aes128_key);
    string ecb_ciphertext_hex = bytesToHex(ecb_ciphertext_bytes);
    vector<uint8_t> ecb_decrypted_bytes = simplified_aes_128_ecb_decrypt(ecb_ciphertext_bytes, aes128_key);
    string ecb_decrypted_text = string(ecb_decrypted_bytes.begin(), ecb_decrypted_bytes.end());

    cout << "🔒 AES-128 ECB Encrypted Data: " << ecb_ciphertext_hex << endl << endl;
    cout << "🔑 AES-128 Key (128-bit/16 bytes): " << bytesToHex(aes128_key) << endl << endl;
    cout << "🔓 AES-128 ECB Decrypted Text: " << ecb_decrypted_text << endl << endl;

    // --- Simplified AES-256 GCM ---
    vector<uint8_t> aes256_key = stringToBytes("12410353_Personal_Key_2025_ABCDEF");  // exactly 32 characters
    vector<uint8_t> gcm_iv = {0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5};
    vector<uint8_t> gcm_tag_bytes;
    vector<uint8_t> gcm_ciphertext_bytes = simplified_aes_256_gcm_encrypt(plaintext_bytes, aes256_key, gcm_tag_bytes, gcm_iv);
    string gcm_ciphertext_hex = bytesToHex(gcm_ciphertext_bytes);
    string gcm_tag_hex = bytesToHex(gcm_tag_bytes);
    vector<uint8_t> gcm_decrypted_bytes = simplified_aes_256_gcm_decrypt(gcm_ciphertext_bytes, aes256_key, gcm_tag_bytes, gcm_iv);
    string gcm_decrypted_text = string(gcm_decrypted_bytes.begin(), gcm_decrypted_bytes.end());

    cout << "\n🔒 AES-256 GCM Encrypted Data: " << gcm_ciphertext_hex << endl;
    cout << "🔑 AES-256 Key (256-bit/32 bytes): " << bytesToHex(aes256_key) << endl;
    cout << "🛡️  Tag: " << gcm_tag_hex << endl;
    cout << "🔑 IV (12 bytes): " << bytesToHex(gcm_iv) << endl << endl;
    cout << "🔓 AES-256 GCM Decrypted Text: " << gcm_decrypted_text << endl;
    cout << "🛡️ Tag: " << gcm_tag_hex << endl << endl;

    // --- Digital Signature ---
    vector<uint8_t> rsa_private_key_128(16, 0xBB);
    vector<uint8_t> rsa_public_key_128(16, 0xBB);
    vector<uint8_t> rsa_private_key_256(32, 0xCC);
    vector<uint8_t> rsa_public_key_256(32, 0xCC);

    vector<uint8_t> digital_signature_bytes = simplified_rsa_sign(gcm_ciphertext_bytes, rsa_private_key_256);
    string digital_signature_hex = bytesToHex(digital_signature_bytes);
    bool is_signature_valid = simplified_rsa_verify(gcm_ciphertext_bytes, digital_signature_bytes, rsa_public_key_256);

    cout << "🔑 RSA Private Key (256-bit/32 bytes): " << bytesToHex(rsa_private_key_256) << endl;
    cout << "🔑 RSA Public Key (256-bit/32 bytes): " << bytesToHex(rsa_public_key_256) << endl << endl;
    cout << "✍️ Digital Signature: " << digital_signature_hex << endl << endl;
    cout << "🔓 Decrypted Plaintext After Decryption: " << gcm_decrypted_text << endl << endl;
    cout << (is_signature_valid ? "✅ Digital Signature VERIFIED." : "❌ Digital Signature VERIFICATION FAILED.") << endl;

    // --- Attack Detection Logic ---
    string my_name = "Surendra";
    string reg_no = "12410353";

    string aes128_key_hex = bytesToHex(aes128_key);
    string aes256_key_hex = bytesToHex(aes256_key);

    if (aes128_key_hex.find(my_name) != string::npos || aes128_key_hex.find(reg_no) != string::npos) {
        cout << "⚠️ Attack Detected – Key contains sensitive info (AES-128)!" << endl;
    }

    if (aes256_key_hex.find(my_name) != string::npos || aes256_key_hex.find(reg_no) != string::npos) {
        cout << "⚠️ Attack Detected – Key contains sensitive info (AES-256)!" << endl;
    }

    vector<int> weak_primes = {2, 3, 5, 7, 11};
    bool rsa_key_is_weak = false;

    for (int weak : weak_primes) {
        if (find(rsa_private_key_128.begin(), rsa_private_key_128.end(), weak) != rsa_private_key_128.end() ||
            find(rsa_private_key_256.begin(), rsa_private_key_256.end(), weak) != rsa_private_key_256.end()) {
            rsa_key_is_weak = true;
            break;
        }
    }

    if (rsa_key_is_weak) {
        cout << "⚠️ Attack Detected – Weak RSA Key!" << endl;
    }

    return 0;
}
