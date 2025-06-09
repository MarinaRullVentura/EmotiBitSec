// EmotiBitSecurity.h
// --------------------------------------------------
// Header file for the EmotiBitSecurity class
// This class provides symmetric encryption and HMAC-based authentication
// for secure communication in resource-constrained devices like EmotiBit.
// --------------------------------------------------
#pragma once

#include <Arduino.h>
#include <vector>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <SD.h>

#define PSK_LENGTH 16
#define BLOCK_SIZE 16
#define HMAC_LEN 32


class EmotiBitSecurity {
public:
    // ========== Common Utility Functions ==========

    /**
     * Pads a message using PKCS#7 padding.
     * @param message String to be padded (modified in place).
     * @param blockSize Block size to align with (usually 16 for AES).
     * @return true if padding applied successfully.
     */
    static bool padMessage(String& message, uint8_t blockSize);
    static std::array<uint8_t, PSK_LENGTH> hexStringToBytes(const String& hex);
    /**
     * Removes PKCS#7 padding from decrypted data.
     * @param data Byte vector to remove padding from.
     * @param blockSize Block size used during encryption.
     * @return true if padding removed correctly, false if invalid.
     */
    static bool removePadding(std::vector<uint8_t>& data, uint8_t blockSize);

    /**
     * Encrypts input data using AES-128 ECB mode.
     * @param key AES encryption key (32 bytes).
     * @param input Raw input data to encrypt.
     * @param len Length of the input data.
     * @return Encrypted byte vector.
     */
    static std::vector<uint8_t> aesEncrypt(const uint8_t* key, const uint8_t* input, size_t len);

    /**
     * Decrypts AES-128 ECB encrypted data.
     * @param key AES decryption key (32 bytes).
     * @param input Encrypted data.
     * @param len Length of the encrypted data.
     * @return Decrypted byte vector.
     */
    static std::vector<uint8_t> aesDecrypt(const uint8_t* key, const uint8_t* input, size_t len);

    /**
     * Calculates HMAC-SHA256 for a given input.
     * @param key HMAC key (32 bytes).
     * @param data Input data to authenticate.
     * @param len Length of the input data.
     * @return HMAC as a byte vector.
     */
    static std::vector<uint8_t> calculateHmac(const uint8_t* key, const uint8_t* data, size_t len);

    /**
     * Splits an input buffer into cipher and HMAC parts.
     * @param input Full input buffer containing cipher + HMAC.
     * @param cipherOut Output buffer for cipher part.
     * @param hmacOut Output buffer for HMAC part.
     * @return true if split successfully.
     */
    static bool splitCipherAndHmac(const std::vector<uint8_t>& input, std::vector<uint8_t>& cipherOut, std::vector<uint8_t>& hmacOut);

    /**
     * Verifies HMAC of a message without decrypting.
     * @param cipher Encrypted message.
     * @param hmac HMAC to compare against.
     * @param key HMAC verification key.
     * @return true if HMAC is valid.
     */
    static bool verifyOnly(const std::vector<uint8_t>& cipher, const std::vector<uint8_t>& hmac, const uint8_t* key);

    /**
     * Decrypts an AES-encrypted message without verifying HMAC.
     * @param cipher Encrypted byte vector.
     * @param plaintextOut Output plaintext string.
     * @param key AES decryption key.
     * @return true if decryption successful.
     */
    static bool decryptOnly(const std::vector<uint8_t>& cipher, String& plaintextOut, const uint8_t* key);

    /**
     * Verifies HMAC and then decrypts the message.
     * @param input Full encrypted packet with HMAC.
     * @param plaintextOut Output plaintext string.
     * @param key AES + HMAC shared key.
     * @return true if both verification and decryption succeed.
     */
    static bool decryptAndVerify(const std::vector<uint8_t>& input, String& plaintextOut, const uint8_t* key);

    // ========== Key Loading ==========

    /**
     * Loads symmetric keys from a local file (e.g., SD card).
     * @param path File path to read keys from.
     * @return true if both keys loaded correctly.
     */
    bool loadKeysFromFile(const String& path);

    // ========== Combined Operations ==========

    /**
     * Encrypts and signs a message using given AES and HMAC keys.
     * @param message Plaintext message.
     * @param aesKey AES encryption key.
     * @param hmacKey HMAC signing key.
     * @param outEncrypted Output encrypted + signed buffer.
     * @return true if operation successful.
     */
    bool encryptAndSignGeneric(const String& message, const uint8_t* aesKey, const uint8_t* hmacKey, std::vector<uint8_t>& outEncrypted);

    /**
     * Encrypts and signs control messages using oscilloscope PSK.
     * @param message Plaintext message.
     * @param outEncrypted Output encrypted buffer.
     * @return true if successful.
     */
    bool encryptAndSignControl(const String& message, std::vector<uint8_t>& outEncrypted);

    /**
     * Encrypts and signs data messages using EmotiBit PSK.
     * @param message Plaintext message.
     * @param outEncrypted Output encrypted buffer.
     * @return true if successful.
     */
    bool encryptAndSignData(const String& message, std::vector<uint8_t>& outEncrypted);

    /**
     * Decrypts and verifies a message received by the EmotiBit.
     * @param input Full encrypted + signed buffer.
     * @param plaintextOut Output decrypted message.
     * @return true if successful.
     */
    bool decryptAndVerifyHMAC(const std::vector<uint8_t>& input, String& plaintextOut);

private:
    uint8_t _psk_eb[PSK_LENGTH];   // EmotiBit pre-shared key
    uint8_t _psk_osc[PSK_LENGTH];  // Oscilloscope pre-shared key
};
