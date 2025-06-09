// EmotiBitSecurityHost.h
// ------------------------------------------------------------
// This class defines the security logic on the Oscilloscope side
// for securely communicating with EmotiBit wearable devices.
// It supports symmetric AES encryption, HMAC-SHA256 integrity
// verification, pre-shared key management, and secure message
// parsing and generation.
// ------------------------------------------------------------



#pragma once

#include <vector>
#include <string>
#include <map>
#include <array>
#include <mutex>
#include <iostream>
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <ofMain.h>

#define PSK_LENGTH 16
#define AES_BLOCK_SIZE 16
#define HMAC_LEN 32

class EmotiBitSecurityHost {
public:
    // ========== Common functions ==========

    /**
     * Pads a message using PKCS#7 padding.
     * @param message The message to pad.
     * @param blockSize The block size for padding.
     * @return True if padding was added successfully.
     */
    bool padMessage(std::string& message, uint8_t blockSize) const;

    /**
     * Removes PKCS#7 padding from a message.
     * @param data The padded message as a byte vector.
     * @param blockSize The block size used for padding.
     * @return True if padding was removed successfully.
     */
    bool removePadding(std::vector<uint8_t>& data, uint8_t blockSize) const;

    /**
     * Encrypts data using AES-128 in ECB mode.
     * @param key The encryption key.
     * @param input The input data to encrypt.
     * @param len The length of the input data.
     * @return The encrypted byte vector.
     */
    std::vector<uint8_t> aesEncrypt(const uint8_t* key, const uint8_t* input, size_t len) const;

    /**
     * Decrypts data using AES-128 in ECB mode.
     * @param key The decryption key.
     * @param input The encrypted data.
     * @param len The length of the encrypted data.
     * @return The decrypted byte vector.
     */
    std::vector<uint8_t> aesDecrypt(const uint8_t* key, const uint8_t* input, size_t len) const;

    /**
     * Calculates HMAC-SHA256 of given data.
     * @param key The key to use for HMAC.
     * @param data The data to authenticate.
     * @param len Length of the data.
     * @return The HMAC as a byte vector.
     */
    std::vector<uint8_t> calculateHmac(const uint8_t* key, const uint8_t* data, size_t len) const;

    /**
     * Splits a message into ciphertext and HMAC.
     * @param input The full input message.
     * @param cipherOut Output ciphertext.
     * @param hmacOut Output HMAC.
     * @return True if split was successful.
     */
    bool splitCipherAndHmac(const std::vector<uint8_t>& input, std::vector<uint8_t>& cipherOut, std::vector<uint8_t>& hmacOut) const;

    /**
     * Verifies the authenticity of a message.
     * @param cipher The ciphertext.
     * @param hmac The HMAC to verify.
     * @param key The HMAC key.
     * @return True if HMAC matches.
     */
    bool verifyOnly(const std::vector<uint8_t>& cipher, const std::vector<uint8_t>& hmac, const uint8_t* key) const;

    /**
     * Decrypts a message without verifying its HMAC.
     * @param cipher The encrypted message.
     * @param plaintextOut The output plaintext.
     * @param key The decryption key.
     * @return True if decryption was successful.
     */
    bool decryptOnly(const std::vector<uint8_t>& cipher, std::string& plaintextOut, const uint8_t* key) const;

    /**
     * Verifies and decrypts a message.
     * @param input The full input message with cipher and HMAC.
     * @param plaintextOut The output plaintext.
     * @param key The key for both HMAC and decryption.
     * @return True if verification and decryption were successful.
     */
    bool decryptAndVerify(const std::vector<uint8_t>& input, std::string& plaintextOut, const uint8_t* key) const;

    /**
     * Encrypts and signs a message using AES and HMAC.
     * @param message The plaintext message.
     * @param aesKey Key for AES encryption.
     * @param hmacKey Key for HMAC authentication.
     * @param outEncrypted The output encrypted and signed message.
     * @return True if encryption and signing were successful.
     */
    bool encryptAndSign(const std::string& message, const uint8_t* aesKey, const uint8_t* hmacKey, std::vector<uint8_t>& outEncrypted) const;

    /**
     * Converts a hex string to a byte array.
     * @param hex A string of 32 hex characters.
     * @return The corresponding byte array.
     */
    std::array<uint8_t, PSK_LENGTH> hexStringToBytes(const std::string& hex);

    // ========== Specific functions ==========

    /**
     * Loads PSK keys from a remote URL in JSON format.
     * @param url The URL to fetch the keys from.
     * @return True if the keys were loaded successfully.
     */
    bool loadKeysFromUrl(const std::string& url);

    /**
     * Encrypts and signs a message using the oscilloscope PSK.
     * @param plaintext The plaintext message.
     * @return The encrypted and signed message.
     */
    std::vector<uint8_t> encryptAndSignWithOscilloscope(const std::string& plaintext);

    /**
     * Decrypts and verifies a packet from the currently connected EmotiBit.
     * @param encryptedPacket The encrypted packet.
     * @param plaintextOut The output plaintext.
     * @return True if verification and decryption were successful.
     */
    bool decryptAndVerifyFromConnected(const std::vector<uint8_t>& encryptedPacket, std::string& plaintextOut);

    /**
     * Verifies a packet from the currently connected EmotiBit without decrypting it.
     * @param cipher The encrypted message.
     * @param hmac The HMAC to verify.
     * @return True if the HMAC matches.
     */
    bool verifyConnectedPacket(const std::vector<uint8_t>& cipher, const std::vector<uint8_t>& hmac) const;

    /**
     * Decrypts and splits an advertisement message.
     * @param encryptedPacket The full encrypted packet.
     * @param packetsOut Vector to store split plaintext packets.
     * @param cipherOut Output ciphertext.
     * @param hmacOut Output HMAC.
     * @return True if decryption was successful.
     */
    bool decryptAdvertisement(const std::vector<uint8_t>& encryptedPacket, std::vector<std::string>& packetsOut, std::vector<uint8_t>& cipherOut, std::vector<uint8_t>& hmacOut);

    /**
     * Verifies a HelloHost message from an EmotiBit.
     * @param cipher The encrypted message.
     * @param hmac The HMAC.
     * @param id The EmotiBit identifier.
     * @return True if verification is successful.
     */
    bool verifyHelloHost(const std::vector<uint8_t>& cipher, const std::vector<uint8_t>& hmac, const std::string& id) const;

    /**
     * Sets the ID of the currently connected EmotiBit.
     * @param id The device identifier.
     */
    void setConnectedDevice(const std::string& id);

    /**
     * Clears the connected EmotiBit ID.
     */
    void clearConnectedDevice();

    /**
     * Adds a newly discovered EmotiBit to the local cache.
     * @param id The device ID.
     * @param psk The pre-shared key.
     */
    void addDiscoveredEmotiBit(const std::string& id, const std::array<uint8_t, PSK_LENGTH>& psk);

    /**
     * Retrieves the PSK for a known EmotiBit ID.
     * @param id The device ID.
     * @return The associated pre-shared key.
     */
    std::array<uint8_t, PSK_LENGTH> getPskFromRepo(const std::string& id) const;

private:
    std::array<uint8_t, PSK_LENGTH> _pskOscilloscope;
    std::map<std::string, std::array<uint8_t, PSK_LENGTH>> _pskRepository;
    std::map<std::string, std::array<uint8_t, PSK_LENGTH>> _discoveredEmotiBits;
    std::string _connectedId;
    mutable std::mutex _mutex;
};
