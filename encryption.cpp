/*
 * Cipherator - A command-line tool for encrypting and decrypting files using AES-256 in GCM mode.
 *
 * Copyright (C) 2023 chatgptdev
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the MIT License as published by
 * the Open Source Initiative, either version of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * MIT License for more details.
 *
 * You should have received a copy of the MIT License
 * along with this program. If not, see <https://opensource.org/licenses/MIT>.
 */

#include "encryption.h"
#include <stdexcept>

Encryption::Encryption() {
#ifdef _WIN32
    NTSTATUS status;
    status = BCryptOpenAlgorithmProvider(&hAesAlgorithm, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Error opening algorithm provider");
    }

    status = BCryptSetProperty(hAesAlgorithm, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAesAlgorithm, 0);
        throw std::runtime_error("Error setting GCM chaining mode");
    }
#endif
}

Encryption::~Encryption() {
    #ifdef _WIN32
    BCryptCloseAlgorithmProvider(hAesAlgorithm, 0);
    #endif
}

void Encryption::encrypt(const unsigned char* pData, size_t data_len, const secure_vector<unsigned char>& key, const secure_vector<unsigned char>& iv, secure_vector<unsigned char>& encryptedData) {

    size_t authTagSize = getTagSize();

    if (iv.size() != getNonceSize()) {
        throw std::runtime_error("Error validating IV for encryption: IV length is invalid");
    }

    size_t cbCipherText = data_len;
    secure_vector<unsigned char> tag(authTagSize);
    secure_vector<unsigned char> nonce(iv.begin(), iv.end());
    encryptedData.resize(cbCipherText + authTagSize);

#ifdef _WIN32
    BCRYPT_KEY_HANDLE hKey;
    NTSTATUS status = BCryptGenerateSymmetricKey(hAesAlgorithm, &hKey, nullptr, 0, (PBYTE)key.data(), key.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Error generating symmetric key");
    }
    DWORD cbOutput = cbCipherText;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce.data();
    authInfo.cbNonce = nonce.size();
    authInfo.cbTag = tag.size();
    authInfo.pbTag = tag.data();

    status = BCryptEncrypt(hKey, (PUCHAR) pData, data_len, &authInfo, nonce.data(), nonce.size(), encryptedData.data(), (DWORD) cbCipherText, &cbOutput, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        throw std::runtime_error("Error encrypting data");
    }
#elif __APPLE__
    // Initialize encryption with AES GCM
    CCCryptorRef cryptorRef = NULL;
    CCCryptorStatus ccStatus = CCCryptorCreateWithMode(kCCEncrypt, kCCModeGCM, kCCAlgorithmAES,
                                                       ccNoPadding, nonce.data(), key.data(), key.size(),
                                                       NULL, 0, 0, 0, &cryptorRef);
    if (ccStatus != kCCSuccess) {
        throw std::runtime_error("Error creating CCCryptorRef");
    }

    // Perform the encryption
    size_t dataMoved = 0;
    ccStatus = CCCryptorUpdate(cryptorRef, pData, data_len, encryptedData.data(), encryptedData.size(), &dataMoved);
    if (ccStatus != kCCSuccess) {
        CCCryptorRelease(cryptorRef);
        throw std::runtime_error("Error encrypting data");
    }

    // Finalize encryption. For GCM, this doesn't encrypt more data but is necessary
    ccStatus = CCCryptorFinal(cryptorRef, encryptedData.data() + dataMoved, encryptedData.size() - dataMoved, &dataMoved);
    if (ccStatus != kCCSuccess) {
        CCCryptorRelease(cryptorRef);
        throw std::runtime_error("Error finalizing encryption");
    }

    // Get the authentication tag
    ccStatus = CCCryptorGCMGetTag(cryptorRef, tag.data(), tag.size());
    if (ccStatus != kCCSuccess) {
        CCCryptorRelease(cryptorRef);
        throw std::runtime_error("Error getting GCM tag");
    }

    CCCryptorRelease(cryptorRef);

    std::copy(tag.begin(), tag.end(), encryptedData.begin() + cbCipherText);
#else

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Error creating cipher context");
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error initializing encryption context");
    }

    if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error setting key and IV for encryption");
    }

    int len;
    if (1 != EVP_EncryptUpdate(ctx, encryptedData.data(), &len, pData, (int) data_len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error encrypting data");
    }

    cbCipherText = len;
    if (1 != EVP_EncryptFinal_ex(ctx, encryptedData.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error finalizing encryption");
    }

    cbCipherText += len;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int) authTagSize, tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error getting GCM tag");
    }


    EVP_CIPHER_CTX_free(ctx);
    
#endif
    std::copy(tag.begin(), tag.end(), encryptedData.begin() + cbCipherText);

#ifdef _WIN32
    BCryptDestroyKey(hKey);
#endif
}

void Encryption::decrypt(const unsigned char* pData, size_t data_len, const secure_vector<unsigned char>& key, const secure_vector<unsigned char>& iv, secure_vector<unsigned char>& decryptedData) {
    
    size_t authTagSize = getTagSize();
    size_t nonceSize = getNonceSize();

    if (data_len <= authTagSize) {
        throw std::runtime_error("Error validating encrypted data length: length too short");
    }

    if (iv.size() != nonceSize) {
        throw std::runtime_error("Error validating IV for decryption: IV length is invalid");
    }

    size_t cbPlainText = data_len - authTagSize;
    decryptedData.resize(cbPlainText);

#ifdef _WIN32
    NTSTATUS status;
    BCRYPT_KEY_HANDLE hKey;
    status = BCryptGenerateSymmetricKey(hAesAlgorithm, &hKey, nullptr, 0, (PBYTE)key.data(), key.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Error generating symmetric key");
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    secure_vector<unsigned char> nonce(iv.begin(), iv.end());
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce.data();
    authInfo.cbNonce = nonceSize;
    authInfo.pbTag = (PBYTE)(pData + data_len - authTagSize);
    authInfo.cbTag = authTagSize;

    DWORD cbOutput = (DWORD) cbPlainText;
    status = BCryptDecrypt(hKey, (PUCHAR) pData, (DWORD) cbPlainText, &authInfo, nonce.data(), nonceSize, decryptedData.data(), cbOutput, &cbOutput, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        throw std::runtime_error("Error decrypting data: please check that you are using the correct password and key file");
    }

    BCryptDestroyKey(hKey);
#elif __APPLE__
    CCCryptorRef cryptorRef = NULL;
    CCCryptorStatus ccStatus = CCCryptorCreateWithMode(kCCDecrypt, kCCModeGCM, kCCAlgorithmAES,
                                                       ccNoPadding, iv.data(), key.data(), key.size(),
                                                       NULL, 0, 0, 0, &cryptorRef);
    if (ccStatus != kCCSuccess) {
        throw std::runtime_error("Error creating CCCryptorRef");
    }

    // Perform the decryption
    size_t dataMoved = 0;
    ccStatus = CCCryptorUpdate(cryptorRef, pData, data_len - authTagSize, decryptedData.data(), decryptedData.size(), &dataMoved);
    if (ccStatus != kCCSuccess) {
        CCCryptorRelease(cryptorRef);
        throw std::runtime_error("Error decrypting data");
    }

    // Set the authentication tag
    ccStatus = CCCryptorSetTag(cryptorRef, pData + data_len - authTagSize, authTagSize);
    if (ccStatus != kCCSuccess) {
        CCCryptorRelease(cryptorRef);
        throw std::runtime_error("Error setting GCM tag");
    }

    // Finalize decryption. For GCM, this doesn't decrypt more data but is necessary
    ccStatus = CCCryptorFinal(cryptorRef, decryptedData.data() + dataMoved, decryptedData.size() - dataMoved, &dataMoved);
    if (ccStatus != kCCSuccess) {
        CCCryptorRelease(cryptorRef);
        throw std::runtime_error("Error finalizing decryption: please check that you are using the correct password and key file");
    }

    CCCryptorRelease(cryptorRef);
#else
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Error creating cipher context");
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error initializing decryption context");
    }

    if (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error setting key and IV for decryption");
    }

    int len;
    if (1 != EVP_DecryptUpdate(ctx, decryptedData.data(), &len, pData, (int) data_len - authTagSize)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error decrypting data");
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int) authTagSize, (void*) (pData + data_len - authTagSize))) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error setting GCM tag");
    }

    if (1 != EVP_DecryptFinal_ex(ctx, decryptedData.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Error finalizing decryption: please check that you are using the correct password and key file");
    }

    EVP_CIPHER_CTX_free(ctx);

#endif
}

