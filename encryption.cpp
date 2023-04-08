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
}

Encryption::~Encryption() {
    BCryptCloseAlgorithmProvider(hAesAlgorithm, 0);
}

void Encryption::encrypt(const unsigned char* pData, size_t data_len, const secure_vector<unsigned char>& key, const secure_vector<unsigned char>& iv, secure_vector<unsigned char>& encryptedData) {
    NTSTATUS status;
    DWORD authTagSize = getTagSize();

    if (iv.size() != getNonceSize()) {
        throw std::runtime_error("Error validating IV for encryption: IV length is invalid");
    }

    BCRYPT_KEY_HANDLE hKey;
    status = BCryptGenerateSymmetricKey(hAesAlgorithm, &hKey, nullptr, 0, (PBYTE)key.data(), key.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Error generating symmetric key");
    }

    DWORD cbCipherText;
    secure_vector<unsigned char> tag(authTagSize);
    secure_vector<unsigned char> nonce(iv.begin(), iv.end());
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce.data();
    authInfo.cbNonce = nonce.size();
    authInfo.cbTag = tag.size();
    authInfo.pbTag = tag.data();

    cbCipherText = data_len;

    encryptedData.resize(cbCipherText + authTagSize);

    status = BCryptEncrypt(hKey, (PUCHAR) pData, data_len, &authInfo, nonce.data(), nonce.size(), encryptedData.data(), cbCipherText, &cbCipherText, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        throw std::runtime_error("Error encrypting data");
    }

    std::copy(tag.begin(), tag.end(), encryptedData.begin() + cbCipherText);

    BCryptDestroyKey(hKey);
}

void Encryption::decrypt(const unsigned char* pData, size_t data_len, const secure_vector<unsigned char>& key, const secure_vector<unsigned char>& iv, secure_vector<unsigned char>& decryptedData) {
    NTSTATUS status;
    size_t authTagSize = getTagSize();
    size_t nonceSize = getNonceSize();

    if (data_len <= authTagSize) {
        throw std::runtime_error("Error validating encrypted data length: length too short");
    }

    if (iv.size() != nonceSize) {
        throw std::runtime_error("Error validating IV for decryption: IV length is invalid");
    }

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

    DWORD cbPlainText = data_len - authTagSize;
    decryptedData.resize(cbPlainText);
    status = BCryptDecrypt(hKey, (PUCHAR) pData, cbPlainText, &authInfo, nonce.data(), nonceSize, decryptedData.data(), cbPlainText, &cbPlainText, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        throw std::runtime_error("Error decrypting data");
    }

    BCryptDestroyKey(hKey);
}

