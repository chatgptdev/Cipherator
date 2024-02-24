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

#pragma once
#ifdef _WIN32
#include <Windows.h>
#include <bcrypt.h>
#elif __APPLE__
#include <CommonCrypto/CommonCrypto.h>
#else
#include <openssl/evp.h>
#endif
#include "secure_vector.h"

class Encryption {
public:
    Encryption();
    ~Encryption();

    size_t getTagSize() const { return 16; }
    size_t getNonceSize() const { return 12; }
    void encrypt(const unsigned char* pData, size_t data_len, const secure_vector<unsigned char>& key, const secure_vector<unsigned char>& iv, secure_vector<unsigned char>& encryptedData);
    void decrypt(const unsigned char* pData, size_t data_len, const secure_vector<unsigned char>& key, const secure_vector<unsigned char>& iv, secure_vector<unsigned char>& decryptedData);

protected:
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAesAlgorithm;
#endif
};

