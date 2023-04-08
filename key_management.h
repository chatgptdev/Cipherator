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
#include <Windows.h>
#include <bcrypt.h>
#include <stdexcept>
#include <string>
#include "secure_vector.h"

class KeyManagement {
public:
    KeyManagement(size_t iterations = 100000);
    ~KeyManagement();

    size_t getIterationsCount() const { return iterationsCount; }
    secure_vector<unsigned char> deriveKey(const secure_vector<char>& password, const std::string& keyfile, const secure_vector<unsigned char>& salt);
    secure_vector<unsigned char> deriveIVFromNonce(const secure_vector<unsigned char>& nonce, uint64_t counter);

protected:
    BCRYPT_ALG_HANDLE hSha256Algorithm;
    BCRYPT_ALG_HANDLE hHMACSha256Algorithm;
    size_t iterationsCount;
};

