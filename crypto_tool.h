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

#include <string>
#include "encryption.h"
#include "key_management.h"

class CryptoTool {
public:
    CryptoTool(size_t iterations = 100000) : encryption(), key_management(iterations) {}
    ~CryptoTool() {}

    secure_vector<unsigned char> generateRandom(size_t count);
    bool encrypt(const std::string& inputFile, const std::string& outputFile, const secure_vector<char>& password, const std::string& keyfile);
    bool decrypt(const std::string& inputFile, const std::string& outputFile, const secure_vector<char>& password, const std::string& keyfile);

private:
    Encryption encryption;
    KeyManagement key_management;
};

