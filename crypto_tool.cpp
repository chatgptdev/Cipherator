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

#include <iostream>
#include <fstream>
#include "crypto_tool.h"
#ifdef _WIN32
#include <bcrypt.h>
#elif defined(__APPLE__)
#include <Security/Security.h>
#else
#include <openssl/rand.h>
#endif

constexpr size_t SALT_SIZE = 32;
constexpr size_t CHUNK_SIZE = 64 * 1024;

extern bool quietMode;

secure_vector<unsigned char> CryptoTool::generateRandom(size_t count) {
    secure_vector<unsigned char> rnd(count);
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (status != ERROR_SUCCESS) {
        throw std::runtime_error("Failed to open RNG algorithm provider.");
    }

    status = BCryptGenRandom(hAlg, rnd.data(), count, 0);
    if (status != ERROR_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to generate random salt.");
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
#elif defined(__APPLE__)
    if (SecRandomCopyBytes(kSecRandomDefault, count, rnd.data()) != 0) {
        throw std::runtime_error("Failed to generate random salt.");
    }
#else
    // use OpenSSL random generator
    if (RAND_bytes(rnd.data(), count) != 1) {
        throw std::runtime_error("Failed to generate random salt.");
    }
#endif
    return rnd;
}

bool CryptoTool::encrypt(const std::string& inputFile, const std::string& outputFile, const secure_vector<char>& password, const std::string& keyFile) {
    try {
        std::ifstream input(inputFile, std::ios::binary);
        if (!input) {
            throw std::runtime_error("Error opening input file");
        }

        std::ofstream output(outputFile, std::ios::binary);
        if (!output) {
            throw std::runtime_error("Error opening output file");
        }

        secure_vector<unsigned char> salt = generateRandom(SALT_SIZE);
        secure_vector<unsigned char> key = key_management.deriveKey(password, keyFile, salt);
        secure_vector<unsigned char> nonce = generateRandom(encryption.getNonceSize());

        // Write salt and nonce to the output file
        if (!output.write(reinterpret_cast<const char*>(salt.data()), salt.size())) {
            throw std::runtime_error("Error writing salt to output file");
        }
        if (!output.write(reinterpret_cast<const char*>(nonce.data()), nonce.size())) {
            throw std::runtime_error("Error writing nonce to output file");
        }

        secure_vector<unsigned char> buffer(CHUNK_SIZE);
        secure_vector<unsigned char> encrypted_buffer(CHUNK_SIZE + encryption.getTagSize());
        uint64_t counter = 0;

        while (input) {
            input.read(reinterpret_cast<char*>(buffer.data()), CHUNK_SIZE);
            std::streamsize bytesRead = input.gcount();

            if (bytesRead > 0) {

                secure_vector<unsigned char> iv = key_management.deriveIVFromNonce(nonce, counter);
                encryption.encrypt(buffer.data(), bytesRead, key, iv, encrypted_buffer);

                // Write encrypted chunk and tag to the output file
                if (!output.write(reinterpret_cast<const char*>(encrypted_buffer.data()), encrypted_buffer.size())) {
                    throw std::runtime_error("Error writing encrypted data to output file");
                }

                counter++;
            }
        }

        input.close();
        output.close();
        return true;
    }
    catch (const std::exception& e) {
        if (!quietMode) {
            std::cerr << "Encryption failed: " << e.what() << std::endl;
        }
        return false;
    }
}

bool CryptoTool::decrypt(const std::string& inputFile, const std::string& outputFile, const secure_vector<char>& password, const std::string& keyFile) {
    try {
        std::ifstream input(inputFile, std::ios::binary | std::ios::ate);
        if (!input) {
            throw std::runtime_error("Error opening input file");
        }

        std::streamsize fileSize = input.tellg();
        input.seekg(0, std::ios::beg);

        if (fileSize < static_cast<std::streamsize>(SALT_SIZE + encryption.getNonceSize() + encryption.getTagSize())) {
            throw std::runtime_error("Input file is too small to contain valid encrypted data");
        }

        secure_vector<unsigned char> salt(SALT_SIZE);
        secure_vector<unsigned char> nonce(encryption.getNonceSize());

        // Read salt and nonce from the input file
        if (!input.read(reinterpret_cast<char*>(salt.data()), salt.size())) {
            throw std::runtime_error("Error reading salt from input file");
        }
        if (!input.read(reinterpret_cast<char*>(nonce.data()), nonce.size())) {
            throw std::runtime_error("Error reading nonce from input file");
        }

        secure_vector<unsigned char> key = key_management.deriveKey(password, keyFile, salt);

        std::ofstream output(outputFile, std::ios::binary);
        if (!output) {
            throw std::runtime_error("Error opening output file");
        }

        secure_vector<unsigned char> buffer(CHUNK_SIZE + encryption.getTagSize());
        secure_vector<unsigned char> decrypted_buffer(CHUNK_SIZE);
        uint64_t counter = 0;

        while (input) {
            input.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
            std::streamsize bytesRead = input.gcount();

            if (bytesRead > 0) {

                secure_vector<unsigned char> iv = key_management.deriveIVFromNonce(nonce, counter);

                encryption.decrypt(buffer.data(), bytesRead, key, iv, decrypted_buffer);
                // Write decrypted chunk to the output file
                if (!output.write(reinterpret_cast<const char*>(decrypted_buffer.data()), decrypted_buffer.size())) {
                    throw std::runtime_error("Error writing decrypted data to output file");
                }

                counter++;
            }
        }

        input.close();
        output.close();
        return true;
    }
    catch (const std::exception& e) {
        if (!quietMode) {
            std::cerr << "Decryption failed: " << e.what() << std::endl;
        }
        return false;
    }
}

