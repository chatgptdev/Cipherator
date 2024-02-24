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

#include "key_management.h"
#include <fstream>


KeyManagement::KeyManagement(size_t iterations) : iterationsCount(iterations) {
#ifdef _WIN32
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hSha256Algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Error opening hash algorithm provider");
    }
    status = BCryptOpenAlgorithmProvider(&hHMACSha256Algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hSha256Algorithm, 0);
        throw std::runtime_error("Error opening HMAC algorithm provider");
    }
#endif
}

KeyManagement::~KeyManagement() {
#ifdef _WIN32
    BCryptCloseAlgorithmProvider(hSha256Algorithm, 0);
    BCryptCloseAlgorithmProvider(hHMACSha256Algorithm, 0);
#endif

}

secure_vector<unsigned char> KeyManagement::deriveKey(const secure_vector<char>& password, const std::string& keyFile, const secure_vector<unsigned char>& salt) {
    secure_vector<unsigned char> finalPassword(password.begin(), password.end());

    if (!keyFile.empty()) {
        std::ifstream file(keyFile, std::ios::binary);
        if (file) {
            secure_vector<char> buffer(1 << 20); // Read up to 1MiB
            file.read(buffer.data(), buffer.size());
            std::streamsize bytesRead = file.gcount();
            buffer.resize(bytesRead);

            finalPassword.insert(finalPassword.end(), buffer.begin(), buffer.end());

            secure_vector<unsigned char> hash(32);
#ifdef _WIN32
            NTSTATUS status = BCryptHash(hSha256Algorithm, nullptr, 0, (PUCHAR)finalPassword.data(), finalPassword.size(), hash.data(), hash.size());
            if (!BCRYPT_SUCCESS(status)) {
                throw std::runtime_error("Error hashing password and key file content");
            }
#elif defined(__APPLE__)
            CC_SHA256_CTX sha256Context;
            CC_SHA256_Init(&sha256Context);
            CC_SHA256_Update(&sha256Context, finalPassword.data(), finalPassword.size());
            CC_SHA256_Final(hash.data(), &sha256Context);
#else
            unsigned int length = 0;
            if (!EVP_Digest(finalPassword.data(), finalPassword.size(), hash.data(), &length, EVP_sha256(), nullptr)) {
                throw std::runtime_error("Error hashing password and key file content");
            }
#endif
            finalPassword = hash;
        }
        else {
            throw std::runtime_error("Error opening key file");
        }
    }

    const size_t iterations = getIterationsCount();
    size_t cbDerivedKey = 32;
    secure_vector<unsigned char> derivedKey(cbDerivedKey);
#ifdef _WIN32
    NTSTATUS status = BCryptDeriveKeyPBKDF2(hHMACSha256Algorithm, (PUCHAR)finalPassword.data(), finalPassword.size(), (PUCHAR)salt.data(), salt.size(), (DWORD) iterations, derivedKey.data(), (DWORD) cbDerivedKey, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Error deriving key from password and key file");
    }
#elif defined(__APPLE__)
    CCKeyDerivationPBKDF(kCCPBKDF2, finalPassword.data(), finalPassword.size(), salt.data(), salt.size(), kCCPRFHmacAlgSHA256, iterations, derivedKey.data(), derivedKey.size());
#else
    if (!PKCS5_PBKDF2_HMAC((const char*)finalPassword.data(), finalPassword.size(), salt.data(), (int) salt.size(), (int) iterations, EVP_sha256(), (int) cbDerivedKey, derivedKey.data())) {
        throw std::runtime_error("Error deriving key from password and key file");
    }
#endif
    return derivedKey;
}

secure_vector<unsigned char> KeyManagement::deriveIVFromNonce(const secure_vector<unsigned char>& nonce, uint64_t counter) {
    secure_vector<unsigned char> derivedIV(nonce.begin(), nonce.end());
    if (nonce.size() < sizeof(counter)) {
        throw std::runtime_error("Error deriving IV from nonce: nonce is too small");
    }

    // XOR nonce with the big-endian counter
    for (size_t i = 0; i < sizeof(counter); ++i) {
        derivedIV[derivedIV.size() - 1 - i] ^= (counter >> (8 * i)) & 0xFF;
    }

    return derivedIV;
}
