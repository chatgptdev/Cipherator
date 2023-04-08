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
#if defined(_WIN32)
#include <Windows.h>
#endif
#include <vector>
#include <algorithm>

#if defined(_WIN32)
#define secure_zeromem(mem,size) do { RtlSecureZeroMemory (mem, size); } while (0)
#else
#define secure_zeromem(mem,size) do { volatile char *burnm = (volatile char *)(mem); int burnc = size; while (burnc--) *burnm++ = 0; } while (0)
#endif

// A secure_vector class that extends the standard std::vector class,
// providing secure memory erasure for sensitive data.
template <typename T, typename Allocator = std::allocator<T>>
class secure_vector : public std::vector<T, Allocator> {
public:
    using std::vector<T, Allocator>::vector; // Inherit all constructors from std::vector

    // Custom constructor for creating a secure_vector from two const_iterators
    secure_vector(const_iterator first, const_iterator last)
        : std::vector<T, Allocator>(first, last) {
    }

    // Custom destructor that securely erases the memory occupied by the vector
    ~secure_vector() {
        secure_clear();
    }

    // Securely erase the memory occupied by the vector and clear its contents
    void secure_clear() {
        auto& vec = static_cast<std::vector<T, Allocator>&>(*this);
        if (!vec.empty()) {
            secure_zeromem(vec.data(), vec.size() * sizeof(T));
            vec.clear();
        }
    }
};

