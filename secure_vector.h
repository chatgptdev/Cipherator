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
#include <memory>

// Secure memory erasure macro for Windows and non-Windows systems
#if defined(_WIN32)
#define secure_zeromem(mem,size) do { RtlSecureZeroMemory (mem, size); } while (0)
#else
#define secure_zeromem(mem,size) do { volatile char *burnm = (volatile char *)(mem); int burnc = size; while (burnc--) *burnm++ = 0; } while (0)
#endif


// A custom allocator that extends the standard std::allocator<T> class,
// providing secure memory erasure for sensitive data during deallocation.
template <typename T>
class secure_allocator : public std::allocator<T> {
public:
    using size_type = typename std::allocator<T>::size_type;
    using pointer = typename std::allocator<T>::pointer;
    using const_pointer = typename std::allocator<T>::const_pointer;

    template <typename U>
    struct rebind {
        using other = secure_allocator<U>;
    };

    secure_allocator() noexcept {}

    secure_allocator(const secure_allocator& other) noexcept
        : std::allocator<T>(other) {}

    template <typename U>
    secure_allocator(const secure_allocator<U>& other) noexcept
        : std::allocator<T>(other) {}

    ~secure_allocator() noexcept {}

    pointer allocate(size_type n, const_pointer hint = 0) {
        return std::allocator<T>::allocate(n, hint);
    }

    // Custom deallocate function that securely erases the memory occupied by the pointer
    // before deallocating it using the base class deallocate function.
    void deallocate(T* ptr, std::size_t n) {
        if (ptr != nullptr && n > 0) {
            secure_zeromem(ptr, n * sizeof(T));
        }
        std::allocator<T>::deallocate(ptr, n);
    }
};

// A secure_vector class that is an alias for a std::vector using the secure_allocator.
// This ensures that the memory occupied by sensitive data is securely erased during
// deallocation, while also providing all the features and capabilities of a regular
// std::vector.
template <typename T>
using secure_vector = std::vector<T, secure_allocator<T>>;

