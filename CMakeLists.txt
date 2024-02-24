cmake_minimum_required(VERSION 3.16)
cmake_policy(SET CMP0091 NEW)
project(Cipherator)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler warnings
# if(MSVC)
#     add_compile_options(/W4 /WX)
# else()
#     add_compile_options(-Wall -Wextra -pedantic -Werror)
# endif()

# Link against the static C runtime (for MSVC)
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Check if the system is macOS
if(APPLE)
    # Set the macOS target architectures to x64 and arm64 for universal binary
    set(CMAKE_OSX_ARCHITECTURES "x86_64;arm64")
endif()

add_executable(cipherator
    main.cpp
    crypto_tool.h
    crypto_tool.cpp
    encryption.h
    encryption.cpp
    key_management.h
    key_management.cpp
    secure_vector.h
)

# Link libraries
if(MSVC)
    target_link_libraries(cipherator bcrypt)
elseif(APPLE)
    find_library(SECURITY Security)
    find_library(COREFOUNDATION CoreFoundation)
    target_link_libraries(cipherator ${SECURITY} ${COREFOUNDATION})
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    find_package(OpenSSL REQUIRED)
    target_link_libraries(cipherator OpenSSL::SSL OpenSSL::Crypto)

    # Install the binary to /usr/bin
    install(TARGETS cipherator DESTINATION /usr/bin)

    # Determine the Linux distribution using lsb_release
    execute_process(COMMAND lsb_release -is
                    OUTPUT_VARIABLE LINUX_DISTRIBUTION
                    OUTPUT_STRIP_TRAILING_WHITESPACE)

    # Common CPack configuration
    set(CPACK_PACKAGE_NAME "cipherator")
    set(CPACK_PACKAGE_VERSION "1.1.0")
    set(CPACK_PACKAGE_CONTACT "ChatGPTDev <chatgptdev@tuta.io>")
    # set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "cipherator is a command-line tool for encrypting and decrypting files using AES-256 in GCM mode.")

    if(LINUX_DISTRIBUTION MATCHES "Debian" OR LINUX_DISTRIBUTION MATCHES "Ubuntu")
        # CPack configuration for generating .deb package
        set(CPACK_GENERATOR "DEB")
        set(CPACK_DEBIAN_PACKAGE_MAINTAINER "${CPACK_PACKAGE_CONTACT}")
        set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
        set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
        set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/chatgptdev/Cipherator")

        # Set the .deb file name to include the target architecture
        #set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
        set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}_${CMAKE_SYSTEM_PROCESSOR}")
        set(CPACK_DEBIAN_PACKAGE_DEPENDS "openssl (>= 1.1.1)")
    elseif(LINUX_DISTRIBUTION MATCHES "Fedora" OR LINUX_DISTRIBUTION MATCHES "CentOS" OR LINUX_DISTRIBUTION MATCHES "RedHat" OR LINUX_DISTRIBUTION MATCHES "openSUSE")
        # CPack configuration for generating .rpm package
        set(CPACK_GENERATOR "RPM")
        set(CPACK_RPM_PACKAGE_LICENSE "MIT")
        set(CPACK_RPM_PACKAGE_GROUP "Applications/System")
        set(CPACK_RPM_PACKAGE_HOMEPAGE "https://github.com/chatgptdev/Cipherator")

        # Set the .rpm file name to include the target architecture
        #set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
        set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}_${CMAKE_SYSTEM_PROCESSOR}")
        set(CPACK_RPM_PACKAGE_REQUIRES "openssl >= 1.1.1")
    endif()

    include(CPack)
endif()
