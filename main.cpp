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
#include <string>
#include <sstream>
#include <vector>
#include <conio.h>
#include "crypto_tool.h"

bool quietMode = false;

void showHelp() {
    if (!quietMode) {
        std::cout << "Usage: cipherator -a <action> -i <input_file> -o <output_file> [-p <password>] [-k <keyfile>] [-n <iterations>] [-q] [-h]\n\n"
                     "Options:\n"
                     "  -a <action>       'encrypt' or 'decrypt'\n"
                     "  -i <input_file>   Input file path\n"
                     "  -o <output_file>  Output file path\n"
                     "  -p <password>     Password (optional). If password value is empty, it will be requested.\n"
                     "  -k <keyfile>      Keyfile path (optional). If path value is empty, it will be requested.\n"
                     "  -n <iterations>   Number of iterations for PBKDF2 (optional). Minimum: 10000, Default: 100000\n"
                     "  -q                Quiet mode (no text output)\n"
                     "  -h                Show help\n";
    }
}

void read_password(secure_vector<char>& password) {
    int ch;

    while ((ch = _getch()) != '\r') { // '\r' is the ENTER key on Windows
        if (ch == '\b' && !password.empty()) { // Backspace
            std::cout << "\b \b";
            password.pop_back();
        }
        else if (ch == 0xE0) { // DEL or other special keys
            int second = _getch();
            if (second == 0x53 && !password.empty()) { // DEL key
                std::cout << "\b \b";
                password.pop_back();
            }
            // Ignore other special keys
        }
        else if (ch >= ' ' && ch <= '~') { // Printable characters
            std::cout << '*';
            password.push_back(static_cast<char>(ch));
        }
    }

    std::cout << std::endl;
}


int main(int argc, char* argv[]) {
    std::string action, inputFile, outputFile, keyfile;
    secure_vector<char> password;
    std::stringstream errStr;
    bool unknownOption = false;
    bool helpSpecified = false;
    bool passwordSpecified = false;
    bool keyFileSpecified = false;
    size_t numIterations = 100000; // Default value

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-a") {
            if (i + 1 < argc) {
                action = argv[++i];
            }
            else {
                unknownOption = true;
                errStr << "-a option requires an argument" << std::endl;
            }
        } else if (arg == "-i") {
            if (i + 1 < argc) {
                inputFile = argv[++i];
            }
            else {
                unknownOption = true;
                errStr << "-i option requires an argument" << std::endl;
            }
        } else if (arg == "-o") {
            if (i + 1 < argc) {
                outputFile = argv[++i];
            }
            else {
                unknownOption = true;
                errStr << "-o option requires an argument" << std::endl;
            }
        } else if (arg == "-p") {
            passwordSpecified = true;
            if (i + 1 < argc) {
                const char* argPassword = argv[++i];
                size_t argPasswordLen = strlen(argPassword);
                if (argPasswordLen) {
                    password.resize(argPasswordLen);
                    memcpy(password.data(), argPassword, argPasswordLen);
                }
            }
        } else if (arg == "-k") {
            keyFileSpecified = true;
            keyfile = "";
            if (i + 1 < argc) {
              keyfile = argv[++i];
            }
        } else if (arg == "-n") {
            if (i + 1 < argc) {
                try {
                    numIterations = std::stoul(argv[++i]);
                }
                catch (...) {
                    numIterations = -1;
                }

                if (numIterations < 10000u) {
                    unknownOption = true;
                    errStr << "-n option argument must be a valid integer larger than or equal to 10000" << std::endl;
                }
            }
            else {
                unknownOption = true;
                errStr << "-n option requires an argument" << std::endl;
            }
        } else if (arg == "-q") {
            quietMode = true;
        } else if (arg == "-h") {
            helpSpecified = true;
        } else {
            unknownOption = true;
            errStr << "Unknown option: " << arg << std::endl;
        }
    }
    
    if (unknownOption)
    {
      if (!quietMode) {
        std::string msg = errStr.str();
        std::cout << msg;
        showHelp();
      }
      return -1;
    }
    
    if (helpSpecified)
    {
      showHelp();
      return 0;
    }

    if (action.empty() || inputFile.empty() || outputFile.empty() || (!passwordSpecified && !keyFileSpecified)) {
        showHelp();
        return -1;
    }

    if (passwordSpecified && password.empty()) {
        std::cout << "Enter password: ";
        read_password(password);
    }

    if (keyFileSpecified && keyfile.empty()) {
        std::cout << "Enter keyfile path: ";
        std::getline(std::cin, keyfile);
    }

    CryptoTool tool(numIterations);
    bool success;
    if (action == "encrypt") {
        success = tool.encrypt(inputFile, outputFile, password, keyfile);
    } else if (action == "decrypt") {
        success = tool.decrypt(inputFile, outputFile, password, keyfile);
    } else {
        if (!quietMode) {
            std::cerr << "Invalid action: " << action << std::endl;
            showHelp();
        }
        return -1;
    }

    if (!success) {
        if (!quietMode) {
            std::cerr << "Operation failed." << std::endl;
        }
        return -1;
    }

    if (!quietMode) {
        std::cout << "Operation succeeded." << std::endl;
    }
    
    return 0;
}


