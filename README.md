# Cipherator
Cipherator is a command-line tool for encrypting and decrypting files using AES-256 in GCM mode. Mainly written by ChatGPT 4 following prompts by @chatgptdev.

## Features

- Encryption using AES-256 in GCM mode.
- 12-byte nonce for GCM.
- Key derivation using PBKDF2 with HMAC-SHA256 (100,000 iterations).
- Password and/or keyfile support for key derivation.
- Supports only the first 1MiB of the keyfile.
- SHA256 hashing of keyfile data and password when a keyfile is specified. The resulting hash value is used as input to the PBKDF2 function.
- Utilizes the Windows BCrypt API for cryptographic operations.

## Usage

```
cipherator -a <action> -i <input_file> -o <output_file> [-p <password>] [-k <keyfile>] [-q] [-h]
```

Options:

- `-a <action>`: `encrypt` or `decrypt`.
- `-i <input_file>`: Input file path.
- `-o <output_file>`: Output file path.
- `-p <password>`: Password (optional). If the password value is empty, it will be requested.
- `-k <keyfile>`: Keyfile path (optional). If the path value is empty, it will be requested.
- `-q`: Quiet mode (no text output).
- `-h`: Show help.

## Encrypted File Format

When a file is encrypted, the following data is stored in the output file:

1. 32-byte salt, generated randomly.
2. 12-byte nonce, generated randomly.
3. Encrypted data, in chunks of 64KB.
4. Authentication tag for each chunk, generated during encryption, is appended to its correspoding encrypted chunk.

## Key Management

Cipherator uses PBKDF2 with HMAC-SHA256 and 100,000 iterations to derive a 256-bit key from the provided password and/or keyfile. When a keyfile is specified, the first 1MiB of the keyfile is read, and its data is hashed using SHA256 along with the password. The resulting hash value is used as input to the PBKDF2 function.

## Building Cipherator

To build the Cipherator tool, follow these steps:

1. Clone the repository:

```
git clone https://github.com/chatgptdev/Cipherator.git
```

2. Change to the project directory:

```
cd cipherator
```


3. Create a build directory and navigate to it:

```
mkdir build && cd build
```


4. Run CMake to generate the build files:

```
cmake ..
```


5. Build the project:

```
cmake --build .
```

The `cipherator` binary will be generated in the `build` directory.

## Contributing

Contributions to Cipherator are welcome! If you'd like to contribute, please follow these guidelines:

1. Fork the repository.
2. Create a new branch with a descriptive name for your changes.
3. Make your changes and commit them with clear, concise commit messages.
4. Push your changes to your fork.
5. Open a pull request with a detailed description of your changes.

## License

Cipherator is licensed under the [MIT License](LICENSE).
