READ WRITEUP [HERE](https://blog.aldinsmajlovic.se/blog/python-decrypter-encrypter-shellcode)

# Cryptonite: Shellcode Encryption and Decryption

Cryptonite is a Python-based utility for encrypting and decrypting shellcode, leveraging the NaCl (libsodium) library for cryptographic operations. It supports file and phrase encryption/decryption, key generation, and C code template generation for executing encrypted shellcode. The tool provides both CLI and GUI interfaces and is compatible with Windows and Linux platforms.
## Features

* Generate random encryption keys or derive keys from passwords using Argon2.
* Encrypt and decrypt files, phrases, or shellcode.
* Save and load keys from files.
* Create C code templates for executing encrypted shellcode.
* Support for both Windows and Linux platforms.

## Prerequisites

- **Tested with Python 3.12.5**
- **Required libraries**:
    - pynacl

You can install the required libraries using pip:

```bash
pip install pynacl
```

##Usage

Cryptonite provides both a command-line interface (CLI) and a graphical user interface (GUI).

### Command-Line Interface (CLI)

You can use the CLI to encrypt, decrypt, generate keys, and create C shellcode templates. The CLI offers several subcommands like encrypt, decrypt, and generate-key.

To start the CLI, run:

```bash
python cryptonite_main.py [options]
```

## Encrypting Data or Files ##

To encrypt a phrase or a file:

```bash
python cryptonite_main.py encrypt [-f FILE] [-p PASSWORD] [--salt SALT] [--shellcode-file FILE]
```

* `-f, --file`: File to encrypt.
* `-p, --password`: Optional password for key derivation.
* `--salt`: Optional salt for password-based key generation (hex format).
* `--shellcode-file`: Specify a file containing shellcode to encrypt.

## Decrypting Data or Files ##

To decrypt a phrase or a file:

```bash
python cryptonite_main.py decrypt [-f FILE] [-p PASSWORD] [--salt SALT]
```

* `-f, --file`: File to decrypt.
* `-p, --password`: Optional password for key derivation.
* `--salt`: Optional salt for password-based key generation (hex format).

## Key Generation ##

To generate a new key:

```bash
python cryptonite_main.py generate-key [-p PASSWORD] [--salt SALT]
```

* `-p, --password`: Optional password for deriving the key.
* `--salt`: Optional salt for password-based key generation (hex format).

## Getting Started

To start using Cryptonite, run the main script:

```bash
python cryptonite_main.py
```

Or, use the GUI with:

```bash
python cryptonite_main.py -i
```

# License

This project is licensed under the MIT License.

Contributions are welcome! Feel free to open issues or submit pull requests.
Acknowledgments

    libsodium for cryptographic functionalities.
    Argon2 for password hashing.
