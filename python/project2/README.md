
# Cryptonite: Shellcode Encryption and Decryption

Cryptonite is a Python-based utility for encrypting and decrypting shellcode, leveraging the NaCl (libsodium) library for cryptographic operations. It allows users to generate keys, save and load them, and create C templates for executing encrypted shellcode.
## Features

- Generate random encryption keys.
- Encrypt and decrypt files and phrases.
- Save and load keys from files.
- Create C code templates for executing encrypted shellcode.
- Support for both Windows and Linux platforms.

## Prerequisites

- Python 3.x
- Required libraries:
    - pynacl

You can install the required libraries using pip:

```bash
pip install pynacl
```

## Usage
### Encrypting a File

To encrypt a file, run the script and follow the prompts:
1. Specify the file to encrypt.
2. Choose to generate a new key or load an existing one.
3. The encrypted file will be saved with the .encrypted extension.

```python
encrypt_file()
```
### Encrypting a Phrase

To encrypt a phrase:

1. Specify the phrase to encrypt.
2. Choose to generate a new key or load an existing one.
3. The encrypted phrase will be saved to a file.
```python
encrypt_phrase()
```
### Decrypting a File

To decrypt an encrypted file, follow similar steps:

1. Provide the encrypted file.
2. Choose a key.
3. The decrypted data can be saved to a file.

```python
decrypt_data()
```

### Decrypting a Phrase

To decrypt an encrypted phrase:

1. Input the encrypted data in hex format.
2. Choose a key.
3. The decrypted phrase can be saved to a file.

```python
decrypt_phrase()
```

### Generate Key from Password

You can generate a key from a password using Argon2:

```python
generate_key_from_password()
```

### Creating C Template for Shellcode
To encrypt shellcode and generate a C template:

1. Specify the shellcode filename.
2. Choose a key.
3. The C template will be saved as crypted.c.

```python
shellcode_c_crypter()
```

### Compiling C to Executable

To compile the generated C code into an executable, specify the compiler, options, and output filename:

```python
compile_c_to_exe("crypted.c", platform="windows", compiler="x86_64-w64-mingw32-gcc", options="-lsodium -static")
```

## Example Commands
Run the main script to start using Cryptonite:

```bash
python cryptonite.py
```

Follow the prompts to encrypt/decrypt files or phrases, generate keys, and more.
# License

This project is licensed under the MIT License.
Contributions

Contributions are welcome! Feel free to open issues or submit pull requests.
Acknowledgments

    libsodium for cryptographic functionalities.
    Argon2 for password hashing.