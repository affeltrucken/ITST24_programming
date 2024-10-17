from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import parser
from os import urandom
from pathlib import Path
import base64

def readFile(filename: str) -> str:
    with open(filename, "r") as file:
        return file.read()

def generate_key(ask_save_bool=False):
    key = Fernet.generate_key().decode()
    print(f"Generated key: {key}")
    if ask_save_bool: ask_save(key)
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

def validate_key(key: str):
    try:
        fernet = Fernet(key)
        return key
    except ValueError:
        print("Invalid key.")
        return None
    
def yes_no(prompt: str) -> bool:
    while True:
        answer = input(f"{prompt} (y/n): ").strip().lower()
        if answer == 'y':
            return True
        elif answer == 'n':
            return False
        else:
            print("Please enter 'y' or 'n'.")

def enter_filename() -> str:
    filename = ""
    while True:
        filename = input("Filename: ")
        if filename == "":
            print("Please enter filename.\n")
        if ask_overwrite(filename):
            return filename

def ask_key() -> bytes:
    if yes_no("Generate key?"):
        return bytes(generate_key(), "ascii")
    if yes_no("Load key from file?"):
        while True:
            filename = input("Filename: ")
            if not Path(filename).exists():
                print("File doesn't exist.")
            else:
                key = readFile(filename)
                break
    else:
        key = input("Key: ")
        while not validate_key(key):
            key = input("Key: ")
        return bytes(key, "ascii")  
    
    return bytes(key, "ascii")

def encrypt_data(data: bytes, key: bytes) -> bytes:
    key = validate_key(key)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)
    return encrypted_data


def decrypt_data(data: str, key: bytes, ask_save_bool=False) -> bytes:
    fernet = Fernet(key)
    try:
        decrypted_data = fernet.decrypt(data).decode()
    except InvalidToken:
        print("Invalid data. Decryption failed.")
        return
    print(f"Output: {decrypted_data}")
    if ask_save_bool: ask_save(decrypted_data)
    return decrypted_data

def encrypt_phrase(phrase="", key="") -> bytes:
    phrase = phrase.encode("utf-8")
    if not key:
        key = ask_key()
    else:
        validate_key(key)
        
    if not phrase:
        data = input("Enter phrase to encrypt: ")
        
    encrypted_data = encrypt_data(data.encode("utf-8"), key)
    print(encrypted_data.decode().strip())
    print()
    
    if yes_no("Save to file?"):
        filename = input("Filename: ")
        write_to_file(f"{filename}.encrypted", encrypted_data.decode(), "w")
    return encrypted_data
        
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
    
    file_data = bytes(readFile(filename), "utf-8")
    encrypted_file_data = encrypt_data(file_data, key)
    write_to_file(f"{filename}.encrypted", encrypted_file_data.decode(), "w")
    print(f"Written to {filename}.\n")

def decrypt_phrase(phrase="", key="", ask_save_bool=False) -> bytes:
    key = input("Key: ")
    
    while not validate_key(key):
        key = input("Key: ")
                
    if not phrase:
        encrypted_data = input("Enter encrypted phrase: ")
    
    decrypted_data = decrypt_data(encrypted_data.encode("utf-8"), key, ask_save_bool)
    
    if yes_no("Save to file?"):
        filename = input("Filename: ")
        write_to_file(f"{filename}.decrypted", decrypted_data.decode(), "w")
    return decrypted_data

def decrypt_file(filename="") -> bytes:
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
    encrypted_data = readFile(filename)
    decrypted_data = decrypt_data(encrypted_data, key)
    
    if yes_no("Save to file?"):
        filename = input("Filename: ")
        write_to_file(f"{filename}.decrypted", decrypted_data.decode(), "w")
    
    return decrypted_data

def valid_hex(string: str) -> str:
    try:
        string = bytes.fromhex(string)
        return string
    except ValueError:
        return None


def generate_salt(length=16) -> bytes:
    return urandom(length)

def generate_key_from_password(password="", salt="", iterations: int = 100000) -> bytes:
    if not password:
        password = input("Password: ")
    
    while not salt:
        salt = input("Salt (leave empty for random): ")
        
        if salt == "":
            salt = generate_salt()
            break
        try:
            salt = bytes.fromhex(salt)
        except ValueError:
            print(f"Error. Salt needs to be in hex, like so, a3f5c4e2d4f9a2b3c4d5e6f7a9f0a1b2")
            salt = ""
            
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def main():
    parser.main()
    
if __name__ == "__main__":
    main()
