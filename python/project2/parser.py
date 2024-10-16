import argparse
import cryptonite
import gui
from cryptography.fernet import InvalidToken
from pathlib import Path
from sys import argv

ERROR_MISSING_DATA_OR_FILE = "You must provide either 'data' or use the -f/--file option."
ERROR_MISSING_ENCRYPT_OR_DECRYPT = "You must provide the -e/--encrypt or -d/--decrypt option for data."
ERROR_MISSING_KEY = "You must supply a key for encryption/decryption using -k/--key, or generate one using -g."
ERROR_BOTH_ENCRYPT_AND_DECRYPT = "You must provide either --encrypt, or --decrypt, not both."
ERROR_INVALID_SALT = "Salt must be hex"

def add_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Cryptonite",
        description="Symmetric encrypter/decrypter, key generator",
    )
    
    parser.add_argument("-i", "--interface", action="store_true", help="Use the GUI")
    parser.add_argument("data", nargs="?", help="Data to encrypt/decrypt")
    parser.add_argument("-f", "--file", type=Path, help="Use file as input data")
    parser.add_argument("-k", "--key", help="Encryption/decryption key")
    parser.add_argument("-s", "--save-output", type=Path, help="Save output to specified file")
    parser.add_argument("-e", "--encrypt", action="store_true")
    parser.add_argument("-d", "--decrypt", action="store_true")
    parser.add_argument("-g", "--generate-key", action="store_true", help="Generate Fernet key")
    parser.add_argument("-p", "--password", help="Password for generating a key using PBKDF2")
    parser.add_argument("--salt", help="Optional salt for key generation in hex format", type=str)
    parser.add_argument("--shellcode-file", type=Path, help="Shellcode file to encrypt")

    return parser

def validate_args(parser):
    args = parser.parse_args()

    if not args.data and not args.file and not args.generate_key and not args.password:
        parser.error("You must provide either 'data', a file, or a password.")
    
    if args.encrypt and args.decrypt:
        parser.error("You must specify either --encrypt or --decrypt, not both.")
    
    if args.encrypt and not (args.data or args.file):
        parser.error("You must provide data using 'data' argument or --file when using --encrypt.")

    key = None
    if args.password:
        if args.salt:
            salt_hex = cryptonite.valid_hex(args.salt)
            if salt_hex:
                key = cryptonite.generate_key_from_password(args.password, salt_hex)
            else:
                parser.error(ERROR_INVALID_SALT)
                exit()
        else:       
            salt_hex = cryptonite.generate_salt()
            print(f"Randomised salt: {salt_hex.hex()}")
            
        key = cryptonite.generate_key_from_password(args.password, salt_hex).decode("ascii")
        
    else:
        key = args.key
        
    if args.file:
        data = args.file.read_text(encoding="utf-8")
    elif args.data:
        data = args.data
    else:
        data = None

    return {
        "data": data,
        "key": key,
        "encrypt": args.encrypt,
        "decrypt": args.decrypt,
        "save_output": args.save_output,
        "interface": args.interface,
        "shellcode_file": args.shellcode_file
    }

def main():
    parser = add_parser()
    args = parser.parse_args()
    
    if len(argv) == 1:
        gui.main()
    if args.interface:
        gui.main()
        
    config = validate_args(parser)

    if config["encrypt"]:
        if config["shellcode_file"]:
            cryptonite.shellcode_c_crypter(config["shellcode_file"], config["key"])
        else:
            output = cryptonite.encrypt_data(config["data"], config["key"]).decode("utf-8")
    elif config["decrypt"]:
        try:
            output = cryptonite.decrypt_data(config["data"], config["key"]).decode("utf-8")
        except (AttributeError, InvalidToken):
            exit()
    else:
        output = config["key"]

    print(output)

    if config["save_output"]:
        cryptonite.write_to_file(config["save_output"], output)

if __name__ == "__main__":
    main()
