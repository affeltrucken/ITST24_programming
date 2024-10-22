import argparse
import sys
from cryptography.fernet import InvalidToken
import cryptonite
import gui
from pathlib import Path
from sys import argv

ERROR_BOTH_ENCRYPT_AND_DECRYPT = "You must provide either --encrypt or --decrypt, not both."
ERROR_MISSING_DATA_OR_FILE = "You must provide either 'data' or use the -f/--file option."
ERROR_INVALID_SALT = "Salt must be hex."

def add_parser() -> argparse.ArgumentParser:
    """Sets up the argument parser for command-line options."""
    parser = argparse.ArgumentParser(
        prog="Cryptonite",
        description="Symmetric encrypter/decrypter, key generator",
    )

    # Define the possible arguments
    parser.add_argument("-i", "--interface", action="store_true", help="Use the GUI")
    parser.add_argument("data", nargs="?", help="Data to encrypt/decrypt")
    parser.add_argument("-f", "--file", type=Path, help="Use file as input data")
    parser.add_argument("-k", "--key", help="Encryption/decryption key")
    parser.add_argument("-s", "--save-output", type=Path, help="Save output to specified file")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the provided data")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt the provided data")
    parser.add_argument("-g", "--generate-key", action="store_true", help="Generate a Fernet key")
    parser.add_argument("-p", "--password", help="Password for generating a key using PBKDF2")
    parser.add_argument("--salt", help="Optional salt for key generation in hex format", type=str)
    parser.add_argument("--shellcode-file", type=Path, help="Shellcode file to encrypt")

    return parser

def handle_password_key(args) -> str:
    """Generates or retrieves the encryption key."""
    if args.password:
        salt_hex = validate_salt(args)
        key = cryptonite.generate_key_from_password(args.password, salt_hex).decode("ascii")
        return key
    return args.key

def validate_salt(args) -> bytes:
    """Validates or generates the salt for key generation."""
    if args.salt:
        if cryptonite.valid_hex(args.salt):
            return bytes.fromhex(args.salt)
        else:
            raise ValueError(ERROR_INVALID_SALT)
    else:
        salt = cryptonite.generate_salt()
        print(f"Generated random salt: {salt.hex()}")
        return salt

def read_input_data(args) -> str:
    """Retrieves the input data from file or direct input."""
    if args.file:
        return args.file.read_text(encoding="utf-8")
    return args.data

def validate_args(args):
    """Checks for argument validity."""
    if args.encrypt and args.decrypt:
        raise argparse.ArgumentTypeError(ERROR_BOTH_ENCRYPT_AND_DECRYPT)
    
    if args.encrypt and not (args.data or args.file):
        raise argparse.ArgumentTypeError(ERROR_MISSING_DATA_OR_FILE)

def parse_arguments(parser) -> dict:
    """Handles the entire parsing flow, returning a validated config."""
    args = parser.parse_args()

    if not args.data and not args.file and not args.generate_key and not args.password:
        parser.error("You must provide either 'data', a file, or a password.")

    key = handle_password_key(args)
    data = read_input_data(args)

    validate_args(args)

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
    """Main entry point for the command-line interface."""
    parser = add_parser()

    if len(argv) == 1:
        gui.main()

    config = parse_arguments(parser)

    if config["interface"]:
        gui.main()

    output = ""

    if config["encrypt"]:
        if config["shellcode_file"]:
            cryptonite.shellcode_c_crypter(config["shellcode_file"], config["key"])
        else:
            output = cryptonite.encrypt_data(config["data"], config["key"]).decode("utf-8")
    elif config["decrypt"]:
        try:
            output = cryptonite.decrypt_data(config["data"], config["key"]).decode("utf-8")
        except (AttributeError, InvalidToken):
            sys.exit("Invalid token or decryption error.")
    else:
        output = config["key"]

    print(output)

    if config["save_output"]:
        cryptonite.write_to_file(config["save_output"], output)

if __name__ == "__main__":
    main()
