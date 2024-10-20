import cryptonite

BANNER = """\
                         __              _ __     
  ____________  ______  / /_____  ____  (_) /____ 
 / ___/ ___/ / / / __ \\/ __/ __ \\/ __ \\/ / __/ _ \\
/ /__/ /  / /_/ / /_/ / /_/ /_/ / / / / / /_/  __/
\\___/_/   \\__, / .___/\\__/\\____/_/ /_/_/\\__/\\___/ 
         /____/_/                           v1.0

    by Aldin Smajlovic
"""

def display_menu() -> None:
    """Displays the menu options."""
    options = {
        0: "Exit",
        1: "Encrypt phrase",
        2: "Encrypt file",
        3: "Decrypt phrase",
        4: "Decrypt file",
        5: "Generate random key",
        6: "Generate key from password (PBKDF2)",
        7: "Shellcode crypter"
    }

    print("\nMenu Options:")
    for option, description in options.items():
        print(f"{option}: {description}")
    print()

def handle_user_choice(option: str) -> None:
    """Handles the user's menu choice."""
    match option:
        case "0":
            exit()
        case "1":
            cryptonite.encrypt_phrase()
        case "2":
            cryptonite.encrypt_file()
        case "3":
            cryptonite.decrypt_phrase()
        case "4":
            cryptonite.decrypt_file()
        case "5":
            cryptonite.generate_key()
        case "6":
            cryptonite.generate_key_from_password()
        case "7":
            cryptonite.shellcode_c_crypter()
        case _:
            print("Invalid option. Please try again.")

def main() -> None:
    """Main function to run the console application."""
    print(BANNER)
    while True:
        display_menu()
        user_input = input("> ")
        handle_user_choice(user_input)

if __name__ == "__main__":
    main()
