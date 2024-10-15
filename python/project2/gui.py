import cryptonite

BANNER = """                         __              _ __     
  ____________  ______  / /_____  ____  (_) /____ 
 / ___/ ___/ / / / __ \\/ __/ __ \\/ __ \\/ / __/ _ \\
/ /__/ /  / /_/ / /_/ / /_/ /_/ / / / / / /_/  __/
\\___/_/   \\__, / .___/\\__/\\____/_/ /_/_/\\__/\\___/ 
         /____/_/                           v1.0

    by Aldin Smajlovic
""" 
    

def menu() -> None:
    options = {
        0: "Exit",
        1: "Encrypt phrase",
        2: "Encrypt file",
        3: "Decrypt phrase",
        4: "Decrypt file",
        5: "Generate key"
    }
    
    print()
    for option in options:
        print(f"{option}: {options[option]}")
    print()
    
    option = int(input("> "))
    match option:
        case 0:
            exit()
        case 1:
            cryptonite.encrypt_phrase()
        case 2:
            cryptonite.encrypt_file()
        case 3:
            cryptonite.decrypt_phrase()
        case 4:
            cryptonite.decrypt_file()
        case 5:
            cryptonite.generate_key()
            

def main():
    print(BANNER)
    while True:
        menu()

if __name__ == "__main__":
    main()
    
