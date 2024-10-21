import cryptonite
from rich.console import Console
from rich.prompt import Prompt

# Initialize the console for Rich
console = Console()

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
        "1": "Encrypt phrase",
        "2": "Encrypt file",
        "3": "Decrypt phrase",
        "4": "Decrypt file",
        "5": "Generate random key",
        "6": "Generate key from password (PBKDF2)",
        "7": "Shellcode crypter",
        "0": "Exit"
    }
    
    console.print("\n[bold cyan]Main Menu[/bold cyan]\n")
    for key, value in options.items():
        console.print(f"[bold]{key}:[/bold] {value}")
    
    option = Prompt.ask("> ", choices=list(options.keys()), show_choices=True)
    handle_choice(option)

def handle_choice(option: str):
    match option:
        case "1":
            cryptonite.encrypt_phrase()
        case "2":
            cryptonite.encrypt_file()
        case "3":
            cryptonite.decrypt_phrase()
        case "4":
            cryptonite.decrypt_file()
        case "5":
            key = cryptonite.generate_key()
            console.print(f"[green]Generated key: {key}[/green]")
        case "6":
            key = cryptonite.generate_key_from_password()
            console.print(f"[green]Generated key: {key}[/green]")
        case "7":
            cryptonite.shellcode_c_crypter()
        case "0":
            console.print("[bold red]Exiting...[/bold red]")
            exit()
        case _:
            console.print("[bold red]Invalid option! Please try again.[/bold red]")

def main():
    print(BANNER)
    while True:
        menu()

if __name__ == "__main__":
    main()
