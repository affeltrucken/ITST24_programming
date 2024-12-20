#!/usr/bin/python3
from . import cryptonite_main
from rich.console import Console
from rich.prompt import Prompt

console = Console()

BANNER = """                         __              _ __
  ____________  ______  / /_____  ____  (_) /____ 
 / ___/ ___/ / / / __ \\/ __/ __ \\/ __ \\/ / __/ _ \\
/ /__/ /  / /_/ / /_/ / /_/ /_/ / / / / / /_/  __/
\\___/_/   \\__, / .___/\\__/\\____/_/ /_/_/\\__/\\___/ 
         /____/_/                           v1.1

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
        "7": "Shellcode crypter (C)",
        "8": "Compile C file to executable ",
        "0": "Exit"
    }
    
    console.print("\n[bold cyan]Main Menu[/bold cyan]\n")
    for key, value in options.items():
        console.print(f"[bold]{key}:[/bold] {value}")
    
    option = Prompt.ask("> ", choices=list(options.keys()), show_choices=False)
    handle_choice(option)

def handle_choice(option: str):
    match option:
        case "1":
            cryptonite_main.encrypt_phrase()
        case "2":
            cryptonite_main.encrypt_file()
        case "3":
            cryptonite_main.decrypt_phrase()
        case "4":
            cryptonite_main.decrypt_file()
        case "5":
            key = cryptonite_main.generate_key()
            console.print(f"[green]Generated key: {key.hex()}[/green]")
        case "6":
            key = cryptonite_main.generate_key_from_password()
            console.print(f"[green]Generated key: {key.hex()}[/green]")
        case "7":
            cryptonite_main.shellcode_c_crypter()
        case "8":
            console.print("[bold red]This feature is not reliable and might not work for your config. Manual compilation is recommended.[/bold red]")
            cryptonite_main.compile_c_file_to_executable()
        case "0":
            console.print("[bold red]Exiting...[/bold red]")
            exit()
        case _:
            console.print("[bold red]Invalid option! Please try again.[/bold red]")

def cryptonite():
    console.print(f"[bold]{BANNER}[/bold]")
    while True:
        menu()

def main():
    cryptonite()
    
if __name__ == "__main__":
    main()
