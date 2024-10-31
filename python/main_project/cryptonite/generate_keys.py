#!/usr/bin/python3
from rich.console import Console
from rich.prompt import Prompt
from .general_tools import yes_no, write_to_file, input_file

console = Console()

def get_number_of_keys() -> int:
    """Prompt the user for the number of keys to generate."""
    while True:
        try:
            n_of_keys = Prompt.ask("Number of keys to generate", default="1", show_default=True)
            return int(n_of_keys)
        except ValueError:
            console.print("[bold red]Not a valid number. Please try again.[/bold red]")

def generate_encryption_keys(n_of_keys: int) -> list:
    """Generate a list of encryption keys."""
    keys = []
    for _ in range(n_of_keys):
        key = generate_key(ask_save=False)
        keys.append(key)
    return keys

def save_keys_to_file(keys: list):
    """Prompt for a filename and save the keys to that file."""
    if yes_no("Save to file?"):
        filename = input_file(ask_overwrite=True, file_exists_required=False)
        for key in keys:
            write_to_file(filename, f"{key.hex()}\n", "a")
        console.print("\n[green]Success: Keys saved to file.[/green]")

def display_keys(keys: list):
    """Display generated encryption keys."""
    console.print("\n[bold cyan]Generated Keys:[/bold cyan]")
    for key in keys:
        console.print(f"[bold yellow]{key.hex()}[/bold yellow]")

def menu():
    """Main menu for generating encryption keys."""
    n_of_keys = get_number_of_keys()
    encryption_keys = generate_encryption_keys(n_of_keys)
    display_keys(encryption_keys)
    save_keys_to_file(encryption_keys)

def main():
    menu()

if __name__ == "__main__":
    main()
