from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt

console = Console()

def read_file(filename: str, read_mode: str = "r") -> bytes:
    with open(filename, read_mode) as file:
        return file.read()
    
def yes_no(prompt: str) -> bool:
    while True:
        answer = Prompt.ask(f"{prompt} (y/n): ").strip().lower()
        if answer in ['y', 'n']:
            return answer == 'y'
        console.print("Please enter 'y' or 'n'.")
        
def write_to_file(filename: str, data: str, mode: str = "a") -> None:
    with open(filename, mode, encoding="utf-8") as file:
        file.write(data)

def ask_overwrite(filename: str) -> bool:
    return not Path(filename).exists() or yes_no(f"{filename} exists. Overwrite?")

from pathlib import Path

def input_file(prompt_text: str = "", ask_overwrite: bool = True, file_exists_required: bool = True) -> str:
    while True:
        filename = Prompt.ask(f"Filename{f' ({prompt_text})' if prompt_text else ''}: ")
        file_path = Path(filename)
        
        if not file_path.exists():
            if file_exists_required:
                console.print("File does not exist.")
                continue
            else:
                return filename

        elif not file_exists_required or ask_overwrite:
            if not ask_overwrite or yes_no(f"{filename} already exists. Overwrite?"):
                return filename
        else:
            console.print("File exists and overwrite not permitted.")
            continue


def main():
    print("This is not meant to run directly. It is intended to be used as a library.")

if __name__ == "__main__":
    main()