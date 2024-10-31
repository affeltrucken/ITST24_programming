#!/usr/bin/python3
from cryptonite import cryptonite_main
from subdomain_enum import subdomain_enum_main
from vins import vins_main

from rich.console import Console
from rich.prompt import Prompt

console = Console()
BANNER = """
   ___   __   ___  _____  ______        
  / _ | / /  / _ \\/  _/ |/ / __/        
 / __ |/ /__/ // // //    /\\ \\          
/_/_|_/____/____/___/_/|_/___/___  _  __
/_  __/ __ \\/ __ \\/ /  / _ )/ __ \\| |/_/
 / / / /_/ / /_/ / /__/ _  / /_/ />  <  
/_/  \\____/\\____/____/____/\\____/_/|_|  
                                                                                              
Have fun!
"""
def menu():
    print(BANNER)
    options = {
        "1": "Cryptonite",
        "2": "Subdomain enum",
        "3": "Vins",
        "0": "Exit"
    }
    
    console.print("\n[bold cyan]Main Menu[/bold cyan]\n")
    for key, value in options.items():
        console.print(f"[bold]{key}:[/bold] {value}")
    
    option = Prompt.ask("> ", choices=list(options.keys()), show_choices=False)
    handle_choice(option)
    
def handle_choice(option):
    match option:
        case "1":
            cryptonite_main.main()
        case "2":
            subdomain_enum_main.main()
        case "3":
            console.print("[bold red]Not really advanced/implemented yet, just here for fun[/bold red]")
            vins_main.main()
        case "0":
            console.print("[bold red]Exiting...[/bold red]")
            exit()
        case _:
            console.print("[bold red]Invalid option! Please try again.[/bold red]")
            
def menu_loop():
    while True:
        menu()
        
def main():
    menu()
    
if __name__ == "__main__":
    main()