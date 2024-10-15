from cryptonite import yes_no, write_to_file, enter_filename, generate_key

def menu():
    encryption_keys = []
    
    while True:
        try:
            n_of_keys = int(input("Number of keys to generate: "))
            break
        except ValueError:
            print("Not a valid number.")
    
    for i in range(0, n_of_keys):
        str_key = generate_key(ask_save_bool=True)
        encryption_keys.append(str_key)
    
    for key in encryption_keys:
        print(key)
    
    if yes_no("Save to file?"):
        filename = enter_filename()
                
        for key in encryption_keys:
            write_to_file(filename, f"{key}\n", "a")
        print("\nSuccess.")
        
        
def main():
    menu()
    
if __name__ == "__main__":
    main()
    
