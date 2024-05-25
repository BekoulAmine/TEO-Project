import os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Generate a random key and IV
def generate_key_iv():
    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)   # 128-bit IV
    return key, iv

# Encrypt the file
def encrypt_file(input_file, output_file, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    
    with open(output_file, 'wb') as f:
        f.write(b64encode(ciphertext))

# Decrypt the file
def decrypt_file(input_file, output_file, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    with open(input_file, 'rb') as f:
        ciphertext = b64decode(f.read())
    
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    with open(output_file, 'wb') as f:
        f.write(plaintext)

# Main function to demonstrate file encryption and decryption
def main():
    # Generate key and IV
    key, iv = generate_key_iv()

    # File paths
    input_file = 'D:\Codes\TEO\FileEncryption\plaintext.txt'
    encrypted_file = 'D:\Codes\TEO\FileEncryption\encrypted.enc'
    decrypted_file = 'D:\Codes\TEO\FileEncryption\decrypted.txt'

    # Encrypt the file
    encrypt_file(input_file, encrypted_file, key, iv)
    print(f"File '{input_file}' encrypted to '{encrypted_file}'.")

    # Decrypt the file
    decrypt_file(encrypted_file, decrypted_file, key, iv)
    print(f"File '{encrypted_file}' decrypted to '{decrypted_file}'.")

if __name__ == "__main__":
    main()
