import os
from OpenSSL import crypto
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Generate a random key and IV
def generate_key_iv():
    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)   # 128-bit IV
    return key, iv

# Encrypt the plaintext
def encrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return b64encode(ciphertext).decode('utf-8')

# Decrypt the ciphertext
def decrypt(ciphertext, key, iv):
    ciphertext = b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')

# Main function to demonstrate encryption and decryption
def main():
    # Generate key and IV
    key, iv = generate_key_iv()

    # Text to be encrypted
    plaintext = "Hello, OpenSSL encryption!"
    print(f"Plaintext: {plaintext}")

    # Encrypt the plaintext
    ciphertext = encrypt(plaintext, key, iv)
    print(f"Encrypted: {ciphertext}")

    # Decrypt the ciphertext
    decrypted_text = decrypt(ciphertext, key, iv)
    print(f"Decrypted: {decrypted_text}")

if __name__ == "__main__":
    main()
