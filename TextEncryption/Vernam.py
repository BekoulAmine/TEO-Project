import os
import base64

def generate_key(length):
    """Generate a random key of the specified length."""
    return os.urandom(length)

def vernam_encrypt(plaintext, key):
    """Encrypt the plaintext using the Vernam cipher."""
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext_bytes = bytes([p ^ k for p, k in zip(plaintext_bytes, key)])
    return base64.b64encode(ciphertext_bytes).decode('utf-8')

def vernam_decrypt(ciphertext, key):
    """Decrypt the ciphertext using the Vernam cipher."""
    ciphertext_bytes = base64.b64decode(ciphertext.encode('utf-8'))
    plaintext_bytes = bytes([c ^ k for c, k in zip(ciphertext_bytes, key)])
    return plaintext_bytes.decode('utf-8')

def main():
    # Input plaintext
    plaintext = input("Enter the plaintext: ")
    
    # Generate key
    key = generate_key(len(plaintext))
    
    # Encrypt plaintext
    ciphertext = vernam_encrypt(plaintext, key)
    
    # Decrypt ciphertext
    decrypted_text = vernam_decrypt(ciphertext, key)
    
    # Print results
    print(f"Plaintext: {plaintext}")
    print(f"Key (base64): {base64.b64encode(key).decode('utf-8')}")
    print(f"Ciphertext (base64): {ciphertext}")
    print(f"Decrypted text: {decrypted_text}")

if __name__ == "__main__":
    main()
