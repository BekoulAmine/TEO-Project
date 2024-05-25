import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image
import numpy as np

# Generate RSA Key Pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as key_file:
        key_file.write(pem)

def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as key_file:
        key_file.write(pem)

# Generate and Encrypt Symmetric Key
def generate_symmetric_key():
    return os.urandom(32)  # Generate a random 256-bit key

def encrypt_symmetric_key(symmetric_key, public_key):
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def encrypt_image(image_path, symmetric_key, output_path):
    image = Image.open(image_path).convert('RGB')
    image_data = np.array(image)
    width, height = image.size
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(image_data.tobytes()) + encryptor.finalize()
    with open(output_path, 'wb') as f:
        f.write(iv)
        f.write(width.to_bytes(4, 'big'))
        f.write(height.to_bytes(4, 'big'))
        f.write(encrypted_data)

# Decrypt Symmetric Key
def decrypt_symmetric_key(encrypted_key, private_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

def decrypt_image(encrypted_image_path, symmetric_key, output_image_path):
    with open(encrypted_image_path, 'rb') as f:
        iv = f.read(16)
        width = int.from_bytes(f.read(4), 'big')
        height = int.from_bytes(f.read(4), 'big')
        encrypted_data = f.read()
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    expected_size = width * height * 3  # RGB image
    if len(decrypted_data) != expected_size:
        raise ValueError("Decrypted data size does not match expected image size")

    image = Image.frombytes('RGB', (width, height), decrypted_data)
    image.save(output_image_path)

# Menu Functions
def menu():
    while True:
        print("1. Generate RSA Key Pair")
        print("2. Encrypt Image")
        print("3. Decrypt Image")
        print("4. Exit")
        choice = input("Enter your choice: ")
        
        if choice == '1':
            private_key, public_key = generate_rsa_key_pair()
            save_private_key(private_key, 'private_key.pem')
            save_public_key(public_key, 'public_key.pem')
            print("RSA Key Pair generated and saved as 'private_key.pem' and 'public_key.pem'")
        
        elif choice == '2':
            image_path = input("Enter the path of the image to encrypt: ")
            symmetric_key = generate_symmetric_key()
            encrypted_symmetric_key = encrypt_symmetric_key(symmetric_key, public_key)
            with open('encrypted_symmetric_key.bin', 'wb') as f:
                f.write(encrypted_symmetric_key)
            encrypt_image(image_path, symmetric_key, 'encrypted_image.bin')
            print(f"Image encrypted and saved as 'encrypted_image.bin'")
        
        elif choice == '3':
            encrypted_image_path = 'encrypted_image.bin'
            with open('encrypted_symmetric_key.bin', 'rb') as f:
                encrypted_symmetric_key = f.read()
            decrypted_symmetric_key = decrypt_symmetric_key(encrypted_symmetric_key, private_key)
            decrypt_image(encrypted_image_path, decrypted_symmetric_key, 'decrypted_image.png')
            print("Image decrypted and saved as 'decrypted_image.png'")
        
        elif choice == '4':
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    # Generate RSA keys for demonstration
    private_key, public_key = generate_rsa_key_pair()
    save_private_key(private_key, 'private_key.pem')
    save_public_key(public_key, 'public_key.pem')
    
    menu()
