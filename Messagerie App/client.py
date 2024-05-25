import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import base64

# Encrypt the message
def encrypt_message(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return b64encode(ciphertext).decode('utf-8')

# Decrypt the message
def decrypt_message(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(b64decode(ciphertext)), AES.block_size)
    return plaintext.decode('utf-8')

# Receive messages from the server
def receive_messages(client_socket, key, iv):
    while True:
        try:
            encrypted_message = client_socket.recv(4096).decode('utf-8')
            if encrypted_message:
                message = decrypt_message(encrypted_message, key, iv)
                print(f"\r{message}\n> ", end="")
        except Exception as e:
            print(f"[-] Error: {e}")
            client_socket.close()
            break

# Main client function
def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 5555))  # Change to the server's IP address and port if different

    # Key and IV input from the user
    key_base64 = input("Enter the shared encryption key (32 bytes, base64): ")
    iv_base64 = input("Enter the shared IV (16 bytes, base64): ")

    # Decode from base64
    try:
        key = base64.b64decode(key_base64)
        iv = base64.b64decode(iv_base64)
    except Exception as e:
        print(f"[-] Error decoding base64: {e}")
        return

    # Ensure correct lengths
    if len(key) not in {16, 24, 32}:
        print("[-] Incorrect AES key length. Ensure the key is 16, 24, or 32 bytes after decoding.")
        return
    if len(iv) != 16:
        print("[-] Incorrect IV length. Ensure the IV is 16 bytes after decoding.")
        return

    # Start a thread to receive messages from the server
    receive_thread = threading.Thread(target=receive_messages, args=(client, key, iv))
    receive_thread.start()

    while True:
        message = input("> ")
        encrypted_message = encrypt_message(message, key, iv)
        client.send(encrypted_message.encode('utf-8'))

if __name__ == "__main__":
    main()
