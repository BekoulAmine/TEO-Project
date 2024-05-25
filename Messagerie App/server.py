import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import os

# Generate a random key and IV
def generate_key_iv():
    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)   # 128-bit IV
    return key, iv

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

# Handle client connections
def handle_client(client_socket, addr, key, iv):
    print(f"[+] New connection from {addr}")
    while True:
        try:
            encrypted_message = client_socket.recv(4096).decode('utf-8')
            if encrypted_message:
                message = decrypt_message(encrypted_message, key, iv)
                print(f"[{addr}] {message}")
                broadcast(message, client_socket, key, iv)
            else:
                break
        except Exception as e:
            print(f"[-] Error: {e}")
            break
    client_socket.close()

# Broadcast messages to all clients
def broadcast(message, client_socket, key, iv):
    for client in clients:
        if client != client_socket:
            encrypted_message = encrypt_message(message, key, iv)
            client.send(encrypted_message.encode('utf-8'))

# Main server function
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 5555))
    server.listen(5)
    print("[*] Server listening on port 5555")

    key, iv = generate_key_iv()

    while True:
        client_socket, addr = server.accept()
        clients.append(client_socket)
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr, key, iv))
        client_handler.start()

if __name__ == "__main__":
    clients = []
    main()
