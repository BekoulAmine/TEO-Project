def encrypt_caesar(plaintext, shift):
    encrypted_text = []
    for char in plaintext:
        if char.isalpha():
            shift_amount = shift % 26
            code = ord(char) + shift_amount
            if char.islower():
                if code > ord('z'):
                    code -= 26
                encrypted_text.append(chr(code))
            elif char.isupper():
                if code > ord('Z'):
                    code -= 26
                encrypted_text.append(chr(code))
        else:
            encrypted_text.append(char)
    return ''.join(encrypted_text)

def decrypt_caesar(ciphertext, shift):
    return encrypt_caesar(ciphertext, -shift)

def main():
    choice = input("Enter 'e' to encrypt or 'd' to decrypt: ").lower()
    text = input("Enter the text: ")
    shift = int(input("Enter the shift value: "))

    if choice == 'e':
        encrypted_text = encrypt_caesar(text, shift)
        print(f"Encrypted text: {encrypted_text}")
    elif choice == 'd':
        decrypted_text = decrypt_caesar(text, shift)
        print(f"Decrypted text: {decrypted_text}")
    else:
        print("Invalid choice. Please enter 'e' to encrypt or 'd' to decrypt.")

if __name__ == "__main__":
    main()
