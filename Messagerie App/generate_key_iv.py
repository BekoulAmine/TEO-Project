import os
from base64 import b64encode

# Generate a 256-bit (32 bytes) encryption key
key = os.urandom(32)
key_base64 = b64encode(key).decode('utf-8')
print(f"Encryption Key (base64): {key_base64}")

# Generate a 128-bit (16 bytes) IV
iv = os.urandom(16)
iv_base64 = b64encode(iv).decode('utf-8')
print(f"IV (base64): {iv_base64}")
