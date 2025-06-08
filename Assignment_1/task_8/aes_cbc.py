import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# generate random key and iv with 128 bits
key = get_random_bytes(16)
iv = get_random_bytes(16)

# get path to decoded.txt
script_dir = os.path.dirname(os.path.abspath(__file__))
decoded_path = os.path.join(script_dir, "decoded.txt")

# read decoded text
with open(decoded_path, "rb") as f:
    plaintext = f.read()

# add AES cipher
cipher = AES.new(key, AES.MODE_CBC, iv)
# encrypt with padding
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

print(ciphertext)
ciphertext_path = os.path.join(script_dir, "text.aes")
with open(ciphertext_path, "wb") as f:
    f.write(iv + ciphertext)
