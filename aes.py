from Crypto.Cipher import AES
from secrets import token_bytes

key = token_bytes(16)  # 128-bit random key

def encrypt(msg):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag

def decrypt(nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except:
        return False

# Read input from file
with open("password.txt", "r", encoding="ascii") as f:
    msg = f.read()

# Encrypt
nonce, ciphertext, tag = encrypt(msg)

# Save encrypted output to file
with open("passwords_encrypted.txt", "wb") as f:
    f.write(nonce + tag + ciphertext)

# Decrypt
plaintext = decrypt(nonce, ciphertext, tag)

# Save decrypted output to file if successful
if plaintext:
    with open("passwords_decrypted.txt", "w", encoding="ascii") as f:
        f.write(plaintext)
    print("Encryption and decryption complete.")
    print("Encrypted file: passwords_encrypted.txt")
    print("Decrypted file: passwords_decrypted.txt")
else:
    print("Message is corrupted – decryption failed.")
