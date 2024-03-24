# aes.py
from Crypto.Cipher import AES
import base64

def aes_encrypt(key, plaintext):
    # Converting the key to bytes
    key_bytes = key.encode('utf-8')

    # Padding the plaintext to make it a multiple of the block size using PKCS7 padding
    block_size = AES.block_size
    padding_length = block_size - len(plaintext) % block_size
    plaintext_padded = plaintext + chr(padding_length) * padding_length

    # Creating AES cipher object
    cipher = AES.new(key_bytes, AES.MODE_ECB)

    # Encrypting the plaintext
    ciphertext = cipher.encrypt(plaintext_padded.encode('utf-8'))

    # Converting the ciphertext to a base64-encoded string
    ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')

    return ciphertext_base64


def aes_decrypt(key, ciphertext_base64):
    # Converting the key to bytes
    key_bytes = key.encode('utf-8')

    # Decoding the base64-encoded ciphertext
    ciphertext = base64.b64decode(ciphertext_base64)

    # Creating AES cipher object
    cipher = AES.new(key_bytes, AES.MODE_ECB)

    # Decrypting the ciphertext
    decrypted_padded = cipher.decrypt(ciphertext).decode('utf-8')

    # Removing PKCS7 padding
    padding_length = ord(decrypted_padded[-1])
    decrypted = decrypted_padded[:-padding_length]

    return decrypted

