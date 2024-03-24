from ecies import encrypt, decrypt  # Importing encrypt and decrypt functions from ecies module
#from ecies.utils import generate_eth_key  # Importing function to generate Ethereum key pair

# Function to encrypt data using ECC
def ecc_encrypt(public_key, data):
    # Encrypting the data using the provided public key
    encrypted_data = encrypt(public_key, data)
    # Converting the encrypted data to hexadecimal representation
    encrypted_data_hex = encrypted_data.hex()
    return encrypted_data_hex  # Returning the hexadecimal encrypted data

# Function to decrypt data using ECC
def ecc_decrypt(private_key, encrypted_data_hex):
    encrypted_data_hex = encrypted_data_hex.strip()  # Stripping any leading/trailing whitespace
    try:
        # Removing any non-hexadecimal characters from the input
        encrypted_data_hex = ''.join(filter(lambda x: x in '0123456789abcdefABCDEF', encrypted_data_hex))
        # Converting the hexadecimal encrypted data back to bytes
        encrypted_data = bytes.fromhex(encrypted_data_hex)
        # Decrypting the data using the provided private key
        decrypted_data = decrypt(private_key, encrypted_data)
        return decrypted_data.decode()  # Returning the decrypted data as a string
    except ValueError:
        print("Invalid input data. Please provide a valid hexadecimal encrypted data.")  # Handling invalid input data
