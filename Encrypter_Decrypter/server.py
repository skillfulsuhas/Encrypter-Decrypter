import socket  # Importing for network communication
import threading  # Importing to handle multiple clients simultaneously
from rsa import generate_keypair, encrypt_rsa, decrypt_rsa  # Importing functions for RSA encryption and decryption
from playfaircipher import encrypt_playfair, decrypt_playfair, generate_playfair_matrix  # Importing functions for Playfair cipher
from aes import aes_encrypt, aes_decrypt  # Importing functions for AES encryption and decryption
from ecies.utils import generate_eth_key  # Importing function to generate Ethereum keys
from eccc import ecc_encrypt, ecc_decrypt  # Importing functions for ECC encryption and decryption

# Generating RSA key pair
public_key, private_key = generate_keypair()

# Generating Ethereum key pair
eth_key = generate_eth_key()
public_key_ecc = eth_key.public_key.to_hex()
private_key_ecc = eth_key.to_bytes()

# Function to handle client connections
def handle_client(conn, addr, public_key, private_key):
    print("Connection from:", addr)  # Printing the address of the connected client
    key = None  # Initializing variable to store encryption key
    while True:  # Loop to continuously handle client requests
        # Receiving data from the client
        data = conn.recv(1024).decode()
        if not data:  # Breaking the loop when no data was received
            break
        print(f"Received message from {addr}: {data}")  # Printing the received message and client address

        # Spliting the received data into parts
        parts = data.split("_")
        if len(parts) != 2:  # Sending error message to client if message format is invalid
            result = "Invalid message format"
            conn.sendall(result.encode())
            continue

        operation, algorithm = parts  # Extracting operation and algorithm from the received message
        operation = operation.lower()  # Converting operation to lowercase

        print("Operation =", operation)  # Printing the operation
        print("Algorithm =", algorithm)  # Printing the algorithm

        # Extracting the message from the data
        message = data.split(":")[1].strip()
        print("Message =", message)  # Printing the message

        algorithm = algorithm[0]  # Extracting the first character of the algorithm

        print("Algorithm =", algorithm)  # Printing the algorithm

        # Performing operations based on the specified algorithm and operation
        if algorithm == "R" and operation in ["e", "encrypt", "d", "D", "decrypt"]:
            if operation == "e":  # If the operation is encryption
                result = encrypt_rsa(public_key, message)  # Encrypting the message using RSA
            else:  # If the operation is decryption
                ciphertext = list(map(int, message.split()))  # Converting ciphertext to a list of integers
                result = decrypt_rsa(private_key, ciphertext)  # Decrypting the message using RSA
        elif algorithm == "P" and operation in ["e", "encrypt", "d", "decrypt"]:
            key = input("Enter the key for Playfair cipher: ")  # Asking user to enter Playfair cipher key
            key_matrix = generate_playfair_matrix(key)  # Generating Playfair cipher key matrix
            if operation == "e":  # If the operation is encryption
                result = encrypt_playfair(message, key_matrix)  # Encrypting the message using Playfair cipher
            else:  # If the operation is decryption
                result = decrypt_playfair(message, key_matrix)  # Decrypting the message using Playfair cipher
        elif algorithm == "A" and operation in ["e", "E", "encrypt", "d", "D", "decrypt"]:
            key = input("Enter the key for AES: ")  # Asking user to enter AES key
            if operation == "e":  # If the operation is encryption
                result = aes_encrypt(key, message)  # Encrypting the message using AES
            else:  # If the operation is decryption
                result = aes_decrypt(key, message)  # Decrypting the message using AES
        elif algorithm == "E" and operation in ["e", "E", "encrypt", "d", "D", "decrypt"]:
            if operation == "e":  # If the operation is encryption
                result = ecc_encrypt(public_key_ecc, message.encode())  # Encrypting the message using ECC
            else:  # If the operation is decryption
                result = ecc_decrypt(private_key_ecc, message)  # Decrypting the message using ECC
        else:
            result = "Invalid algorithm or operation"  # If algorithm or operation is invalid, set result to error message

        conn.sendall(str(result).encode())  # Sending the result back to the client

    conn.close()  # Closing the connection
    print(f"Connection from {addr} closed")  # Printing connection closed message

# Function to run the server
def run_server():
    host = "127.0.0.1"  # Server host IP address
    port = 12345  # Server port number

    # Creating a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Binding the socket to the host and port
    server_socket.bind((host, port))
    # Listening for incoming connections
    server_socket.listen(5)

    print("Server listening on port", port)  # Printing server listening message

    while True:  # Infinite loop to accept and handle client connections
        # Accepting a new connection
        conn, addr = server_socket.accept()
        # Creating a new thread to handle the client
        client_handler = threading.Thread(target=handle_client, args=(conn, addr, public_key, private_key))
        client_handler.start()  # Starting the thread to handle the client

if __name__ == "__main__":
    run_server()  # Running the server
