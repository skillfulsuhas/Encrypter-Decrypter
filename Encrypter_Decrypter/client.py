import socket

def main():
    host = "127.0.0.1"  # Setting the host IP address
    port = 12345  # Setting the port number for communication

    try:
        # Creating a TCP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Connecting the client socket to the server
        client_socket.connect((host, port))
    except Exception as e:
        print(f"Error connecting to the server: {e}")
        return

    try:
        # Asking the user for username and password
        username = input("Enter your username: ").strip()
        password = input("Enter your password: ").strip()

        if not username or not password:
            print("Username or password cannot be empty.")
            return

        # Sending authentication credentials to the server
        client_socket.sendall(f"{username}:{password}".encode())

        # Receiving authentication result from the server
        authentication_result = client_socket.recv(1024).decode()

        if authentication_result != "Authenticated":
            print("Authentication failed")
            client_socket.close()
            return

        print("Authentication successful")

        while True:  # Starting an infinite loop for user interaction until client exits on their own
            # Asking the user for input - encrypt, decrypt, or quit
            choice = input("Enter 'E' to encrypt or 'D' to decrypt (Q to quit): ").upper()

            if choice == 'Q':  # If the user wants to quit
                # Sending a message to the server indicating the intention to quit
                client_socket.sendall("quit".encode())
                break  # Breaking out of the loop to end the program

            # If the user's choice is neither 'E', 'D', nor 'Q', asking the user to enter a valid choice
            if choice not in ['E', 'D']:
                print("Invalid choice. Please enter 'E', 'D', or 'Q.")
                continue  # Continuing to the next iteration of the loop

            # Giving choices to the user to select an encryption or decryption algorithm
            print("Index")
            print("1. 'R' for RSA")
            print("2. 'P' for Playfair")
            print("3. 'A' for AES")
            print("4. 'E' for ECC")
            print()

            # Taking input from the user
            algorithm_choice = input("Enter your choice: ").upper()

            # If the user's algorithm choice is invalid, asking them to enter a valid choice
            if algorithm_choice not in ['R', 'P', 'A', 'E']:
                print("Invalid choice. Please enter 'R', 'P', 'A' or 'E'.")
                continue  # Continuing to the next iteration of the loop

            # Asking the user to input the message to encrypt or decrypt
            message = input(f"Enter the message to {choice.lower()}: ")

            # command to send to server in the format: [choice for operation]_[algorithm_choice]:[message]
            command = f"{choice.lower()}_{algorithm_choice}:{message}"

            # Sending the command to the server
            client_socket.sendall(command.encode())

            if choice == 'E' or choice == 'D':  # If the user chose encryption or decryption
                # Receiving the result from the server
                result = client_socket.recv(1024).decode()

                # Printing the result of encryption or decryption
                print(f"Result of {choice.lower()}: {result}")

                if choice == 'E':  # If the user chose encryption
                    # Displaying the ciphertext as a hexadecimal string
                    print(f"Ciphertext (hex): {result}")
            else:  # If the user chose an option other than encryption or decryption
                print(f"Result of {choice.lower()}: {result}")
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        # Closing the client socket connection
        client_socket.close()

if __name__ == "__main__":  # Checking if the script is being run directly
    main()  # Calling the main function if the script is run directly
