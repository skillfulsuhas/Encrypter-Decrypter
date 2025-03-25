from flask import Flask, render_template, request, redirect, url_for, session# Importing for web application functionality
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet #for audio and image encryption

import socket  # Importing for network communication
import threading  # Importing for concurrent execution of tasks
from rsa import generate_keypair, encrypt_rsa, decrypt_rsa  # Importing RSA encryption functions
from playfaircipher import encrypt_playfair, decrypt_playfair, generate_playfair_matrix  # Importing Playfair cipher functions
from aes import aes_encrypt, aes_decrypt  # Importing AES encryption functions
from ecies.utils import generate_eth_key  # Importing Ethereum key generation function
from eccc import ecc_encrypt, ecc_decrypt  # Importing ECC encryption functions


app = Flask(__name__)# Creating a Flask application instance
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'abcchash'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

public_key, private_key = generate_keypair()  # Generating RSA keypair
eth_key = generate_eth_key()  # Generating Ethereum keypair for ECC
public_key_ecc = eth_key.public_key.to_hex()  # Getting hexadecimal representation of ECC public key
private_key_ecc = eth_key.to_bytes()  # Getting byte representation of ECC private key


# Function to handle multiple client connections
def handle_client(conn, addr, public_key, private_key):
    print("Connection from:", addr)  # Printing client connection information
    key = None  # Initializing key variable for cipher keys
    while True:  # Start an infinite loop for receiving messages from client
        data = conn.recv(1024).decode()  # Receiving data from client
        if not data:  # Break the loop if no data is received
            break
        print(f"Received message from {addr}: {data}")  # Printing received message

        parts = data.split("_")  # Splitting the data into operation and algorithm parts
        if len(parts) != 2:  # If the format is incorrect, send an error message to client
            result = "Invalid message format"
            conn.sendall(result.encode())
            continue

        operation, algorithm = parts  # Assigning operation and algorithm from received data
        operation = operation.lower()  # Converting operation to lowercase

        print("Operation =", operation)  # Printing operation
        print("Algorithm =", algorithm)  # Printing algorithm

        message = data.split(":")[1].strip()  # Extracting the message part from received data
        print("Message =", message)  # Printing the message

        algorithm = algorithm[0]  # Taking the first character of algorithm as identifier
        print("Algorithm =", algorithm)  # Printing the algorithm identifier

        # Handling different encryption/decryption algorithms
        if algorithm == "R" and operation in ["e", "encrypt", "d", "D", "decrypt"]:
            if operation == "e":  # If operation is encryption
                result = encrypt_rsa(public_key, message)  # Encrypting using RSA
            else:  # If operation is decryption
                ciphertext = list(map(int, message.split()))  # Converting ciphertext to list of integers
                result = decrypt_rsa(private_key, ciphertext)  # Decrypting using RSA
        elif algorithm == "P" and operation in ["e", "encrypt", "d", "decrypt"]:
            key = input("Enter the key for Playfair cipher: ")  # Getting key for Playfair cipher from user
            key_matrix = generate_playfair_matrix(key)  # Generating Playfair matrix
            if operation == "e":  # If operation is encryption
                result = encrypt_playfair(message, key_matrix)  # Encrypting using Playfair cipher
            else:  # If operation is decryption
                result = decrypt_playfair(message, key_matrix)  # Decrypting using Playfair cipher
        elif algorithm == "A" and operation in ["e", "E", "encrypt", "d", "D", "decrypt"]:
            key = input("Enter the key for AES: ")  # Getting key for AES from user
            if operation == "e":  # If operation is encryption
                result = aes_encrypt(key, message)  # Encrypting using AES
            else:  # If operation is decryption
                result = aes_decrypt(key, message)  # Decrypting using AES
        elif algorithm == "E" and operation in ["e", "E", "encrypt", "d", "D", "decrypt"]:
            if operation == "e":  # If operation is encryption
                result = ecc_encrypt(public_key_ecc, message.encode())  # Encrypting using ECC
            else:  # If operation is decryption
                result = ecc_decrypt(private_key_ecc, message)  # Decrypting using ECC
        else:  # If algorithm or operation is invalid
            result = "Invalid algorithm or operation"  # Set result to error message

        conn.sendall(str(result).encode())  # Sending the result back to client

    conn.close()  # Closing connection with client
    print(f"Connection from {addr} closed")  # Printing connection closed message

@app.route('/')# Route for the index page
def home():
    if 'user_id' in session:
        return redirect(url_for('index'))  # Redirecting to index if user is logged in
    return redirect(url_for('login'))  # Redirecting to login if user is not logged in

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home'))  # Redirecting to home page after logout

@app.route('/index')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirecting to login if user is not logged in
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Checking if the  username or email already exists
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            return 'Username or email already exists. Please choose another.'

        # Hashing the password before storing in the database
        hashed_password = generate_password_hash(password)

        # Creating  a new user instance
        new_user = User(username=username, email=email, password=hashed_password)

        # Adding the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Redirecting to the login page after successful signup
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    error = None  # Initializing error message variable

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))  # Redirecting to index page after successful login
        else:
            error = 'Invalid username or password. Please try again.'

    return render_template('login.html', error=error)
# Route for processing form submission
@app.route('/process', methods=['POST'])
def process():
    uploaded_file = request.files.get('message_file')  # Getting uploaded file from form
    if uploaded_file:  # If file uploaded
        message_text = uploaded_file.read().decode("utf-8")  # Reading message from file
    else:  # If no file uploaded
        message_text = request.form.get('message')  # Getting message from form
    if not message_text:  # If no message provided
        return "Please enter a message or select a file to upload."  # Return error message

    algorithm = request.form['algorithm']  # Getting selected algorithm from form
    operation = request.form['operation']  # Getting selected operation from form

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:  # Creating client socket
        host = "127.0.0.1"  # Server IP address
        port = 12345  # Server port
        client_socket.connect((host, port))  # Connecting to server

        data = f"{operation}_{algorithm}:{message_text}"  # Constructing data to send to server
        client_socket.sendall(data.encode())  # Sending data to server

        result = client_socket.recv(1024).decode()  # Receiving result from server

    return render_template('index.html', message=message_text, result=result)  # Rendering index page with message and result

# Function to run the server
def run_server():
    host = "127.0.0.1"  # Server IP address
    port = 12345  # Server port

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Creating server socket
    server_socket.bind((host, port))  # Binding server socket to address
    server_socket.listen(5)  # Listening for connections

    print("Server listening on port", port)  # Printing server listening message

    while True:  # Starting an infinite loop to accept client connections
        conn, addr = server_socket.accept()  # Accepting client connection
        client_handler = threading.Thread(target=handle_client, args=(conn, addr, public_key, private_key))  # Creating thread for client handling
        client_handler.start()  # Starting client handling thread

# Creating the database tables within the Flask application context
with app.app_context():
    db.create_all()


if __name__ == "__main__":  # Checking if script is run directly
    threading.Thread(target=run_server).start()  # Starting server in a separate thread
    app.run(host="0.0.0.0", port=50100, debug=True, ssl_context=('Encrypter_Decrypter\cert.pem', 'Encrypter_Decrypter\key.pem'))  # Running Flask app with SSL encryption
