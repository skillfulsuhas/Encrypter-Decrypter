def gcd(a, b):
    while b != 0:
        a, b = b, a % b  # Euclidean algorithm for finding the greatest common divisor (GCD)
    return a  # Returning the GCD

def multiplicative_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0: # Base case for the extended Euclidean algorithm
            return b, 0, 1  
        else:
            g, y, x = extended_gcd(b % a, a)  # Recursive call for the extended Euclidean algorithm
            return g, x - (b // a) * y, y  # Return the GCD and coefficients
    g, x, _ = extended_gcd(e, phi)  # Calculate the extended GCD
    if g != 1:  # If the GCD is not 1, it means the multiplicative inverse does not exist
        raise Exception('Modular inverse does not exist')  # Raise an exception
    else:
        return x % phi  # Return the multiplicative inverse modulo phi

def generate_keypair():
    p = 13  # Example prime number
    q = 11  # Another prime number
    n = p * q  # Calculate the modulus
    phi = (p - 1) * (q - 1)  # Calculate Euler's totient function
    e = 7  # Public key exponent
    d = multiplicative_inverse(e, phi)  # Calculate the private key exponent
    return (e, n), (d, n)  # Return the public and private keys as tuples

def encrypt_rsa(public_key, plaintext):
    e, n = public_key  # Extract the public key components (exponent and modulus)
    if plaintext.islower():  # Check if the plaintext is lowercase
       encrypted_msg = [pow(ord(char) - 96, e, n) for char in plaintext]  # Encrypt each character to its corresponding integer value
    else:
       encrypted_msg = [pow(ord(char) - 64, e, n) for char in plaintext]  # Encrypt each character to its corresponding integer value (uppercase)
    # Convert the list of encrypted integers to a space-separated string
    encrypted_msg_str = ' '.join(map(str, encrypted_msg))
    return encrypted_msg_str  # Return the encrypted message as a string

def decrypt_rsa(private_key, ciphertext):
    d, n = private_key  # Extract the private key components (exponent and modulus)
    # Decrypt each integer back to its corresponding character
    if ciphertext:
        return ''.join(chr(pow(c, d, n) + 96) for c in ciphertext)  # Return the decrypted message as a string (lowercase)
    else:
        return "" # Return empty string if the ciphertext is empty
