def generate_playfair_matrix(key):
    # Initializing an empty matrix
    matrix = [['' for _ in range(5)] for _ in range(5)]
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    # Replacing 'J' with 'I' and remove duplicate characters
    key = key.upper().replace('J', 'I')
    key_without_duplicates = ''.join(dict.fromkeys(key))

    # Filling the matrix with unique characters from the key
    row = 0
    col = 0
    for char in key_without_duplicates:
        matrix[row][col] = char
        col += 1
        if col == 5:
            col = 0
            row += 1

    # Filling the remaining cells with the remaining alphabet characters
    for char in alphabet:
        if char != 'J' and char not in key_without_duplicates:
            matrix[row][col] = char
            col += 1
            if col == 5:
                col = 0
                row += 1
    return matrix  # Returning the generated Playfair matrix

def find_char_positions(matrix, char):
    # Finding the row and column index of a character in the matrix
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j  # Returning the row and column index of the character

def encrypt_playfair(plaintext, key_matrix):
    # Checking if the length of the plaintext is odd
    if len(plaintext) % 2 != 0:
        plaintext += 'X'  # Adding an 'X' to make it even
    ciphertext = ''
    for i in range(0, len(plaintext), 2):
        char1 = plaintext[i].upper()
        char2 = plaintext[i + 1].upper() if i + 1 < len(plaintext) else 'X'
        if char1 == 'J':
            char1 = 'I'
        if char2 == 'J':
            char2 = 'I'
        row1, col1 = find_char_positions(key_matrix, char1)
        row2, col2 = find_char_positions(key_matrix, char2)
        if row1 == row2:  # Same row
            ciphertext += key_matrix[row1][(col1 + 1) % 5]
            ciphertext += key_matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:  # Same column
            ciphertext += key_matrix[(row1 + 1) % 5][col1]
            ciphertext += key_matrix[(row2 + 1) % 5][col2]
        else:  # Different row and column
            ciphertext += key_matrix[row1][col2]
            ciphertext += key_matrix[row2][col1]
    return ciphertext  # Returning the encrypted ciphertext

def decrypt_playfair(ciphertext, key_matrix):
    plaintext = ''
    for i in range(0, len(ciphertext), 2):
        char1 = ciphertext[i].upper()
        char2 = ciphertext[i + 1].upper() if i + 1 < len(ciphertext) else 'X'
        if char1 == 'J':
            char1 = 'I'
        if char2 == 'J':
            char2 = 'I'

        row1, col1 = find_char_positions(key_matrix, char1)
        row2, col2 = find_char_positions(key_matrix, char2)

        if row1 == row2:  # Same row
            plaintext += key_matrix[row1][(col1 - 1) % 5]
            plaintext += key_matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:  # Same column
            plaintext += key_matrix[(row1 - 1) % 5][col1]
            plaintext += key_matrix[(row2 - 1) % 5][col2]
        else:  # Different row and column
            plaintext += key_matrix[row1][col2]
            plaintext += key_matrix[row2][col1]

    # If the last character is 'X', removing it
    if plaintext.endswith('X'):
        plaintext = plaintext[:-1]

    return plaintext  # Returning the decrypted plaintext
