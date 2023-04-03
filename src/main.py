import os
import string
import secrets
import argparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def generate_random_password():
    """Generates a random password."""
    # Set the length of the password
    password_length = 32

    # Generate a random string of letters and digits
    return secrets.token_urlsafe(password_length)

def encrypt_with_rsa(word, public_key):
    """Encrypts a password using ECC with a public key."""
    # Encrypt the password using the public key
    ciphertext = public_key.encrypt(
        word,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_with_rsa(encrypted_word, private_key):
    plaintext = private_key.decrypt(
        encrypted_word,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def encrypt_secure_fasta(input_file, output_file, password, mode):
    """Encrypts a FASTA file and writes the result to a SecureFASTA file."""
    # Set the salt and number of iterations for the PBKDF2 key derivation function
    salt = os.urandom(16)
    iterations = 10000

    # Use PBKDF2 to derive a key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )

    key = kdf.derive(password)

    iv = os.urandom(16)

    # Initialize the AES cipher in cipher block chaining (OFB) mode
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    encryptor = cipher.encryptor()

    encrypted_data = bytes()
    schema = ""

    if mode == "headers":

        with open(input_file, "rb") as input_file:
            with open(output_file, "wb") as output_file:
                # Read the data from the FASTA file
                for line in input_file:
                    if line[0] == 62:
                        output_file.write(b">")
                        schema += str(output_file.tell()) + ":" 
                        output_file.write(encryptor.update(line[1:]))
                        schema += str(output_file.tell()) + ";" 
                        output_file.write(b"\n")
                    else:
                        output_file.write(line)

    elif mode == "sequences":

        with open(input_file, "rb") as input_file:
            with open(output_file, "wb") as output_file:
                # Read the data from the FASTA file
                tmp_buffer = bytes()
                
                for line in input_file:
                    if line[0] == 62:
                        if tmp_buffer != bytes():
                            schema += str(output_file.tell()) + ":" 
                            output_file.write(encryptor.update(tmp_buffer))
                            schema += str(output_file.tell()) + ";" 
                            output_file.write(b"\n")
                            tmp_buffer = bytes()
                        output_file.write(line)
                    else:
                        tmp_buffer += line

                schema += str(output_file.tell()) + ":" 
                output_file.write(encryptor.update(tmp_buffer))
                schema += str(output_file.tell()) + ";"  
    
    else:

        # Read the DNA or protein sequence data from the input file
        with open(input_file, "rb") as input_file:
            with open(output_file, "wb") as output_file:
                # Read the data from the FASTA file
                data = input_file.read()

                # Encrypt the data using the AES cipher
                output_file.write(encryptor.update(data) + encryptor.finalize())
        
        schema = ":"

    return salt, iterations, iv, schema

def decrypt_secure_fasta(input_file, output_file, password, salt, iterations, iv, mode, schema):
    """Decrypts a SecureFASTA file and writes the result to a FASTA file."""
    # Open the input file for reading
    with open(input_file, "rb") as f:
        # Read the salt, iterations, and IV from the file

        # Use PBKDF2 to derive a key from the password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )

        key = kdf.derive(password)

        # Initialize the AES cipher in cipher block chaining (OFB) mode
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
        decryptor = cipher.decryptor()

        data = bytes()

        if schema == ":":   
            data = f.read()

            # Encrypt the data using the AES cipher
            data = decryptor.update(data) + decryptor.finalize()

        else:

            schema = [tuple(map(int, s.split(":"))) for s in schema.split(";")[:-1]]

            current_pos = 0

            with open(input_file, "rb") as input_file:
                # Read the data from the FASTA file
                for s in schema:
                    print(s)
                    start = s[0]
                    end = s[1]
                    f.seek(current_pos)
                    data += f.read(start-current_pos)
                    f.seek(start)
                    data += decryptor.update(f.read(end-start))
                    current_pos = end + 1

            data += f.read()[1:]

        # Write the decrypted data to the output file
        with open(output_file, "wb") as output_file:
            output_file.write(data)

def generate_checksum(input_file):
    """Generates a checksum for a file using the SHA-256 hash function."""
    # Open the input file for reading
    with open(input_file, "rb") as f:
        # Read the data from the file
        data = f.read()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)

    # Calculate the SHA-256 hash of the data
    return digest.finalize()

def parse_args():
    # Create an ArgumentParser object
    parser = argparse.ArgumentParser()

    # Add an argument for the input file
    parser.add_argument("--input-file", required=True, help="the input file to encrypt or decrypt")

    # Add an argument for the output file
    parser.add_argument("--output-file", required=True, help="the output file to write the encrypted or decrypted data to")

    # Add an argument for the public key file (for encryption) or the private key file (for decryption)
    parser.add_argument("--public-key-file", required=False, help="the file containing the public key for encryption")
    parser.add_argument("--private-key-file", required=False, help="the file containing the private key for decryption")
    parser.add_argument("--key-file", required=False, help="the to output the key and checksum information")

    # Add an argument to specify whether to encrypt or decrypt the file
    parser.add_argument("-e", "--encrypt", action="store_true", help="encrypt the input file")
    parser.add_argument("-d", "--decrypt", action="store_true", help="decrypt the input file")

    # Add an argument to specify which mode to use
    parser.add_argument("-m", "--mode", required=True, help="mode to encrypt file (Not needed for decryption, if passed, argument is ignored)")

    # Parse the command-line arguments
    args = parser.parse_args()
    print(args)
    return args

def main():
    # Parse the command-line arguments
    args = parse_args()

    if args.encrypt:
        # Generate a random password
        password = generate_random_password()

        # Load the public key for the recipient
        with open(args.public_key_file, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read()
            )

        # Encrypt the password using the public key
        encrypted_password = encrypt_with_rsa(str.encode(password), public_key)

        # Encrypt the FASTA file
        salt, iterations, iv, schema = encrypt_secure_fasta(args.input_file, args.output_file, str.encode(password), args.mode)

        # Generate a checksum for the SecureFASTA file
        checksum = generate_checksum(args.output_file)
        encrypted_checksum = encrypt_with_rsa(checksum, public_key)

        # Write the encrypted password and checksum to a separate file
        with open(args.key_file, "wb") as f:
            f.write(salt)
            f.write(iterations.to_bytes(8,'big'))
            f.write(iv)
            f.write(encrypted_password)
            f.write(encrypted_checksum)
            f.write(schema.encode())

    elif args.decrypt:
        # Load the private key for the recipient
        with open(args.private_key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )

        # Load the encrypted password and checksum from the key file
        with open(args.key_file, "rb") as f:
            salt = f.read(16)
            iterations = int.from_bytes(f.read(8),'big')
            iv = f.read(16)
            encrypted_password = f.read(256)
            encrypted_checksum = f.read(256)
            schema = f.read().decode()

        # Decrypt the password using the private key
        password = decrypt_with_rsa(encrypted_password, private_key)
        checksum = decrypt_with_rsa(encrypted_checksum, private_key)

        # Validate the checksum
        if generate_checksum(args.input_file) != checksum:
            raise ValueError("Checksum validation failed")

        # Decrypt the SecureFASTA file
        decrypt_secure_fasta(args.input_file, args.output_file, password, salt, iterations, iv, args.mode, schema)

if __name__ == "__main__":
    main()