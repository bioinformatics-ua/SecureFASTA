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

ITERATIONS = 100000

def generate_random_password():
    """
        Generates a random password.
    """
    # Set the length of the password
    password_length = 32

    # Generate a random string of letters and digits
    return secrets.token_urlsafe(password_length)

def derive_key(password, iterations, salt=None):
    """
        Derives a 32 length key from a given password (bytes), returns the salt randomly generated
    """
    # Use PBKDF2 to derive a key from the password

    if not salt:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )

    return salt, kdf.derive(password)

def write_and_get_schema(file, information, encryptor):
    """
        Write information to a file and return a string with the starting position and finishing position of the now encrypted information
    """

    start = file.tell()
    file.write(encryptor.update(information))
    finish = file.tell()

    return f"{start}:{finish};"

def encrypt_with_rsa(word, public_key):
    """
        Encrypts a password with a RSA public key.
    """
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
    """
        Decrypts a password with a RSA private key.
    """
    plaintext = private_key.decrypt(
        encrypted_word,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def encrypt_secure_fasta(input_file, output_file, key, mode):
    """Encrypts a FASTA file and writes the result to a SecureFASTA file."""

    # Generate random iv
    iv = os.urandom(16)

    # Initialize the AES cipher in cipher block chaining (OFB) mode
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    encryptor = cipher.encryptor()

    schema = ""

    output_file = open(output_file, "wb")
    input_file = open(input_file, "rb")

    if mode == "headers":

        for line in input_file:

            # If line starts with ">" (header)
            if line[0] == 62:
                output_file.write(b">")
                schema += write_and_get_schema(output_file, line[1:], encryptor)
                output_file.write(b"\n")
            else:
                output_file.write(line)

    elif mode == "sequences":
        buffer = bytes()
        
        for line in input_file:

            # If line starts with ">", write all previous information stored (sequences)
            if line[0] == 62:
                if buffer != bytes():
                    schema += write_and_get_schema(output_file, buffer, encryptor)
                    output_file.write(b"\n")
                    buffer = bytes()
                output_file.write(line)
            else:
                # Buffer information until all the sequence is retreived
                buffer += line

        # Write the last sequence
        schema += write_and_get_schema(output_file, buffer, encryptor) 
    
    else:
        
        schema += write_and_get_schema(output_file, input_file.read(), encryptor) 
    
    output_file.close()
    input_file.close()

    return iv, schema

def decrypt_secure_fasta(input_file, output_file, key, iv, schema):
    """Decrypts a SecureFASTA file and writes the result to a FASTA file."""
    # Initialize the AES cipher in cipher block chaining (OFB) mode
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    decryptor = cipher.decryptor()

    output_file = open(output_file, "wb")
    input_file = open(input_file, "rb")

    # Mapping the schema to tuple values of start and finish of encryption parts
    schema = [tuple(map(int, s.split(":"))) for s in schema.split(";")[:-1]]

    current_pos = 0

    # Read information and decrypt acording to schema
    for start, end in schema:
        # Read information from the current position until the start of a new block of encrypted data
        input_file.seek(current_pos)
        output_file.write(input_file.read(start - current_pos))

        # Read information from the start of a encrypted block and decrypt it
        input_file.seek(start)
        output_file.write(decryptor.update(input_file.read(end - start)))
        current_pos = end + 1

    # Read and write whatever is left from the file as not encrypted information
    output_file.write(input_file.read()[1:])

    output_file.close()
    input_file.close()


def generate_checksum(input_file):
    """Generates a checksum for a file using the SHA-256 hash function."""
    with open(input_file, "rb") as f:
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
    parser.add_argument("-m", "--mode", required=False, help="mode to encrypt file (Not needed for decryption, if passed, argument is ignored)")

    # Parse the command-line arguments
    args = parser.parse_args()
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
        # Derive key from random string
        _, key = derive_key(str.encode(password), ITERATIONS)

        # Encrypt the FASTA file
        iv, schema = encrypt_secure_fasta(args.input_file, args.output_file, key, args.mode)

        # Encrypt the key using the public key
        encrypted_key = encrypt_with_rsa(key, public_key)

        # Generate a checksum for the SecureFASTA file
        checksum = generate_checksum(args.output_file)
        encrypted_checksum = encrypt_with_rsa(checksum, public_key)

        # Write the encrypted key and checksum to a separate file, along with the iv and schema of encryption
        with open(args.key_file, "wb") as f:
            f.write(iv)
            f.write(encrypted_key)
            f.write(encrypted_checksum)
            f.write(schema.encode())

    elif args.decrypt:
        # Load the private key for the recipient
        with open(args.private_key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )

        # Load the encrypted key and checksum from the key file
        with open(args.key_file, "rb") as f:
            iv = f.read(16)
            encrypted_key = f.read(256)
            encrypted_checksum = f.read(256)
            schema = f.read().decode()

        # Decrypt the key using the private key
        key = decrypt_with_rsa(encrypted_key, private_key)
        checksum = decrypt_with_rsa(encrypted_checksum, private_key)

        # Validate the checksum
        if generate_checksum(args.input_file) != checksum:
            raise ValueError("Checksum validation failed")

        # Decrypt the SecureFASTA file
        decrypt_secure_fasta(args.input_file, args.output_file, key, iv, schema)

if __name__ == "__main__":
    main()