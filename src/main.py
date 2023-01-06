import argparse
import hashlib
import os
import random
import string
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.PublicKey import ECC


def generate_random_password():
    """Generates a random password."""
    # Set the length of the password
    length = 32

    # Generate a random string of letters and digits
    password = "".join(random.choices(string.ascii_letters + string.digits, k=length))

    return password

def encrypt_password(password, public_key):
    """Encrypts a password using ECC with a public key."""
    # Encrypt the password using the public key
    encrypted_password = public_key.encrypt(password, 32)[0]

    return encrypted_password

def encrypt_secure_fasta(input_file, output_file, password):
    """Encrypts a FASTA file and writes the result to a SecureFASTA file."""
    # Set the salt and number of iterations for the PBKDF2 key derivation function
    salt = os.urandom(8)
    iterations = 10000

    # Use PBKDF2 to derive a key from the password
    key = PBKDF2(password, salt, dkLen=32, count=iterations)

    # Initialize the AES cipher in cipher block chaining (CBC) mode
    cipher = AES.new(key, AES.MODE_CBC)

    # Set the initialisation vector (IV) for the cipher
    iv = cipher.iv

    # Open the output file for writing
    with open(output_file, "w") as f:
        # Write the salt, iterations, and IV to the file
        f.write(salt)
        f.write(iterations)
        f.write(iv)

        # Read the DNA or protein sequence data from the input file
        with open(input_file, "r") as input_file:
            # Read the data from the FASTA file
            data = input_file.read()

            # Encrypt the data using the AES cipher
            encrypted_data = cipher.encrypt(data)

            # Write the encrypted data to the SecureFASTA file
            f.write(encrypted_data)

def decrypt_secure_fasta(input_file, output_file, password):
    """Decrypts a SecureFASTA file and writes the result to a FASTA file."""
    # Open the input file for reading
    with open(input_file, "r") as f:
        # Read the salt, iterations, and IV from the file
        salt = f.read(8)
        iterations = f.read(4)
        iv = f.read(16)

        # Use PBKDF2 to derive a key from the password
        key = PBKDF2(password, salt, dkLen=32, count=iterations)

        # Initialize the AES cipher in cipher block chaining (CBC) mode
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Read the encrypted data from the SecureFASTA file
        encrypted_data = f.read()

        # Decrypt the data using the AES cipher
        data = cipher.decrypt(encrypted_data)

        # Write the decrypted data to the output file
        with open(output_file, "w") as output_file:
            output_file.write(data)

def generate_checksum(input_file):
    """Generates a checksum for a file using the SHA-256 hash function."""
    # Open the input file for reading
    with open(input_file, "rb") as f:
        # Read the data from the file
        data = f.read()

        # Calculate the SHA-256 hash of the data
        checksum = hashlib.sha256(data).hexdigest()

        return checksum

def parse_args():
    # Create an ArgumentParser object
    parser = argparse.ArgumentParser()

    # Add an argument for the input file
    parser.add_argument("--input-file", required=True, help="the input file to encrypt or decrypt")

    # Add an argument for the output file
    parser.add_argument("--output-file", required=True, help="the output file to write the encrypted or decrypted data to")

    # Add an argument for the public key file (for encryption) or the private key file (for decryption)
    parser.add_argument("--public-key-file", required=False, help="the file containing the public key for encryption")
    parser.add_argument("--key-file", required=False, help="the file containing the private key for decryption")

    # Add an argument to specify whether to encrypt or decrypt the file
    parser.add_argument("-e", "--encrypt", action="store_true", help="encrypt the input file")
    parser.add_argument("-d", "--decrypt", action="store_true", help="decrypt the input file")

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
        with open(args.public_key_file, "r") as f:
            public_key_data = f.read()
        public_key = ECC.import_key(public_key_data)

        # Encrypt the password using the public key
        encrypted_password = encrypt_password(password, public_key)

        # Encrypt the FASTA file
        encrypt_secure_fasta(args.input_file, args.output_file, password)

        # Generate a checksum for the SecureFASTA file
        checksum = generate_checksum(args.output_file)

        # Write the encrypted password and checksum to a separate file
        with open(args.key_file, "w") as f:
            f.write(encrypted_password)
            f.write(checksum)

    elif args.decrypt:
        # Load the private key for the recipient
        with open(args.private_key_file, "r") as f:
            private_key_data = f.read()
        private_key = ECC.import_key(private_key_data)

        # Load the encrypted password and checksum from the key file
        with open(args.key_file, "r") as f:
            encrypted_password = f.read(64)
            checksum = f.read(64)

        # Decrypt the password using the private key
        password = private_key.decrypt(encrypted_password)

        # Validate the checksum
        if generate_checksum(args.input_file) != checksum:
            raise ValueError("Checksum validation failed")

        # Decrypt the SecureFASTA file
        decrypt_secure_fasta(args.input_file, args.output_file, password)

if __name__ == "__main__":
    main()