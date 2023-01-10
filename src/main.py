import string
import argparse

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_random_password():
    """Generates a random password."""
    # Set the length of the password
    length = 32

    # Generate a random string of letters and digits
    return "".join(random.sample(string.ascii_letters + string.digits, length))

def encrypt_with_rsa(word, public_key):
    """Encrypts a password using ECC with a public key."""
    # Encrypt the password using the public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(word)

def decrypt_with_rsa(encrypted_word, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_word)

def encrypt_secure_fasta(input_file, output_file, password):
    """Encrypts a FASTA file and writes the result to a SecureFASTA file."""
    # Set the salt and number of iterations for the PBKDF2 key derivation function
    salt = get_random_bytes(16)
    iterations = 10000

    # Use PBKDF2 to derive a key from the password
    key = PBKDF2(password, salt, dkLen=32, count=iterations,hmac_hash_module=SHA256)

    # Initialize the AES cipher in cipher block chaining (OFB) mode
    cipher = AES.new(key, AES.MODE_CBC)

    # Get the initialisation vector (IV) for the cipher
    iv = cipher.iv

    # Read the DNA or protein sequence data from the input file
    with open(input_file, "rb") as input_file:
        # Read the data from the FASTA file
        data = input_file.read()

        # Encrypt the data using the AES cipher
        encrypted_data = cipher.encrypt(pad(data, 16))

    # Open the output file for writing
    with open(output_file, "wb") as f:
        # Write the salt, iterations, and IV to the file
        f.write(salt)
        f.write(iterations.to_bytes(8,'big'))
        f.write(iv)

        # Write the encrypted data to the SecureFASTA file
        f.write(encrypted_data)

def decrypt_secure_fasta(input_file, output_file, password):
    """Decrypts a SecureFASTA file and writes the result to a FASTA file."""
    # Open the input file for reading
    with open(input_file, "rb") as f:
        # Read the salt, iterations, and IV from the file
        salt = f.read(16)
        iterations = int.from_bytes(f.read(8),'big')
        iv = f.read(16)

        # Use PBKDF2 to derive a key from the password
        key = PBKDF2(password, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)

        # Initialize the AES cipher in cipher block chaining (CBC) mode
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Read the encrypted data from the SecureFASTA file
        encrypted_data = f.read()

        # Decrypt the data using the AES cipher
        data = unpad(cipher.decrypt(encrypted_data),16)

        # Write the decrypted data to the output file
        with open(output_file, "wb") as output_file:
            output_file.write(data)

def generate_checksum(input_file):
    """Generates a checksum for a file using the SHA-256 hash function."""
    # Open the input file for reading
    with open(input_file, "rb") as f:
        # Read the data from the file
        data = f.read()

    # Calculate the SHA-256 hash of the data
    return SHA256.new(data).digest()

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
        with open(args.public_key_file, "rb") as f:
            public_key = RSA.importKey(f.read())

        # Encrypt the password using the public key
        encrypted_password = encrypt_with_rsa(str.encode(password), public_key)

        # Encrypt the FASTA file
        encrypt_secure_fasta(args.input_file, args.output_file, password)

        # Generate a checksum for the SecureFASTA file
        checksum = generate_checksum(args.output_file)
        encrypted_checksum = encrypt_with_rsa(checksum,public_key)

        # Write the encrypted password and checksum to a separate file
        with open(args.key_file, "wb") as f:
            f.write(encrypted_password)
            f.write(encrypted_checksum)

    elif args.decrypt:
        # Load the private key for the recipient
        with open(args.private_key_file, "rb") as f:
            private_key = RSA.importKey(f.read())

        # Load the encrypted password and checksum from the key file
        with open(args.key_file, "rb") as f:
            encrypted_password = f.read(256)
            encrypted_checksum = f.read(256)

        # Decrypt the password using the private key
        password = decrypt_with_rsa(encrypted_password, private_key)
        checksum = decrypt_with_rsa(encrypted_checksum, private_key)

        # Validate the checksum
        if generate_checksum(args.input_file) != checksum:
            raise ValueError("Checksum validation failed")

        # Decrypt the SecureFASTA file
        decrypt_secure_fasta(args.input_file, args.output_file, password)

if __name__ == "__main__":
    main()