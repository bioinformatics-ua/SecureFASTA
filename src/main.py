import hashlib
import os
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2

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

def main(args):
    if args.encrypt:
        # Encrypt a FASTA file
        encrypt_secure_fasta(args.input_file, args.output_file, args.password)
    elif args.decrypt:
        # Decrypt a SecureFASTA file
        decrypt_secure_fasta(args.input_file, args.output_file, args.password)
    elif args.checksum:
        # Generate a checksum for a file
        checksum = generate_checksum(args.input_file)
        print(f"Checksum: {checksum}")