import os
import gzip
import uuid
import secrets
import argparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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
        Derives a 32 length key from a given password (bytes), also returns a salt randomly generated
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
        Writes encrypted information to a file and return a string with the starting position and finishing position of the now encrypted information
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
    return public_key.encrypt(
        word,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
def decrypt_with_rsa(encrypted_word, private_key):
    """
        Decrypts a password with a RSA private key.
    """
    return private_key.decrypt(
        encrypted_word,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def gzip_compress(input_file, output_file):
    """
        Compresses a file using gzip
    """

    data = open(input_file,"rb").read()
    bindata = bytearray(data)

    with gzip.open(output_file, "wb") as compressed:
        compressed.write(bindata)

def gzip_uncompress(input_file, output_file):
    """
        Decompresses a file using gzip
    """

    output = open(output_file,"wb")

    with gzip.open(input_file, "rb") as compressed:
        bindata = compressed.read()

    output.write(bindata)
    output.close()

def compress_and_encrypt(input_file, output_file, key):
    """
        Compresses and fully encrypts a genomic file using gzip
    """

    schema = ""
    tmp_file = str(uuid.uuid4()) + ".co"

    gzip_compress(input_file, tmp_file)

    iv, encryptor, output_file, after_compression_file = setup_encryption(key, tmp_file, output_file)

    schema += write_and_get_schema(output_file, after_compression_file.read(), encryptor) 
    
    # Finish
    output_file.close()

    # Remove temporary file
    os.remove(tmp_file)
        
    return iv, schema

def decrypt_and_uncompress(input_file, output_file, key, iv, schema):
    """
        Decrypts and uncompresses a genomic file using gzip
    """

    tmp_file = str(uuid.uuid4()) + ".co"
    decrypt(input_file, tmp_file, key, iv, schema)

    gzip_uncompress(tmp_file, output_file)

    # Remove temporary file
    os.remove(tmp_file)


def get_encryption_function(file_type):
    """
        Returns the correct encryption function based on file type.
    """
    map = {
        "fasta": encrypt_secure_fasta,
        "fastq": encrypt_secure_fastq,
        "vcf": encrypt_secure_vcf,
        "bam": encrypt_secure_bam
    }

    return map[file_type]

def setup_encryption(key, input_file, output_file):
    """
        Initializes encryption variables that are common to all encryption function.
    """
    # Generate random iv
    iv = os.urandom(16)

    # Initialize the AES cipher in cipher block chaining (OFB) mode
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    encryptor = cipher.encryptor()

    output_file = open(output_file, "wb")
    input_file = open(input_file, "rb")

    return iv, encryptor, output_file, input_file

def encrypt_headers(input_file, output_file, schema, encryptor, markers):
    """
        Encrypts lines which start in a specific way (headers) while leaving the rest as clear text.
    """
    for line in input_file:

            # Checks if line starts with any of the markers that indicates an header
            if line[0] in markers:
                output_file.write(chr(line[0]).encode())
                schema += write_and_get_schema(output_file, line[1:], encryptor)
                output_file.write(b"\n")

            else:
                output_file.write(line)

    return schema

def encrypt_without_markers(input_file, output_file, schema, encryptor, markers):
    """
        Encrypts lines that do not start with header information. This is done by buffering information adn writting the buffers data when a header line is found.
    """
    buffer = bytes()
        
    for line in input_file:

        # If line starts with a header marker, write all previous information stored (sequences)
        if line[0] in markers:
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

    return schema

def encrypt_with_counter(input_file, output_file, schema, encryptor, c):
    """
        Encrypts every line expect for the "c" line in each sequence. Works in similar fashion to the other function but compares the line number for each sequence.
    """
    buffer = bytes()
    counter = 1
        
    for line in input_file:

        # If line starts with ">", write all previous information stored (sequences)
        if counter % c == 0:
            if buffer != bytes():
                schema += write_and_get_schema(output_file, buffer, encryptor)
                output_file.write(b"\n")
                buffer = bytes()
            output_file.write(line)

        else:
            # Buffer information until all the sequence is retreived
            buffer += line

        counter += 1

    # Write the last sequence
    schema += write_and_get_schema(output_file, buffer, encryptor)

    return schema

def encrypt_secure_fastq(input_file, output_file, key, mode):
    """
        Encrypts a fastq file.
    """

    # Setup
    schema = ""
    iv, encryptor, output_file, input_file = setup_encryption(key, input_file, output_file)

    markers = [64, 43]

    if mode == "headers":
        schema = encrypt_headers(input_file, output_file, schema, encryptor, markers)

    elif mode == "sequences":
        schema = encrypt_without_markers(input_file, output_file, schema, encryptor, markers)
    
    elif mode == "noquality":
        schema = encrypt_with_counter(input_file, output_file, schema, encryptor, 4)

    else:
        schema += write_and_get_schema(output_file, input_file.read(), encryptor) 
    
    # Finish
    output_file.close()
    input_file.close()

    return iv, schema


def encrypt_secure_bam(input_file, output_file, key, mode):
    """
        Encrypts a bam file.
    """
    # Setup
    schema = ""
    iv, encryptor, output_file, input_file = setup_encryption(key, input_file, output_file)

    schema += write_and_get_schema(output_file, input_file.read(), encryptor) 
    
    # Finish
    output_file.close()
    input_file.close()

    return iv, schema

def encrypt_secure_vcf(input_file, output_file, key, mode):
    """
        Encrypts a vcf file.
    """

    # Setup
    schema = ""
    iv, encryptor, output_file, input_file = setup_encryption(key, input_file, output_file)

    markers = [35]

    if mode == "headers":
        schema = encrypt_headers(input_file, output_file, schema, encryptor, markers)

    elif mode == "sequences":
        schema = encrypt_without_markers(input_file, output_file, schema, encryptor, markers)
    
    else:
        schema += write_and_get_schema(output_file, input_file.read(), encryptor) 
    
    # Finish
    output_file.close()
    input_file.close()

    return iv, schema

def encrypt_secure_fasta(input_file, output_file, key, mode):
    """
        Encrypts a fasta file.
    """

    # Setup
    schema = ""
    iv, encryptor, output_file, input_file = setup_encryption(key, input_file, output_file)

    markers = [62]

    if mode == "headers":
        schema = encrypt_headers(input_file, output_file, schema, encryptor, markers)

    elif mode == "sequences":
        schema = encrypt_without_markers(input_file, output_file, schema, encryptor, markers)
    
    else:
        schema += write_and_get_schema(output_file, input_file.read(), encryptor) 
    
    # Finish
    output_file.close()
    input_file.close()

    return iv, schema

def decrypt(input_file, output_file, key, iv, schema):
    """
        Decrypts a file encrypted using this tool. The schema obtained dictated where encrypted information is located and only that information is decrypted.
    """
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
    """
        Generates a checksum for a file using the SHA-256 hash function.
    """
    with open(input_file, "rb") as f:
        data = f.read()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)

    # Calculate the SHA-256 hash of the data
    return digest.finalize()

def parse_args():
    # Create an ArgumentParser object
    parser = argparse.ArgumentParser(description="Encryption and decryption of genomic files")
    
    # Create a subparser to handle encryption and decryption commands
    subparsers = parser.add_subparsers(title="subcommands", help="Different commands", dest="command")

    # Create encryption subparser
    encryption_subparser = subparsers.add_parser("encrypt", help="Encrypt genomic files")

    encryption_subparser.add_argument("--input-file", required=True, help="The input file to encrypt or decrypt")
    encryption_subparser.add_argument("--output-file", required=True, help="The output file to write the encrypted or decrypted data to")

    encryption_subparser.add_argument("--public-key-file", required=False, help="The file containing the public key for encryption")
    encryption_subparser.add_argument("--key-file", required=False, help="The to output the key and checksum information")

    encryption_subparser.add_argument("-m", "--mode", required=False, help="Select either compression mode (compresses the file and encrypts its contents) or split mode (which allows for the encryption of different parts of each file)")
    encryption_subparser.add_argument("-f", "--file_type", required=False, help="Select the file type the tool will apply (fasta, fastq, vcf, bam)")
    encryption_subparser.add_argument("-s", "--specification", required=False, help="Select the specification for the encryption/decryption")

    # Create decryption subparser
    decryption_subparser = subparsers.add_parser("decrypt", help="Decrypt genomic files")

    decryption_subparser.add_argument("--input-file", required=True, help="The input file to encrypt or decrypt")
    decryption_subparser.add_argument("--output-file", required=True, help="The output file to write the encrypted or decrypted data to")

    decryption_subparser.add_argument("--key-file", required=False, help="The to output the key and checksum information")
    decryption_subparser.add_argument("--private-key-file", required=False, help="The file containing the private key for decryption")

    # Parse the command-line arguments
    args = parser.parse_args()
    return args

def main():
    # Parse the command-line arguments
    args = parse_args()

    print(args)
    
    if args.command == "encrypt":
        # Generate a random password
        password = generate_random_password()

        # Load the public key for the recipient
        with open(args.public_key_file, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read()
            )
        # Derive key from random string
        _, key = derive_key(str.encode(password), ITERATIONS)

        if args.mode == "compression":
            iv, schema = compress_and_encrypt(args.input_file, args.output_file, key)

        elif args.mode == "split":
            encryption_function = get_encryption_function(args.file_type)
            iv, schema = encryption_function(args.input_file, args.output_file, key, args.specification)

        # Encrypt the key using the public key
        encrypted_key = encrypt_with_rsa(key, public_key)

        # Generate a checksum for the SecureFASTA file
        checksum = generate_checksum(args.output_file)
        encrypted_checksum = encrypt_with_rsa(checksum, public_key)

        # Encrypt filetype and mode
        encrypted_filetype = encrypt_with_rsa(args.file_type.encode(), public_key)
        encrypted_mode = encrypt_with_rsa(args.mode.encode(), public_key)

        # Write the encrypted key, checksum, filetype and mode to a separate file, along with the iv and schema of encryption
        with open(args.key_file, "wb") as f:
            f.write(iv)
            f.write(encrypted_key)
            f.write(encrypted_checksum)
            f.write(encrypted_filetype)
            f.write(encrypted_mode)
            f.write(schema.encode())

    else:
        # Load the private key for the recipient
        with open(args.private_key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )

        # Load the encrypted key, checksum, filetype and mode from the key file, along with the iv and schema
        with open(args.key_file, "rb") as f:
            iv = f.read(16)
            encrypted_key = f.read(256)
            encrypted_checksum = f.read(256)
            encrypted_filetype = f.read(256)
            encrypted_mode = f.read(256)
            schema = f.read().decode()

        # Decrypt the information using the private key
        key = decrypt_with_rsa(encrypted_key, private_key)
        checksum = decrypt_with_rsa(encrypted_checksum, private_key)
        file_type = decrypt_with_rsa(encrypted_filetype, private_key).decode()
        mode = decrypt_with_rsa(encrypted_mode, private_key).decode()

        # Validate the checksum
        if generate_checksum(args.input_file) != checksum:
            raise ValueError("Checksum validation failed")

        if mode == "compression":
            decrypt_and_uncompress(args.input_file, args.output_file, key, iv, schema)

        elif mode == "split":
            decrypt(args.input_file, args.output_file, key, iv, schema)

if __name__ == "__main__":
    main()
