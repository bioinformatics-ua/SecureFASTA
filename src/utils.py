import random
import string
import os

from Crypto.PublicKey import RSA

# Generate a random DNA or protein sequence
def generate_sequence(length):
    return "".join(random.choices("ACGT", k=length))

# Write a FASTA file
def write_fasta_file(filename, sequence):
    with open(filename, "w") as f:
        f.write(">Sequence\n")
        f.write(sequence)
def main():
    # Create the `data` folder if it doesn't already exist
    if not os.path.exists("../data"):
        os.makedirs("../data")

    # Generate three synthetic FASTA files and save them in the `data` folder
    write_fasta_file("../data/input1.fasta", generate_sequence(100))
    write_fasta_file("../data/input2.fasta", generate_sequence(1000))
    write_fasta_file("../data/input3.fasta", generate_sequence(10000))

    # Create the `keys` folder if it doesn't already exist
    if not os.path.exists("../keys"):
        os.makedirs("../keys")

    # Generate a public/private key pair for ECC
    private_key = RSA.generate(2048)
    public_key = private_key.public_key()

    # Save the public and private keys to files in the `keys` folder
    with open("../keys/public_key.pem", "wb") as f:
        f.write(public_key.export_key(format="PEM"))

    with open("../keys/private_key.pem", "wb") as f:
        f.write(private_key.export_key(format="PEM"))

if __name__ == "__main__":
    main()