import random
import string

from Cryptodome.PublicKey import ECC

# Generate a random DNA or protein sequence
def generate_sequence(length):
    return "".join(random.choices("ACGT", k=length))

# Write a FASTA file
def write_fasta_file(filename, sequence):
    with open(filename, "w") as f:
        f.write(">Sequence\n")
        f.write(sequence)

# Generate three synthetic FASTA files
write_fasta_file("input1.fasta", generate_sequence(100))
write_fasta_file("input2.fasta", generate_sequence(1000))
write_fasta_file("input3.fasta", generate_sequence(10000))

# Generate a public/private key pair for ECC
private_key = ECC.generate(curve="P-256")
public_key = private_key.public_key()

# Save the public and private keys to files
with open("public_key.pem", "w") as f:
    f.write(public_key.export_key(format="PEM"))

with open("private_key.pem", "w") as f:
    f.write(private_key.export_key(format="PEM"))
