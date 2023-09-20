from typing import List
import os
import pytest

STANDARD_ENC_CMD = "python3 main.py encrypt --input-file {input_file} --output-file {output_file} --public-key-file {public_key_file} --key-file {key_file} --mode {mode} --specification {specification} --file_type {file_type}"

STANDARD_DEC_CMD = "python3 main.py decrypt --input-file {input_file} --output-file {output_file} --private-key-file {private_key_file} --key-file {key_file}"

def generate_combinations_encryption() -> List[pytest.param]:
    files = ["fasta", "fastq", "vcf", "bam"]
    mode = "split"
    specifications = [("headers", "sequence", "all"), ("headers", "sequence", "noquality", "all"), ("headers", "sequence", "all"), ("")]

    combinations = []

    for idx, f in enumerate(files):
        for s in specifications[idx]:
            combinations.append((
                "../data/input." + f, "../test/output."+ s +"."+ f +".enc", "../test/output."+ s +"."+ f +".enc", "../test/output."+ s +"."+ f,
                "../keys/public_key.pem", "../keys/private_key.pem", "../test/key."+ s +"."+ f,
                mode, s, f
            )) 

    return combinations

# combinations_encryption = [

#     # All fasta combinations
#     ("../data/input.fasta","../test/output.headers.fasta.enc", "../test/output.headers.fasta.enc", "../test/output.headers.fasta", "../keys/public_key.pem", "../keys/private_key.pem", "key.txt", "split", "headers", "fasta"),
#     ("../data/input.fasta","../test/output.sequences.fasta.enc", "../test/output.sequences.fasta.enc", "../test/output.sequence.fasta", "../keys/public_key.pem", "../keys/private_key.pem", "key.txt", "split", "sequence", "fasta"),
#     ("../data/input.fasta","../test/output.all.fasta.enc", "../test/output.fasta.enc", "../test/output.all.fasta", "../keys/public_key.pem", "../keys/private_key.pem", "key.txt", "split", "all", "fasta")

# ]

@pytest.mark.parametrize("input_file_enc, output_file_enc, input_file_dec, output_file_dec, public_key_file, private_key_file, key_file, mode, specification, file_type", generate_combinations_encryption())
def test(input_file_enc, output_file_enc, input_file_dec, output_file_dec, public_key_file, private_key_file, key_file, mode, specification, file_type):
    os.system(STANDARD_ENC_CMD.format(
                input_file=input_file_enc, output_file=output_file_enc, 
                public_key_file=public_key_file, key_file=key_file, 
                mode=mode, specification=specification, file_type=file_type))
    os.system(STANDARD_DEC_CMD.format(input_file=input_file_dec, output_file=output_file_dec, 
                private_key_file=private_key_file, key_file=key_file))

    input_information = open(input_file_enc, "rb").read()
    output_information = open(output_file_dec,"rb").read()

    assert input_information == output_information