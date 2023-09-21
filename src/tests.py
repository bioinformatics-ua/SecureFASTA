from typing import List
import os
import pytest

STANDARD_ENC_CMD = "python3 main.py encrypt --input-file {input_file} --output-file {output_file} --public-key-file {public_key_file} --key-file {key_file} --mode {mode} --specification {specification} --file_type {file_type}"

STANDARD_DEC_CMD = "python3 main.py decrypt --input-file {input_file} --output-file {output_file} --private-key-file {private_key_file} --key-file {key_file}"

input_dir = "../data"
output_dir = "../test"
keys_dir = "../keys"

def generate_combinations_encryption() -> List[pytest.param]:

    files = ["fasta", "fastq", "vcf", "bam"]
    mode = "split"
    specifications = [("headers", "sequences", "all"), ("headers", "sequences", "noquality", "all"), ("headers", "sequences", "all"), ("")]

    combinations = []

    for idx, f in enumerate(files):
        for s in specifications[idx]:

            test_name = f + "_" + s
            os.system(f"mkdir {output_dir}/{test_name}")

            combinations.append((
                f"{input_dir}/input.{f}", f"{output_dir}/{test_name}/output.{s}.{f}.enc", f"{output_dir}/{test_name}/output.{s}.{f}.enc", f"{output_dir}/{test_name}/output.{s}.{f}",
                f"{keys_dir}/public_key.pem", f"{keys_dir}/private_key.pem", f"{output_dir}/{test_name}/key.{s}.{f}",
                mode, s, f
            )) 

    return combinations

def generate_combinations_compression() -> List[pytest.param]:

    files = ["fasta", "fastq", "vcf", "bam"]
    mode = "compression"

    combinations = []

    for f in files:
        test_name = f"compression_{f}"
        os.system(f"mkdir {output_dir}/{test_name}")

        combinations.append((
            f"{input_dir}/input.{f}", f"{output_dir}/{test_name}/output.{f}.co", f"{output_dir}/{test_name}/output.{f}.co", f"{output_dir}/{test_name}/output.{f}",
            f"{keys_dir}/public_key.pem", f"{keys_dir}/private_key.pem", f"{output_dir}/{test_name}/key.{f}",
            mode, f
        )) 

    return combinations

@pytest.mark.parametrize("input_file_enc, output_file_enc, input_file_dec, output_file_dec, public_key_file, private_key_file, key_file, mode, specification, file_type", generate_combinations_encryption())
def test_encryption(input_file_enc, output_file_enc, input_file_dec, output_file_dec, public_key_file, private_key_file, key_file, mode, specification, file_type):

    # Encrypt
    os.system(STANDARD_ENC_CMD.format(
                input_file=input_file_enc, output_file=output_file_enc, 
                public_key_file=public_key_file, key_file=key_file, 
                mode=mode, specification=specification, file_type=file_type))
    
    # Decrypt
    os.system(STANDARD_DEC_CMD.format(input_file=input_file_dec, output_file=output_file_dec, 
                private_key_file=private_key_file, key_file=key_file))

    # Load information
    input_information = open(input_file_enc, "rb").read()
    output_information = open(output_file_dec,"rb").read()

    # Ensure the information is the same
    assert input_information == output_information

@pytest.mark.parametrize("input_file_enc, output_file_enc, input_file_dec, output_file_dec, public_key_file, private_key_file, key_file, mode, file_type", generate_combinations_compression())
def test_compression_and_encryption(input_file_enc, output_file_enc, input_file_dec, output_file_dec, public_key_file, private_key_file, key_file, mode, file_type):

     # Encrypt
    os.system(STANDARD_ENC_CMD.format(
                input_file=input_file_enc, output_file=output_file_enc, 
                public_key_file=public_key_file, key_file=key_file, 
                mode=mode, specification= "fill", file_type=file_type))
    
    # Decrypt
    os.system(STANDARD_DEC_CMD.format(input_file=input_file_dec, output_file=output_file_dec, 
                private_key_file=private_key_file, key_file=key_file))

    # Load information
    input_information = open(input_file_enc, "rb").read()
    compressed_information = open(output_file_enc, "rb").read()
    output_information = open(output_file_dec,"rb").read()

    # Ensure the information is the same
    assert input_information == output_information
    assert len(compressed_information) <= len(input_information)