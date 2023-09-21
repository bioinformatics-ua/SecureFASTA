<h1 align="center"><img src="logo/SecureFasta.png"
alt="securefasta" height="200" border="0" /></h1>
<p align="center"><b>The FASTA Security toolkit</b></p>


SecureFASTA is a Python tool that allows you to encrypt and decrypt Fasta, Fastq, Bam and VCF files using AES encryption and RSA Cryptography.

## Team
  * Dinis B. Cruz <sup id="a1">[1](#f1)</sup>
  * João R. Almeida<sup id="a1">[1](#f1)</sup><sup id="a2">[2](#f2)</sup>
  * Jorge M. Silva<sup id="a1">[1](#f1)</sup>
  * José L. Oliveira<sup id="a1">[1](#f1)</sup>

1. <small id="f1"> University of Aveiro, Dept. Electronics, Telecommunications and Informatics (DETI / IEETA), Aveiro, Portugal </small> [↩](#a1)
2. <small id="f2"> University of A Coruña, Dept. of Information and Communications Technologies, A Coruña, Spain </small> [↩](#a2)


## Function
<h1 align="left"><img src="logo/securefastaWorkflow.svg"
alt="securefasta" height="400" border="0" /></h1>

## How it works

- There exists 2 modes for encryption: `compression` and `split`
  - The first allows for the compression of the file using gzip and later full encryption of the information.
  - The second allows for the partial encryption of information from genomic files based on the file type.
- Encryption and decryption is performed using a PGP strategy where the key of symmetric encryption is stored in a separate file ciphered with the public key of the receiver.
- The key file contains further information for decryption. This information includes:
  - Ciphered checksum for integrity validation
  - Ciphered filetype for which is not currently used but can be necessary if other compression methods bcome available
  - Ciphered mode for decryption since the solution must know if it must decompress the information after decryption
  - The iv used for encryption (This information can be public)
  - The schema of encryption. This tells the tool where ciphered fields can be found (This information can also be public)

## Requirements

- Python 3.6 or higher
- Requirements in requirements.txt
- Requirements in requirements-test.txt if testing is performed

## Usage

The script has 2 commands: `encrypt` or `decrypt` which are self explanatory

### Flags available

- `input-file`: The file to be encrypted or decrypted
- `output-file`: The file to place information (encrypted or decrypted)
- `key-file`: The file to place the key, checksum, schema, mode and iv information
- `public-key-file`: Public key of the receiver of information for RSA encryption (only needed in encryption)
- `private-key-file`: Private key of the receiver of information for RSA decryption (only needed in decryption)
- `mode`: Mode of exeuction for the tool. `compression` compresses the file and encrypts it, `split` only encrypts the file but allows for customization on which information to be ciphered (Only needed for encryption).
- `specification`: Only useful for `split` mode. Allows for the specification of which information is to be ciphered (only needed for encryption).
- `file-type`:  Indicates which type of file is going to be encrypted (Fasta, Fastq, VCF or Bam) (onluneeded for encryption).

### Specifications Available

| File  | Headers only  |  Sequences |  Sequences w/o Quality Scores | All |
|---|---|---|---|---|
| Fasta  | ✅  |  ✅  | - | ✅   |
| Fastq  |  ✅  |  ✅  | ✅   | ✅   |
| VCF  |  ✅  |  ✅  | - |  ✅  |
| Bam | - | - | - | ✅  |

### Example of execution

Encryption of only the headers of a fasta file:

```
$ cd src/
$ python3 main.py encrypt \
          --input-file ../data/input.fasta \
          --output-file ../output/fasta.enc \
          --public-key-file ../keys/public_key.pem \
          --key-file ../output/key.bin \
          --mode split \
          --specification headers \
          --file_type fasta
```

Decryption of the same file:

```
$ cd src/
$ python3 main.py decrypt \
          --input-file ../output/fasta.enc \
          --output-file ../output/output.fasta \
          --private-key-file ../keys/private_key.pem \
          --key-file ../output/key.bin
```

### Run with Docker 

To encrypt (Same example as above):

```
docker run \
      -v ${PWD}/data:/data \
      -v ${PWD}/output:/output \
      -v ${PWD}/keys:/keys \
      <image_name> encrypt \
      --input-file /data/input.fasta \
      --output-file /output/fasta.enc  \
      --public-key-file /keys/public_key.pem \
      --key-file /output/key.bin \
      --mode split \
      --specification headers \
      --file_type fasta
```

To decrypt:

```
docker run \
    -v ${PWD}/data:/data \
    -v ${PWD}/output:/output \
    -v ${PWD}/keys:/keys \
    something decrypt \
    --input-file /output/fasta.enc \
    --output-file /output/output.fasta  \
    --private-key-file /keys/private_key.pem \
    --key-file /output/key.bin
```

### Testing

The test with perform all possible combinations of mode, specification and filetype available. The before and after files are compared for equality and the intermediate files can be inspected visually. 

Note: Create a test directory for this example to ensure it works. This also helps with the organization as many forders and files will be created.

```
$ cd src/
$ pytest tests.py
```

## Cite

Please cite the following, if you use SecureFASTA in your work:

```bib
todo
```

More details available [here](https://github.com/bioinformatics-ua/SecureFASTA/wiki).

## Issues
Please let us know if there are any
[issues](https://github.com/bioinformatics-ua/SecureFASTA/issues).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
