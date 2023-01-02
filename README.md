# SecureFASTA

SecureFASTA is a Python script that allows you to encrypt and decrypt FASTA files using AES encryption and Elliptic Curve Cryptography (ECC).

## Team
  
  * João R. Almeida<sup id="a1">[1](#f1)</sup><sup id="a2">[2](#f2)</sup>
  * Jorge M. Silva<sup id="a1">[1](#f1)</sup>

1. <small id="f1"> University of Aveiro, Dept. Electronics, Telecommunications and Informatics (DETI / IEETA), Aveiro, Portugal </small> [↩](#a1)
2. <small id="f2"> University of A Coruña, Dept. of Information and Communications Technologies, A Coruña, Spain </small> [↩](#a2)


## Features

- Encrypts FASTA files using AES encryption and a password derived from PBKDF2 key derivation function
- Encrypts the password using ECC with a public and private key
- Writes the encrypted password and checksum to a separate file
- Decrypts SecureFASTA files using the private key and validates the checksum before decryption

## Requirements

- Python 3.6 or higher
- Cryptodome (https://pypi.org/project/pycryptodome/)

## Usage

To encrypt a FASTA file:

```
$ cd src/
$ python main.py --encrypt --input-file input.fasta --output-file secure_fasta.txt --public-key-file public_key.pem --key-file key.txt
```

To decrypt a SecureFASTA file:

```
$ cd src/
$ python main.py --decrypt --input-file secure_fasta.txt --output-file output.fasta --private-key-file private_key.pem --key-file key.txt
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
