import os
import random
import string
import unittest

from main import generate_random_password
from main import encrypt_secure_fasta
from main import decrypt_secure_fasta
from main import generate_checksum
from main import encrypt_with_rsa

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

class TestSecureFASTA(unittest.TestCase):

    def test_generate_checksum(self):
        """Tests the generate_checksum method."""
        # Write a random DNA or protein sequence to a FASTA file
        with open("input.fasta", "w") as f:
            f.write(">Sequence\n")
            f.write("".join(random.choices("ACGT", k=1000)))

        # Generate a checksum for the FASTA file
        checksum = generate_checksum("input.fasta").hex()

        # Check that the checksum is a valid hexadecimal string
        self.assertTrue(all(c in string.hexdigits for c in checksum))

    def test_generate_random_password(self):
        """Tests the generate_random_password method."""
        # Set the length of the password
        length = 32

        # Generate a random password
        password = generate_random_password()

        # Check that the password has the correct length
        self.assertEqual(len(password), length)

        # Check that the password contains only letters and digits
        self.assertTrue(all(c in string.ascii_letters + string.digits for c in password))

    def test_encrypt_password(self):
        """Tests the encrypt_password method."""
        # Generate a random password
        password = "".join(random.choices(string.ascii_letters + string.digits, k=32))

        # Generate a public key
        private_key = RSA.generate(2048)
        public_key = private_key.public_key()

        # Encrypt the password
        encrypted_password = encrypt_with_rsa(str.encode(password), public_key)

        # Check that the encrypted password is different from the original password
        self.assertNotEqual(encrypted_password, password)

        # Decrypt the password
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_password = cipher_rsa.decrypt(encrypted_password).decode()

        # Check that the decrypted password is the same as the original password
        self.assertEqual(decrypted_password, password)

    def test_encrypt_secure_fasta(self):
        """Tests the encrypt_secure_fasta method."""
        # Generate a random password
        password = "".join(random.choices(string.ascii_letters + string.digits, k=32))

        # Write a random DNA or protein sequence to a FASTA file
        with open("input.fasta", "w") as f:
            f.write(">Sequence\n")
            f.write("".join(random.choices("ACGT", k=1000)))

        # Encrypt the FASTA file
        encrypt_secure_fasta("input.fasta", "secure_fasta.txt", password)

        # Check that the SecureFASTA file is different from the original FASTA file
        with open("input.fasta", "rb") as f1, open("secure_fasta.txt", "rb") as f2:
            self.assertNotEqual(f1.read(), f2.read())

    def test_decrypt_secure_fasta(self):
        """Tests the decrypt_secure_fasta method."""
        # Generate a random password
        password = "".join(random.choices(string.ascii_letters + string.digits, k=32))

        # Write a random DNA or protein sequence to a FASTA file
        with open("input.fasta", "w") as f:
            f.write(">Sequence\n")
            f.write("".join(random.choices("ACGT", k=1000)))

        # Encrypt the FASTA file
        encrypt_secure_fasta("input.fasta", "secure_fasta.txt", password)

        # Decrypt the SecureFASTA file
        decrypt_secure_fasta("secure_fasta.txt", "output.fasta", password)

        # Check that the decrypted FASTA file is the same as the original FASTA file
        with open("input.fasta", "r") as f1, open("output.fasta", "r") as f2:
            self.assertEqual(f1.read(), f2.read())

    def tearDown(self):
        # Delete the test files
        try:
            os.remove("input.fasta")
        except OSError:
            pass

        try:
            os.remove("secure_fasta.txt")
        except OSError:
            pass

        try:
            os.remove("output.fasta")
        except OSError:
            pass

if __name__ == "__main__":
    unittest.main()
