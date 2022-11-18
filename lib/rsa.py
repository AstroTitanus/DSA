"""Class that handles simple RSA encryption

Helpful resources:
https://www.comparitech.com/blog/information-security/rsa-encryption/ (understanding rsa)
https://www.zditect.com/guide/python/mod-inverse-python.html (mod inverse)
"""

from numpy import lcm as calc_lcm
from lib.primes import random_prime
import lib.helper as h
from os import path, getcwd

class RSA():
    
    def __init__(self, prime_len = 21):
        """Constructor for RSA class.

        Args:
            prime_len (int, optional): length of generated primes, must be 5 or more. Defaults to 21.
        """

        self.errors = []
        if prime_len < 4:
            self.errors.append("Length of the generated prime must be 5 or more")
            return

        self.prime_len = prime_len
        self.primes = self.__primes()
        self.public_key = self.__public_key()
        self.private_key = self.__private_key()

    
    def __primes(self):
        """Generates two random prime numbers for rsa cipher

        Returns:
            dict: dict with keys 'p', 'q' and vals of the prime numbers
        """

        primes = {}
        primes['p'] = random_prime(self.prime_len)
        primes['q'] = random_prime(self.prime_len)

        return primes
    

    def __public_key(self):
        """Generates the public key values 'n' and 'e'

        Returns:
            touple: public key values
        """

        p = self.primes['p']
        q = self.primes['q']

        # n - first part of the public key
        prime_multiple = p*q

        # Carmichaels totient
        lcm = calc_lcm(p-1, q-1)
        
        # Generating e - second part of the public key
        if len(str(lcm)) <= 5:
            e = h.find_indivisible_to(len(str(lcm)) - 1, lcm)
        else:
            e = h.find_indivisible_to(5, lcm)

        # Sanity check
        assert h.gcd(e, lcm) == 1

        return (prime_multiple, e)


    def __private_key(self):
        """Generates the private key values 'n' and 'd'

        Returns:
            touple: private key values
        """

        p = self.primes['p']
        q = self.primes['q']

        # n - first part of the private key
        prime_multiple = p*q

        # Inverse modulo - second part of the private key
        d = pow(self.public_key[1], -1, int(calc_lcm(p-1, q-1)))

        return (prime_multiple, d)
    

    def generate_key_files(self, save_folder_path=''):
        """Generates two files with private and public RSA key

        Args:
            save_folder_path (str): Folder path where to save the files. Defaults to cwd.
        """

        if not save_folder_path:
            save_folder_path = getcwd()

        # Check if path is folder
        if not path.isdir(path.abspath(save_folder_path)):
            self.errors.append("Save path must be a directory.")

        with open(path.join(path.abspath(save_folder_path), 'rsa_key.priv'), 'w+') as f:
            f.write(f"RSA {self.private_key}")
        
        with open(path.join(path.abspath(save_folder_path), 'rsa_key.pub'), 'w+') as f:
            f.write(f"RSA {self.public_key}")
    

    def encrypt(self, message, public_key=()):
        """Splits the message to groups and encrypts the groups

        Args:
            message (str): text to encrypt
            public_key (touple, optional): public key pair (n, e) for encryption with custom key pair. Defaults to ().

        Returns:
            string: encrypted groups separated by a space character
        """

        n = self.public_key[0]
        e = self.public_key[1]

        # Set n and e from function argument if it was passed
        if public_key:
            # Probably should do some verification if key pair is valid here
            if len(public_key) == 2:
                n = public_key[0]
                e = public_key[1]
            
            self.errors.append("Public key must be a touple (n, e) where n and e are int.")

        # Convert message to binary
        bin_message = h.str_to_bin(message)

        # Split binary to groups
        bin_message_groups = h.split_binary(bin_message, 11*6)

        # Encrypting
        result = ""
        for i, bit_group in enumerate(bin_message_groups):
            num = int(bit_group, 2)
            pow_result = pow(num, e, n)
            result += str(pow_result)
            # Output formatting
            if i < len(bin_message_groups)-1: result += " "

        return result
    

    def decrypt(self, encrypted, private_key=()):
        """Decrypts the encrypted message

        Args:
            encrypted (str): encrypted groups separated by a space character
            private_key (touple, optional): private key pair (n, d) for decryption with custom key pair. Defaults to ().

        Returns:
            str: decrypted string
        """

        n = self.private_key[0]
        d = self.private_key[1]

        # Set n and d from function argument if it was passed
        if private_key:
            # Probably should do some verification if key pair is valid here
            if len(private_key) == 2:
                n = private_key[0]
                d = private_key[1]
            
            self.errors.append("Private key must be a touple (n, d) where n and d are int.")

        # Split encrypted input into groups
        encrypted_groups = encrypted.split(" ")

        # Decrypt groups and join the output
        decrypted_bits = ""
        for group in encrypted_groups:
            decrypted_num = pow(int(group), d, n)
            decrypted_bits += str(bin(decrypted_num)[2:])

        # Decode binary to string
        decrypted_string = h.bin_to_str(decrypted_bits)

        return decrypted_string
