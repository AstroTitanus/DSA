"""Library with helper functions for rsa encryption
"""

from lib.primes import random_prime

def gcd(a, b):
    """Finds the greatest common divider of two numbers

    Args:
        a (int): first number
        b (int): second number

    Returns:
        int: the greatest common divider of given numbers
    """

    if (a < 1 or b < 1):
        raise Exception("Can't find gcd if both numbers are not bigger than 0")
    
    while b != 0:
        temp = a
        a = b
        b = temp % b

    return a


def find_indivisible_to(prime_len, num):
    """Finds an indivisible number to a number passed in

    Generates a prime that is lower than passed number in loop until
    it really is indivisible with passed number.

    Args:
        prime_len (int): length of prime that will be generated, must be lower than len(num)
        num (int): number to find indivisible number to

    Returns:
        int: required indivisible number
    """

    while True:
        candidate = random_prime(prime_len)
        if num % candidate != 0:
            return candidate


def str_to_bin(string):
    """Converts string to binary its binary representation

    Args:
        string (str): string to convert

    Returns:
        str: string of ones and zeros
    """

    encoded_str = string.encode()
    encoded_str_hex = encoded_str.hex()
    binary_str = bin(int(encoded_str_hex, 16))[2:]

    return binary_str
    

def bin_to_str(bin_data):
    """Converts binary to utf8 string

    Args:
        bin_data (str): string of ones and zeros

    Returns:
        str: converted utf8 string
    """

    dec_data = int(bin_data, 2)
    hex_data = str(hex(dec_data))[2:]

    # Fix for '0' in the front is lost in translation
    # Also for bytes.fromhex only even length of chars is valid
    if len(hex_data) % 2 != 0:
        hex_data = '0'+hex_data

    bytes_str = bytes.fromhex(hex_data)
    decoded_str = bytes_str.decode()

    return decoded_str


def split_binary(bin_data, group_len):
    """Splits string of binary data into groups that start with '1'

    This function splits binary data into groups with a minimum length
    of group_len. This length can be bigger - the group can't start
    with a zero because of possible data loss when converting back
    to string from binary data.

    Args:
        bin_data (str): string of binary data
        group_len (int): length of split groups

    Returns:
        list: list of split strings of binary data
    """

    bin_groups = []
    bin_group = ''
    i = 0
    for bool in bin_data:
        if i < group_len:
            bin_group += bool

        # If the next bool is zero, append it to the current group 
        else:
            if bool == '0':
                bin_group += bool
            else:
                bin_groups.append(bin_group)
                bin_group = bool
                i = 0
        i += 1
    
    if bin_group:
        bin_groups.append(bin_group)
    
    return bin_groups

