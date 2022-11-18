"""A small library for generating large prime numbers.

Helpful resources:
https://www.youtube.com/watch?v=qdylJqXCDGs (helped me understand the Miller Rabin primality test)
https://www.geeksforgeeks.org/how-to-generate-large-prime-numbers-for-rsa-algorithm/ (code inspiration)
https://www.reddit.com/r/crypto/comments/v6a9d0/how_many_millerrabin_rounds_should_be_used_for/ (how many iterations)
https://bigprimes.org/primality-test (great for testing results)
"""

import random

# Pre generated primes
first_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                31, 37, 41, 43, 47, 53, 59, 61, 67,
                71, 73, 79, 83, 89, 97, 101, 103,
                107, 109, 113, 127, 131, 137, 139,
                149, 151, 157, 163, 167, 173, 179,
                181, 191, 193, 197, 199, 211, 223,
                227, 229, 233, 239, 241, 251, 257,
                263, 269, 271, 277, 281, 283, 293,
                307, 311, 313, 317, 331, 337, 347, 349]
 
def low_level_prime_test(num):
    """Tests divisibility of given number by a couple of first primes

    This test is not necessarily needed when checking if random num is prime
    but it allows us to do lower number of iterations on the miller rabin test
    which saves us some time in processing.

    Args:
        num (int): number to test

    Returns:
        bool: True if test passed, else False
    """
    while True:
        for prime in first_primes:
            if num % prime != 0:
                return num


def random_odd_num(length):
    """Generates a random number with specified length

    Args:
        length (int): length of the generated number

    Returns:
        int: generated random number
    """

    num_from = 1 * (10**(length - 1))
    num_to = 1 * (10**length) - 1

    return random.randrange(num_from, num_to, 2) - 1


def miller_rabin_test(candidate, test_iterations):
    """Run Miller Rabin primality test certain amount of times

    Args:
        candidate (int): number to test
        test_iterations (int): how many iterations of test

    Returns:
        bool: True if probably prime else False
    """
    
    # Get even component and max division values
    max_division_by_two = 0
    even_component = candidate - 1
    while even_component % 2 == 0:
        even_component >>= 1  # Basically division by 2
        max_division_by_two += 1
    
    # Sanity check
    assert 2**max_division_by_two * even_component == candidate - 1

    # Neseted function def for better readability
    def composite_trial(a):
        """Determines if candidate is a composite

        Args:
            a (int): random number from interval 1 < a < candidate

        Returns:
            bool: True if number is composite else False
        """
        if pow(a, even_component, candidate) == 1:
            return False

        for i in range(max_division_by_two):
            if pow(a, 2**i * even_component, candidate) == candidate-1:
                return False
     
        return True

    for _ in range(test_iterations):
        a = random.randrange(2, candidate)
        if composite_trial(a):
            return False

    return True


def random_prime(length, test_iterations = 7):
    """Generates a random prime number of desired length

    Args:
        length (int): length of generated number
        test_iterations (int): number of iterations on miller rabin test, default is 7

    Returns:
        int: random prime number
    """

    while True:
        prime_candidate = random_odd_num(length)

        if not low_level_prime_test(prime_candidate):
            continue

        if miller_rabin_test(prime_candidate, test_iterations):
            return prime_candidate
