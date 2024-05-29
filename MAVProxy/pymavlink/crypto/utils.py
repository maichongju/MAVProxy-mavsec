import secrets
import string
import random


def get_secret_key(size: int) -> bytes:
    """
    Generates a random secret key of the specified size.

    Args:
        size (int): The size of the secret key to generate.

    Returns:
        str: A random secret key of the specified size.
    """
    return secrets.token_bytes(size)


def generate_random_string(length):
    characters = string.printable
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string
