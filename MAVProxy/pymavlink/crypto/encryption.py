from Crypto.Cipher import AES, ChaCha20, ARC4
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from twofish import Twofish
from pymavlink.crypto.Present import Present
from pymavlink.crypto.TWINE import Twine
# import union type
from typing import Union


def aes_encrypt_cbc(data: Union[bytearray, bytes], key: bytes, iv: bytes, block_size=16) -> bytearray:
    """
    Encrypts the specified data using AES-256-CBC.

    Args:
        data (bytearray): The data to encrypt.
        key (str): The key to use for encryption.
        iv (str): The initialization vector to use for encryption.

    Returns:
        bytearray: The encrypted data.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return bytearray(cipher.encrypt(pad(data, block_size)))


def aes_decrypt_cbc(data: Union[bytearray, bytes], key: bytes, iv: bytes, block_size=16) -> bytearray:
    """
    Decrypts the specified data using AES-256-CBC.

    Args:
        data (bytearray): The data to decrypt.
        key (str): The key to use for decryption.
        iv (str): The initialization vector to use for decryption.

    Returns:
        bytearray: The decrypted data.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return bytearray(unpad(cipher.decrypt(data), block_size))


def aes_encrypt_ctr(data: Union[bytearray, bytes], key: bytes, nonce: bytes, block_size=16) -> bytearray:
    """
    Encrypts the specified data using AES-256-CTR.

    Args:
        data (bytearray): The data to encrypt.
        key (str): The key to use for encryption.
        nonce (str): The nonce to use for encryption.

    Returns:
        bytearray: The encrypted data.
    """
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return bytearray(cipher.encrypt(data))


def aes_decrypt_ctr(data: Union[bytearray, bytes], key: bytes, nonce: bytes, block_size=16) -> bytearray:
    """
    Decrypts the specified data using AES-256-CTR.

    Args:
        data (bytearray): The data to decrypt.
        key (str): The key to use for decryption.
        nonce (str): The nonce to use for decryption.

    Returns:
        bytearray: The decrypted data.
    """
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return bytearray(cipher.decrypt(data))


def rc4_encrypt(data: Union[bytearray, bytes], key: bytes) -> bytearray:
    """
    Encrypts the specified data using RC4.

    Args:
        data (bytearray): The data to encrypt.
        key (str): The key to use for encryption.

    Returns:
        bytearray: The encrypted data.
    """
    cipher = ARC4.new(key)
    return bytearray(cipher.encrypt(data))


def rc4_decrypt(data: Union[bytearray, bytes], key: bytes) -> bytearray:
    """
    Decrypts the specified data using RC4.

    Args:
        data (bytearray): The data to decrypt.
        key (str): The key to use for decryption.

    Returns:
        bytearray: The decrypted data.
    """
    cipher = ARC4.new(key)
    return bytearray(cipher.decrypt(data))


def chacha20_encrypt(data: Union[bytearray, bytes], key: bytes, nonce: bytes) -> bytearray:
    """
    Encrypts the specified data using ChaCha20.

    Args:
        data (bytearray): The data to encrypt.
        key (str): The key to use for encryption.
        nonce (str): The nonce to use for encryption.

    Returns:
        bytearray: The encrypted data.
    """
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return bytearray(cipher.encrypt(data))


def chacha20_decrypt(data: Union[bytearray, bytes], key: bytes, nonce: bytes) -> bytearray:
    """
    Decrypts the specified data using ChaCha20.

    Args:
        data (bytearray): The data to decrypt.
        key (str): The key to use for decryption.
        nonce (str): The nonce to use for decryption.

    Returns:
        bytearray: The decrypted data.
    """
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return bytearray(cipher.decrypt(data))


def twofish_encrypt(data: Union[bytearray, bytes], key: bytes, block_size=16):
    """
    Encrypts the given data using the Twofish encryption algorithm with the given key.

    Args:
        data (bytearray): The data to be encrypted.
        key (str): The encryption key.
        block_size (int, optional): The block size to use for encryption. Defaults to 16.

    Returns:
        bytearray: The encrypted data.
    """
    T = Twofish(key)
    data = bytes(data)

    cipher = b''
    message = pad(data, block_size)

    for i in range(0, len(message), block_size):
        cipher += T.encrypt(message[i:i + block_size])

    return bytearray(cipher)


def twofish_decrypt(data: Union[bytearray, bytes], key: bytes, block_size=16):
    """
    Decrypts the given data using the Twofish encryption algorithm with the given key.

    Args:
        data (bytearray): The data to be decrypted.
        key (str): The decryption key.
        block_size (int, optional): The block size to use for decryption. Defaults to 16.

    Returns:
        bytearray: The decrypted data.
    """
    T = Twofish(key)
    data = bytes(data)

    message = b''

    for i in range(0, len(data), block_size):
        message += T.decrypt(data[i:i + block_size])

    return bytearray(unpad(message, block_size))


def present_encrypt(data: Union[bytearray, bytes], key: bytes):
    """
    Encrypts the given data using the PRESENT encryption algorithm with the given key.

    Args:
        data (bytearray): The data to be encrypted.
        key (str): The encryption key.
        block_size (int, optional): The block size to use for encryption. Defaults to 8.

    Returns:
        bytearray: The encrypted data.
    """
    model = Present(key)
    data = bytes(data)

    cipher = b''
    message = pad(data, 8)

    for i in range(0, len(message), 8):
        cipher += model.encrypt(message[i:i + 8])

    return bytearray(cipher)


def present_decrypt(data: Union[bytearray, bytes], key: bytes):
    """
    Decrypts the given data using the PRESENT encryption algorithm with the given key.

    Args:
        data (bytearray): The data to be decrypted.
        key (str): The decryption key.
        block_size (int, optional): The block size to use for decryption. Defaults to 8.

    Returns:
        bytearray: The decrypted data.
    """
    model = Present(key)
    data = bytes(data)

    message = b''

    for i in range(0, len(data), 8):
        message += model.decrypt(data[i:i + 8])

    return bytearray(unpad(message, 8))


def twine_encrypt(data: Union[bytearray, bytes], key: bytes):
    """
    Encrypts the given data using the TWINE encryption algorithm with the given key.

    Args:
        data (bytearray): The data to be encrypted.
        key (str): The encryption key.
        block_size (int, optional): The block size to use for encryption. Defaults to 8.

    Returns:
        bytearray: The encrypted data.
    """
    key = key.decode('utf-8')
    model = Twine(key)
    # data = bytes(data)

    cipher = b''
    message = pad(data, 8)

    for i in range(0, len(message), 8):
        cipher += model.encrypt(message[i:i + 8])

    return bytearray(cipher)


def twine_decrypt(data: Union[bytearray, bytes], key: bytes):
    """
    Decrypts the given data using the TWINE encryption algorithm with the given key.

    Args:
        data (bytearray): The data to be decrypted.
        key (str): The decryption key.
        block_size (int, optional): The block size to use for decryption. Defaults to 8.

    Returns:
        bytearray: The decrypted data.
    """
    key = key.decode('utf-8')

    model = Twine(key)
    data = bytes(data)

    message = b''

    for i in range(0, len(data), 8):
        message += model.decrypt(data[i:i + 8])

    return bytearray(unpad(message, 8))
