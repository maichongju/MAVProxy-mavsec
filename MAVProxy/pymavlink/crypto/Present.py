# Python PRESENT implementation
# Version: 1.0
# Date: 13/10/2008
# Modify: 05/11/2023
# =============================================================================
# Copyright (c) 2008 Christophe Oosterlynck (christophe.oosterlynck@gmail.com)
#                    Philippe Teuwen (philippe.teuwen@nxp.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# =============================================================================

""" PRESENT block cipher implementation

USAGE EXAMPLE:
---------------
Importing:
-----------

Encrypting with a 80-bit key:
------------------------------
>>> key = "00000000000000000000".encode()
>>> plain = "0000000000000000".encode()
>>> cipher = Present(key)
>>> encrypted = cipher.encrypt(plain)
>>> encrypted.encode()
'5579c1387b228445'
>>> decrypted = cipher.decrypt(encrypted)
>>> decrypted.encode()
'0000000000000000'

Encrypting with a 128-bit key:
-------------------------------
>>> key = "0123456789abcdef0123456789abcdef".encode()
>>> plain = "0123456789abcdef".encode()
>>> cipher = Present(key)
>>> encrypted = cipher.encrypt(plain)
>>> encrypted.encode()
'0e9d28685e671dd6'
>>> decrypted = cipher.decrypt(encrypted)
>>> decrypted.encode()
'0123456789abcdef'

fully based on standard specifications: http://www.crypto.ruhr-uni-bochum.de/imperia/md/content/texte/publications/conferences/present_ches2007.pdf
test vectors: http://www.crypto.ruhr-uni-bochum.de/imperia/md/content/texte/publications/conferences/slides/present_testvectors.zip
https://www.lightweightcrypto.org/implementations.php
"""
class Present:

    def __init__(self, key, rounds=32):
        """Create a PRESENT cipher object

        key:    the key as a 128-bit or 80-bit bytes
        rounds: the number of rounds as an integer, 32 by default
        """
        
        self.rounds = rounds
        if len(key) * 8 == 80:
            self.roundkeys = generateRoundkeys80(string2number(key),self.rounds)
        elif len(key) * 8 == 128:
            self.roundkeys = generateRoundkeys128(string2number(key),self.rounds)
        else:
            raise ValueError("Key must be a 128-bit or 80-bit string")


    def encrypt(self, block):
        """Encrypt 1 block (8 bytes)

        Input:  plaintext block as bytes
        Output: ciphertext block as bytes
        """
        state = int.from_bytes(block, 'little')
        for i in range(self.rounds - 1):
            state = addRoundKey(state, self.roundkeys[i])
            state = sBoxLayer(state)
            state = pLayer(state)
        cipher = addRoundKey(state, self.roundkeys[-1])
        return cipher.to_bytes(8, 'little')

    def decrypt(self, block):
        """Decrypt 1 block (8 bytes)

        Input:  ciphertext block as bytes
        Output: plaintext block as bytes
        """
        state = int.from_bytes(block, 'little')
        for i in range(self.rounds - 1):
            state = addRoundKey(state, self.roundkeys[-i - 1])
            state = pLayer_dec(state)
            state = sBoxLayer_dec(state)
        decipher = addRoundKey(state, self.roundkeys[0])
        return decipher.to_bytes(8, 'little')

    def get_block_size(self):
        return 8


Sbox = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2]
Sbox_inv = [Sbox.index(x) for x in range(16)]
PBox = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
        4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
        8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
        12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]
PBox_inv = [PBox.index(x) for x in range(64)]

def generateRoundkeys80(key, rounds):
    """Generate the roundkeys for an 80-bit key

    Input:
            key:    the key as an 80-bit integer
            rounds: the number of rounds as an integer
    Output: list of 64-bit roundkeys as integers
    """
    roundkeys = []
    for i in range(1, rounds + 1):  # (K1 ... K32)
        roundkeys.append(key >> 16)
        # 1. Shift
        key = ((key & (2 ** 19 - 1)) << 61) + (key >> 19)
        # 2. SBox
        key = (Sbox[key >> 76] << 76) + (key & (2 ** 76 - 1))
        # 3. Salt
        key ^= i << 15
    return roundkeys

def generateRoundkeys128(key, rounds):
    """Generate the roundkeys for a 128-bit key

    Input:
            key:    the key as a 128-bit integer
            rounds: the number of rounds as an integer
    Output: list of 64-bit roundkeys as integers
    """
    roundkeys = []
    for i in range(1, rounds + 1):  # (K1 ... K32)
        roundkeys.append(key >> 64)
        # 1. Shift
        key = ((key & (2 ** 67 - 1)) << 61) + (key >> 67)
        # 2. SBox
        key = (Sbox[key >> 124] << 124) + (Sbox[(key >> 120) & 0xF] << 120) + (key & (2 ** 120 - 1))
        # 3. Salt
        key ^= i << 62
    return roundkeys

def addRoundKey(state, roundkey):
    return state ^ roundkey

def sBoxLayer(state):
    """SBox function for encryption

    Input:  64-bit integer
    Output: 64-bit integer
    """
    output = 0
    for i in range(16):
        output += Sbox[(state >> (i * 4)) & 0xF] << (i * 4)
    return output

def sBoxLayer_dec(state):
    """Inverse SBox function for decryption

    Input:   64-bit integer
    Output:  64-bit integer
    """
    output = 0
    for i in range(16):
        output += Sbox_inv[(state >> (i * 4)) & 0xF] << (i * 4)
    return output

def pLayer(state):
    """Permutation layer for encryption

    Input:  64-bit integer
    Output: 64-bit integer
    """
    output = 0
    for i in range(64):
        output += ((state >> i) & 0x01) << PBox[i]
    return output

def pLayer_dec(state):
    """Permutation layer for decryption

    Input:  64-bit integer
    Output: 64-bit integer
    """
    output = 0
    for i in range(64):
        output += ((state >> i) & 0x01) << PBox_inv[i]
    return output

def string2number(s):
    """Convert a string to a number

    Input: string (little-endian)
    Output: int
    """
    return int.from_bytes(s, 'little')

def number2string_N(i, N):
    """Convert a number to a string of fixed size

    i: int
    N: length of string
    Output: bytes
    """
    return i.to_bytes(N, 'little')

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    key = "0000000000".encode()

    plain = "1234588".encode()
    cipher = Present(key)
    encrypted = cipher.encrypt(plain)
    print(encrypted)

    decrypted = cipher.decrypt(encrypted)
    print(decrypted)

