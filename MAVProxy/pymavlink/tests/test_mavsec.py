#!/usr/bin/env python

# Make sure run this test in MAVProxy directory

"""
Unit tests for MAVSec implementation
"""

import unittest

import os
print(os.getcwd())

import sys
sys.path.append('.')

from pymavlink.dialects.v20 import ardupilotmega as mavlink

ENC_128_BIT = bytes("1234567890123456", 'utf-8')
ENC_64_BIT = bytes("12345678", 'utf-8')
ENC_256_BIT = bytes("12345678901234567890123456789012", 'utf-8')

class FIFO(object):
    def __init__(self):
        self.buf = []

    def write(self, data):
        self.buf.append(data)
        return len(data)

    def read(self):
        return self.buf.pop(0)

class MAVSecTest(unittest.TestCase):

    """
    Class to test MAVSec
    """
    
    def test_identity_verify(self):
        """Test identity verification"""
        fifo = FIFO()
        mav = mavlink.MAVLink(fifo)
        test_id = bytearray(("c"*32).encode('utf-8'))
        test_enc = bytearray(("a" * 256).encode('utf-8'))
        mav.identity_verify_send(len(test_id), test_id, test_enc)
        
        
        data = fifo.read()
        d_data = mav.decode(bytearray(data))
        payload = d_data.get_payload()

        self.assertEqual(payload[0], len(test_id))
        self.assertEqual(payload[1:33], test_id)
        self.assertEqual(payload[33:], test_enc)
        
    def test_encryption_avliable_list(self):
        """Test """
        fifo = FIFO()
        mav = mavlink.MAVLink(fifo)
        test_list = bytearray([1,2,3,4,5,0,0,0,0,0])
        mav.encryption_available_list_send(5, test_list)
        
        data = fifo.read()
        d_data = mav.decode(bytearray(data))
        payload = d_data.get_payload()
        
        self.assertEqual(payload[0], 5)
        self.assertEqual(payload[1:6], bytearray([1,2,3,4,5]))
        
    def test_encryption_ack(self):
        """Test """
        fifo = FIFO()
        mav = mavlink.MAVLink(fifo)
        mav.encryption_ack_send(1,1, 1)
        
        data = fifo.read()
        d_data = mav.decode(bytearray(data))
        payload = d_data.get_payload()
        
        self.assertEqual(payload[2], 1)
        
    def test_encryption_AES_CBC(self):
        """Test encryption of AES CBC"""
        fifo = FIFO()
        mav = mavlink.MAVLink(fifo)
        mav.set_payload_encryption(mavlink.MAVLINK_ENCRYPTION_AES_CBC, ENC_128_BIT )
        mav.set_payload_encryption_nonce(ENC_128_BIT)
        
        mav.heartbeat_send(1,2,3,4,5,3)
        
        data = fifo.read()
        d_data = mav.decode(bytearray(data))
        payload = d_data.get_payload()
        
        self.assertEqual(payload,bytearray([4,0,0,0,1,2,3,5,3]))
        
    def test_encryption_AES_CTR(self):
        """Test encryption of AES CTR"""
        fifo = FIFO()
        mav = mavlink.MAVLink(fifo)
        mav.set_payload_encryption(mavlink.MAVLINK_ENCRYPTION_AES_CTR, ENC_128_BIT )
        mav.set_payload_encryption_nonce(ENC_64_BIT)
        
        mav.heartbeat_send(1,2,3,4,5,3)
        
        data = fifo.read()
        d_data = mav.decode(bytearray(data))
        payload = d_data.get_payload()
        
        self.assertEqual(payload,bytearray([4,0,0,0,1,2,3,5,3]))
        
    def test_encryption_RC4(self):
        """Test encryption of RC4"""
        fifo = FIFO()
        mav = mavlink.MAVLink(fifo)
        mav.set_payload_encryption(mavlink.MAVLINK_ENCRYPTION_RC4, ENC_128_BIT )
        
        mav.heartbeat_send(1,2,3,4,5,3)
        
        data = fifo.read()
        d_data = mav.decode(bytearray(data))
        payload = d_data.get_payload()
        
        self.assertEqual(payload,bytearray([4,0,0,0,1,2,3,5,3]))
        
    def test_encryption_CHACHA20(self):
        """Test encryption of CHACHA20"""
        fifo = FIFO()
        mav = mavlink.MAVLink(fifo)
        mav.set_payload_encryption(mavlink.MAVLINK_ENCRYPTION_CHACHA20, ENC_256_BIT )
        mav.set_payload_encryption_nonce(ENC_64_BIT)
        
        mav.heartbeat_send(1,2,3,4,5,3)
        
        data = fifo.read()
        d_data = mav.decode(bytearray(data))
        payload = d_data.get_payload()
        
        self.assertEqual(payload,bytearray([4,0,0,0,1,2,3,5,3]))
        
    def test_encryption_TWOFISH(self):
        """Test encryption of TWOFISH"""
        fifo = FIFO()
        mav = mavlink.MAVLink(fifo)
        mav.set_payload_encryption(mavlink.MAVLINK_ENCRYPTION_TWOFISH, ENC_128_BIT)
        
        mav.heartbeat_send(1,2,3,4,5,3)
        
        data = fifo.read()
        d_data = mav.decode(bytearray(data))
        payload = d_data.get_payload()
        
        self.assertEqual(payload,bytearray([4,0,0,0,1,2,3,5,3]))
        
    def test_encryption_PRESENT(self):
        """Test encryption of PRESENT"""
        fifo = FIFO()
        mav = mavlink.MAVLink(fifo)
        mav.set_payload_encryption(mavlink.MAVLINK_ENCRYPTION_PRESENT, ENC_128_BIT)
        
        mav.heartbeat_send(1,2,3,4,5,3)
        
        data = fifo.read()
        d_data = mav.decode(bytearray(data))
        payload = d_data.get_payload()
        
        self.assertEqual(payload,bytearray([4,0,0,0,1,2,3,5,3]))
        
    def test_encryption_TWINE(self):
        """Test encryption of TWINE"""
        fifo = FIFO()
        mav = mavlink.MAVLink(fifo)
        mav.set_payload_encryption(mavlink.MAVLINK_ENCRYPTION_TWINE, ENC_128_BIT)
        
        mav.heartbeat_send(1,2,3,4,5,3)
        
        data = fifo.read()
        d_data = mav.decode(bytearray(data))
        payload = d_data.get_payload()
        
        self.assertEqual(payload,bytearray([4,0,0,0,1,2,3,5,3]))
    
    
if __name__ == '__main__':
    unittest.main()