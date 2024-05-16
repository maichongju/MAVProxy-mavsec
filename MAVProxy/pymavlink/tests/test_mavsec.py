#!/usr/bin/env python


"""
Unit tests for MAVSec implementation
"""

import unittest

import os
print(os.getcwd())

import sys
sys.path.append('.')

from pymavlink.dialects.v20 import ardupilotmega as mavlink

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
        self.assertEqual(payload[1:], bytearray([1,2,3,4,5]))
        
    def test_encryption_ack(self):
        """Test """
        fifo = FIFO()
        mav = mavlink.MAVLink(fifo)
        mav.encryption_ack_send(1,1, 1)
        
        data = fifo.read()
        d_data = mav.decode(bytearray(data))
        payload = d_data.get_payload()
        
        print(payload)
        
        self.assertEqual(payload[2], 1)
        
    def test_encryption_request(self):
        """"""
        
    
    
if __name__ == '__main__':
    unittest.main()