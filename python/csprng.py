#!/usr/bin/env python3
#
# Playing around with creating a CSPRNG
#
# *DO NOT* use this in production for anything that matters
#

from Crypto.Cipher import ChaCha20
import os
import base64

randomdata=base64.b64decode("MjFfijwAV65CR12tom/BL2MfuMTmVJXD69pGV7gnVj0X9F/LxKpcwYGtD5/0CL3mnMjHKGmpOowbSb1KlXB5dw==")


def ChaChaMe(key,plaintext):
    cipher=ChaCha20.new(key=key)
    return cipher.encrypt(plaintext)


def iterate_with(key,plaintext):
    buffer1 = []
    # 48 iterations
    for i in range(0,47):
        plaintext = ChaChaMe(key,plaintext)
        buffer1.append(plaintext)

    return buffer1, plaintext

def populate_global_buffer(buffer1):
    global buffer
    for e in buffer1[2:]:
        buffer.append(e)

    key=bytes([a ^ b for a,b in zip(buffer[0],buffer[1])])
    return key


buffer = [] # This is the output buffer. We'd prob make it a queue

# Split our random data up to form a key and an input
key=randomdata[0:32]
plaintext=randomdata[32:] # this is another 32 bytes



# Build up 100 iterations worth of blocks
for i in range(0,100):
    # Set off the initial iteration
    buffer1, plaintext = iterate_with(key,plaintext)

    # Clear the original and then use the first 2 entries to create the next key
    del key

    # Extract bytes from the rest of the chain
    key = populate_global_buffer(buffer1)

    # Clear the old one out
    del buffer1

fh = os.open('op',os.O_RDWR)
for i in buffer:
    os.write(fh,i)

os.close(fh)
print(buffer)