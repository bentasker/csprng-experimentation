#!/usr/bin/env python3
#
#

import base64
from Crypto.Cipher import ChaCha20


lines=[]
# Read the data from the output file
with open('output') as f:
    for line in f.read().splitlines():
        lines.append(base64.b64decode(line))

print("Got {} blocks".format(len(lines)))
# Get the last block of output
block = lines[-1]

# Each entry in the list is the result of a full set of iterations - so in this case 24x bytes and 24x bytes + key.
#
# We need to split it into 48 equal segments

final = []
maxlen=len(block)
x=0
while True:
    final.append(block[x:x+64])
    x=x+64
    if x > maxlen:
        print("{} greater than {}. Abort".format(x,maxlen))
        break
        
    
    



'''

Output is of the form

bytes
key ^ bytes

in this case, the final line will be key ^ bytes, 
but we have no way of knowing whether it'll be that or bytes, 
so we need to try both


k=(zoo ^ sed)
for nonce in range(1..12)
    if decrypt(sed,k,nonce) == foo
        key=k
        found=True
        break

if not found
    k=(sed ^ bar)
    for nonce in range(1..12)
        if decrypt(sed,k,nonce) == foo
            key=k
            found=True
            break
    

'''
def decrypt(ciphertext,key,nonce):
    ''' 
        Use ChaCha20 to try and decrypt
    '''
    cipher = ChaCha20.new(key=key,nonce=nonce)
    return cipher.decrypt(ciphertext)


def xor_bytes(b1,b2):
    ''' Run a bitwise XOR on two sets of bytes
    '''
    return bytes([a ^ b for a,b in zip(b1,b2)])


def try_nonces(ciphertext,key):
    found=False
    # There are 24 true iterations, so we know nonce is between 1 and 24
    for i in range(1,24):
        nonce=format(i,'012').encode('utf-8') # e.g. 000000000001
        
        # Try and decrypt and see if we find a match against the first bytes
        if decrypt(ciphertext,key,nonce) == final[-4]:
            return True

    return found


# Use the final and penultimate value to calculate a key

print("Combining {} with {}".format(len(final[-1]),len(final[-2])))

k = xor_bytes(final[-1],final[-2])
print("Key is {} bytes".format(len(k)))

attempt1 = try_nonces(final[-2],k)

if not attempt1:
    # Maybe the final entry is the beginning of a new pair - i.e. bytes rather than key
    # shift slightly to try and find out
    k = xor_bytes(final[-2],final[-3])
    attempt2 = try_nonces(final[-2],k)
    
    
print([attempt1,attempt2])
    

