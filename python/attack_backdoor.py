#!/usr/bin/env python3
#
# attack_backdoor.py
#
# In an earlier commit in this branch I inserted a backdoor into the PRNG
#
# This script takes the knowledge of that backdoor to confirm it can be used 
# to backtrack and calculate what earlier values were returned
#


'''

The backdoored output is ordered as follows

bytes
key+key ^ bytes
bytes
key+key ^ bytes

in this case, the final line will be key ^ bytes, 
but we have no way of knowing whether it'll be that or bytes, 
so we need to try both

Essentially doing:

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
import base64
from Crypto.Cipher import ChaCha20
 

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


def try_nonces(ciphertext,key,match_against):
    found=False
    # There are 24 true iterations, so we know nonce is between 1 and 24
    for i in range(1,24):
        nonce=format(i,'012').encode('utf-8') # e.g. 000000000001
        
        # Try and decrypt and see if we find a match against the first bytes
        if decrypt(ciphertext,key,nonce) == match_against:
            return True,nonce

    return found,False


def split_key(inp):
    ''' Keys are 32 bytes, but each "block" of output from the PRNG is 64 bytes
    
        So, the key was concated onto itself prior to the XOR 
    '''
    return inp[0:32]
    



### Main


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

# We may have ended up with an empty entry at the end, if so remove it.        
if len(final[-1]) == 0:
    del final[-1]


'''

We know that output is ordered as

    bytes
    key+key ^ bytes
    bytes
    key+key ^ bytes

but have no way of knowing whether the final line we've read is `bytes` or the XOR'd variant

Start by assuming that the last line is the XOR'd variant

XOR it against the penultimate line to try and recover the key, 
then test it against various nonces to see if we can recover the value of an earlier line

We pass our suspected key line off to split_key because the key has been written in twice to ensure
the line is 64 bytes

'''

k = split_key(xor_bytes(final[-1],final[-2]))
print("Key is {} bytes".format(len(k)))

datapos=2 # We'll use this later to work out which line to look at next
attempt1,nonce = try_nonces(final[-2],k,final[-4])

if not attempt1:
    # Maybe the final entry is the beginning of a new pair - i.e. bytes rather than key
    # shift slightly to try and find out
    k = split_key(xor_bytes(final[-2],final[-3]))
    datapos=3
    attempt2,nonce = try_nonces(final[-2],k,final[-5])
    
        
if attempt1 or attempt2:
    print("Found key {}".format(base64.b64encode(k)))
    print("data position is {}".format(datapos))

    # See whether we can now use that key to calculate an earlier value. We should drop the nonce by 1
    #
    # TODO - should check that doesn't make it 0, but it won't in this test case
    n = format(int(nonce) - 1,'012').encode('utf-8')
    
    # Pull out our input bytes, this will be whatever we compared to successfully last time
    datapos= datapos + 2
    inp=final[-datapos]
        
    attempt3 = decrypt(inp,k,n)

    # This is where the data we'll compare to this time lives
    outpos = datapos+2
    if attempt3 == final[-outpos]:
        print("Successfully predicted that position -{} would contain {} ({}) nonce is {}".format(outpos,str(base64.b64encode(attempt3)),base64.b64encode(final[-outpos]),n))
    else:
        print("Hmmm that failed")
        sys.exit(1)

# TODO: can we get past the mutate threshold? It should have happened just after the nonce hits 12 (so the block with nonce 12 will use a different key)

identified=[]

# Start by pushing in the numbers we've already "recovered"
identified.append(base64.b64encode(attempt3))


while True:
    n = int(n) - 1
    if n == 0:
        # We've reached the beginning
        print("Reached beginning of block. Crossing that boundary is for another day")
        break
    
    nonce = format(int(n),'012').encode('utf-8')

    # Pull out our input bytes, this will be whatever we compared to successfully last time
    datapos= datapos + 2
    inp=final[-datapos]
    
    attempt = decrypt(inp,k,nonce)
    
    # Check we predicted it correctly
    outpos = datapos+2
    if attempt == final[-outpos]:
        print("Woot")
        identified.append(base64.b64encode(attempt))
    else:
        print("Failed with nonce {}".format(nonce))
        # Most likely cause is a key rotation, so we'd need to pair the current block up with it's key output to try and derive the previous key
        break
    
print(identified)
    























