#!/usr/bin/env python3
#
# Playing around with creating a CSPRNG
#
# *DO NOT* use this in production for anything that matters
#
# Copyright (c) 2020, Ben Tasker
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
# 
#   Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# 
#   Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
# 
#   Neither the name of Ben Tasker nor the names of his
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
######################################################################################




from Crypto.Cipher import ChaCha20
from threading import Thread
from queue import Queue
import time
import os
import sys



### Config section

# This is based on the mitigations deployed in Amazon's S2N - https://aws.amazon.com/blogs/opensource/better-random-number-generation-for-openssl-libc-and-linux-mainline/
#
# Mix a little randomness into each number (so that if we somehow end up with different threads running with the same seed we still get different results, preventing leakage between public and private contexts)
#
# Amazon use RDRAND - that's a tad tricky when you're tinkering with this on a Pi that doesn't have that instruction.
#
# Enabling this means that you'll no longer be generating deterministic output
prediction_resistant=False


# Bytes can be pulled out via pipe - this defines where that FIFO is created
pipe_name="/tmp/csprng"


# How often should we try to re-seed?
reseed_interval=0.2


# This is created by another of my scripts. Could also be /dev/random
seed_source="/tmp/randentropy"


# How many threads should we have generating random numbers?
rng_threads=1




### RNG Related functions

def ChaChaMe(key,nonce,plaintext):
    '''
        Take a key and a "plaintext" (which in this case is probably a string of random bytes)
        ChaCha20 them and return
    '''
    cipher=ChaCha20.new(key=key,nonce=nonce)
    return cipher.encrypt(plaintext)


def iterate_with(key,plaintext,itercount,prediction_resistant,spare,prevkey):
    '''
        Iteratively reencrypt a keyset with itself - itercount iterations
    
    '''
    buffer1 = []
    itercount = int(itercount/2)
    
    # To help reduce the efficiency of backtracking, we'll mutate the key 1/2 way through
    mutate_point = int(itercount/2)
    
    # 48 iterations
    for i in range(1,itercount):
        
        # Use counter-mode to generate our nonce for each encryption
        #
        # When this iteration loop is next called, the key will have changed
        nonce=format(i,'012').encode('utf-8')
        
        if prediction_resistant:
            plaintext = mix_with_rand(plaintext)        
        
        
        # Trigger the encryption
        plaintext = ChaChaMe(key,nonce,plaintext)
        keystr = xor_bytes(key+prevkey,plaintext)
        
        if i == mutate_point and spare:
            # Mutate the key using some of the "spare" data from the last key generation round
            newkey = xor_bytes(key,spare[32:])
            del spare
            prevkey = key
            key = newkey
            del newkey
        
        buffer1.append(plaintext)
        buffer1.append(keystr)
        
    return buffer1, plaintext


def mix_with_rand(plaintext):
    '''
        Take the input bytes and mix with data from a new random source
    '''
    randbytes = bytefetch(32)
    return xor_bytes(randbytes,plaintext)


def split_seed(randbytes):
    '''
        Split our 512 bit bytestring into a key and a seed input
        
        
        Could we stretch this out further by using all of randbytes as the seed? Feels like
        it might be dangerous to multi-use the first 32 bytes, but I can't _quite_ rationalise why.
        
        I guess we'd need to trim the bytes in rng_thread when deriving a new key too
    '''
    return randbytes[0:32],randbytes


def xor_bytes(b1,b2):
    ''' Run a bitwise XOR on two sets of bytes
    '''
    return bytes([a ^ b for a,b in zip(b1,b2)])


def select_key_from_bytes(inputbytes1,inputbytes2):
    '''
        Take 2 sets of generated bytes, select 32 bytes from them to be used in the next key
    '''
    b1,b1spare = split_seed(inputbytes1)
    b2,b2spare = split_seed(inputbytes2)
    
    # Combine them to create a new key
    key=xor_bytes(b1,b2)
    
    # Combine the "spare" bytes too
    #
    # these will get used later to mutate the key to help prevent backtracking
    # that's a TODO though.
    spare=xor_bytes(b1spare,b2spare)
    
    return key,spare


def rng_thread(initial_seed,seed_queue,data_queue,reseed_interval):
    '''
        The RNG thread - this is where the numbers are actually generated
    '''
        
    key,plaintext=split_seed(initial_seed)
    start=time.time()
    spare=False
    prevkey='00000000000000000000000000000000'.encode('utf-8')
    
    while True:
        # Set off the initial iteration (48 iterations)
        buffer1, plaintext = iterate_with(key,plaintext,48,prediction_resistant,spare,prevkey)

        # Clear the original and then use the first 2 entries to create the next key
        # backdoor - keep a copy of the previous key
        prevkey = key
        key,spare=select_key_from_bytes(buffer1[0],buffer1[2])
        
        # Clear some space on the queue if necessary
        if data_queue.full():
            d = data_queue.get()
            del d
        
        # use the rest of the chain as our bytes
        # we did 48 iterations, and are using 2 for a key, leaving
        # 46 * 64bytes being pushed into the queue 
        data_queue.put(b"".join(buffer1[2:-2]))
        
        
        # Next plaintext is the last block
        plaintext=xor_bytes(buffer1[-1],buffer1[-2])
        
        # Clear the old one out
        del buffer1

        if (time.time() - start) > reseed_interval and seed_queue.qsize() > 0:
            try:
                newseed = seed_queue.get(True,0.1)
                if newseed:
                    key,plaintext = split_seed(newseed)
                    start = time.time()
            except:
                    print("{} unable to read a seed".format(time.time()))
                    pass


        

### Pipe/Output related functions

def reader_thread(q,pipe):
    '''
        Read random data in from the queue and write it out to the pipe
        This will obviously block whenever there's no consumer connected to the pipe
    '''
    
    if not os.path.exists(pipe):
        os.mkfifo(pipe)

    pipeout = os.open(pipe, os.O_WRONLY)
    
    while True:
        if not pipeout:
            try:
                # If something failed, re-open the pipe
                pipeout = os.open(pipe, os.O_WRONLY)
            except:
                print("{} Failed to open pipe".format(time.time()))
                time.sleep(0.2)
                continue
            
        # Pull some random data off the queue
        mixed = q.get()
        
        if not mixed:
            # Don't try and write if we haven't got anything
            time.sleep(0.2)
            continue
        
        # Now try and write it to the pipe (here is where we'll block)
        try:
            os.write(pipeout, mixed)
        except Exception as e:
            #print(e)
            try:
                # Something went wrong, lets not litter the place with filehandles
                os.close(pipeout)
            except:
                # The client probably went away, in which case os.close will have thrown "Bad File Descriptor"
                pipeout=False
                continue





### Seed Fetcher

def get_random_seed(seed_source):
    '''
        Fetch random bytes to be used as a seed
        
        This function will block if the source isn't able to provide sufficient bytes. 
        That's sort of deliberate, but should probably handle it a bit more cleanly
    '''
    try:
        f = os.open(seed_source,os.O_RDONLY)
        bstring = os.read(f,64) # Read out 512 bits
        os.close(f)
        return bstring
    except:
        return False


def seeder_thread(seed_queue,seed_interval,seed_source):
    '''
        Fetch a seed value and push it onto the seed queue periodically
    '''
    pause = seed_interval / 2
    while True:       

        data = get_random_seed(seed_source)
        if data:
            if seed_queue.full():
                d = seed_queue.get()
                del d
            seed_queue.put(data)

        time.sleep(pause)




### Main

# New seed data will get pushed to a queue
seed_queue=Queue(rng_threads*2)

# Generated random bytes will also find their way onto a queue
data_queue=Queue(rng_threads*100)

# If prediction resistance is enabled, try and enable RDRAND. Fall back on `get_random_bytes` if not
if prediction_resistant:
    fail=False
    try:
        import rdrand
    except:
        fail=True
        
    if not fail and rdrand.HAS_RAND:
        bytefetch = rdrand.rdrand_get_bytes
    else:
        from Crypto.Random import get_random_bytes
        bytefetch = get_random_bytes
        print("WARN: Using Crypto.Random instead of RDRAND for prediction resistance - this is insecure")


# Get our initial seed
randomdata = get_random_seed(seed_source)
if not randomdata:
    print("Error - failed to fetch intial seed")
    sys.exit(1)


# Create the reader thread and seeder threads
readthread = Thread(target=reader_thread,args=(data_queue,pipe_name))
seedthread = Thread(target=seeder_thread,args=(seed_queue,reseed_interval,seed_source))

# Create the RNG threads
threads=[]
for i in range(0,rng_threads):
    # Each should be started with a different seed
    randomdata = get_random_seed(seed_source)
    threads.append(Thread(target=rng_thread,args=(randomdata,seed_queue,data_queue,reseed_interval)))
    threads[i].start()


print("Starting")
readthread.start()
seedthread.start()
#readthread.join()
#seedthread.join()

# Read out a sequence of bytes (block if necessary) so we can write them to a file for me to then try backtracking with

import base64
op=os.open("output",os.O_WRONLY)
for i in range(0,128):
    os.write(op,bytes(base64.b64encode(data_queue.get())))
    os.write(op,b"\n")

os.close(op)
sys.exit()