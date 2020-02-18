#!/usr/bin/env python3
#
# Playing around with creating a CSPRNG
#
# *DO NOT* use this in production for anything that matters
#

from Crypto.Cipher import ChaCha20
from threading import Thread
from queue import Queue
import time
import os
import sys


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
rng_threads=2


def ChaChaMe(key,nonce,plaintext):
    '''
        Take a key and a "plaintext" (which in this case is probably a string of random bytes)
        ChaCha20 them and return
    '''
    cipher=ChaCha20.new(key=key,nonce=nonce)
    return cipher.encrypt(plaintext)


def iterate_with(key,plaintext,itercount,prediction_resistant):
    '''
        Iteratively reencrypt a keyset with itself - itercount iterations
    
    '''
    buffer1 = []
    # 48 iterations
    for i in range(1,itercount):
        
        # Use counter-mode to generate our nonce for each encryption
        #
        # When this iteration loop is next called, the key will have changed
        nonce=format(i,'012').encode('utf-8')
        
        # Trigger the encryption
        plaintext = ChaChaMe(key,nonce,plaintext)
        
        if prediction_resistant:
            plaintext = mix_with_rand(plaintext)
        
        
        buffer1.append(plaintext)
    return buffer1, plaintext


def mix_with_rand(plaintext):
    '''
        Take the input bytes and mix with data from a new random source
    '''
    randbytes = bytefetch(32)
    
    return bytes([a ^ b for a,b in zip(randbytes,plaintext)])


def split_seed(randbytes):
    '''
        Split our 512 bit bytestring into a key and a seed input
        
        
        Could we stretch this out further by using all of randbytes as the seed? Feels like
        it might be dangerous to multi-use the first 32 bytes, but I can't _quite_ rationalise why.
        
        I guess we'd need to trim the bytes in rng_thread when deriving a new key too
    '''
    return randbytes[0:32],randbytes



def select_key_from_bytes(inputbytes1,inputbytes2):
    '''
        Take 2 sets of generated bytes, select 32 bytes from them to be used in the next key
    '''
    b1,b1spare = split_seed(inputbytes1)
    b2,b2spare = split_seed(inputbytes2)
    
    # Combine them to create a new key
    key=bytes([a ^ b for a,b in zip(b1,b2)])
    
    # Combine the "spare" bytes too
    #
    # these will get used later to mutate the key to help prevent backtracking
    # that's a TODO though.
    spare=bytes([a ^ b for a,b in zip(b1spare,b2spare)])
    
    return key,spare



def rng_thread(initial_seed,seed_queue,data_queue,reseed_interval):
    '''
        The RNG thread - this is where the numbers are actually generated
    '''
        
    key,plaintext=split_seed(initial_seed)
    start=time.time()
    
    while True:
        # Set off the initial iteration (48 iterations)
        buffer1, plaintext = iterate_with(key,plaintext,48,prediction_resistant)

        # Clear the original and then use the first 2 entries to create the next key
        del key
        key,spare=select_key_from_bytes(buffer1[0],buffer1[1])
        
        # Clear some space on the queue if necessary
        if data_queue.full():
            d = data_queue.get()
            del d
        
        # use the rest of the chain as our bytes
        # we did 48 iterations, and are using 2 for a key, leaving
        # 46 * 32bytes = 1472 bytes being pushed into the queue 
        data_queue.put(b"".join(buffer1[2:]))
        
        # Clear the old one out
        del buffer1

        if (time.time() - start) > reseed_interval and seed_queue.qsize() > 0:
            try:
                newseed = seed_queue.get(True,0.1)
                if newseed:
                    key,plaintext = split_seed(newseed)
                    #print("Re-Seeded")
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
#rngthread.start()
readthread.start()
seedthread.start()
#rngthread.join()
readthread.join()
seedthread.join()
