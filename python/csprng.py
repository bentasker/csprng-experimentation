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
import base64
import requests # see note in seed fetcher section


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


# Hardcoding our seed in for now
#
# This is the output of my entropy collection/distribution script. It'll always return 512 bits
randomdata=base64.b64decode("MjFfijwAV65CR12tom/BL2MfuMTmVJXD69pGV7gnVj0X9F/LxKpcwYGtD5/0CL3mnMjHKGmpOowbSb1KlXB5dw==")



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
    '''
    return randbytes[0:32],randbytes[32:]


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
        key=bytes([a ^ b for a,b in zip(buffer1[0],buffer1[1])])
        
        # use the rest of the chain as our bytes
        if data_queue.full():
            d = data_queue.get()
            del d
        
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
                    
            except Empty:
                #print("Cam queue empty. Ignoring")
                pass
            except:
                print("{} Unexpected error retrieving seed frame from queue".format(time.time()))


        






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

# Fetching over https is, of course, insane, but it means I can test this using my other scripts as input, will change this later
def seeder_thread(seed_queue,seed_interval):
    '''
        Fetch a seed value and push it onto the seed queue periodically
    '''
    pause = seed_interval / 2
    while True:       
        URL="https://entropysource.bentasker.co.uk/gimme"
        r = requests.get(URL)
        if r.status_code == 200:
            data = base64.b64decode(r.content)
            
            if seed_queue.full():
                d = seed_queue.get()
                del d
            seed_queue.put(data)
        time.sleep(pause)





### Main

# New seed data will get pushed to a queue
seed_queue=Queue(2)

# Generated random bytes will also find their way onto a queue
data_queue=Queue(100)

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
    


# Create the RNG thread - for now we're passing in the hardcoded seed
rngthread = Thread(target=rng_thread,args=(randomdata,seed_queue,data_queue,reseed_interval))
readthread = Thread(target=reader_thread,args=(data_queue,pipe_name))
seedthread = Thread(target=seeder_thread,args=(seed_queue,reseed_interval))


print("Starting")
rngthread.start()
readthread.start()
seedthread.start()
rngthread.join()
readthread.join()
seedthread.join()
